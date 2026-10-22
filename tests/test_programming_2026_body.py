"""Authored selected CUW fixtures and primitive transcripts; no vendor execution."""

import csv
import hashlib
import io
import json
import struct
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from scripts.calibration_2026 import parse_cuw_2026
from scripts.j2534_2026 import (
    J2534Device2026,
    NativeCommunicationAddress,
    NativeJ2534Error2026,
    NativeMessage,
    NativePassThruError2026,
    PrimitiveResult,
)
from scripts.native_modules import identify_native_module
from scripts.programming import NativeTransportError
from scripts.programming_2026_body import (
    IMPLEMENTED_EXPORTS,
    MODULE_EXPORTS,
    bind_native_context,
    is_finish_reprogramming,
    prepare_body,
    prepare_chassis,
    run_native_context,
)
from scripts.programming_2026_common import (
    NativeRuntime2026,
    SecretInfoClient,
    bind_native_parameter2026,
)
from tests.test_calibration_2026 import cuw

AIRBAG = "TCUWP4CanAirbagPrepareWriter.dll"
SONAR = "TCUWP4CanClearanceSonarPrepareWriter.dll"
SECURITY = "TCUWP4CanSecurityAirbagPrepareWriter.dll"
BODY = "TCUWP4CanBodyPrepareWriter.dll"
CHASSIS = "TCUWP4CanChassisShrinkPrepareWriter.dll"
SECURITY_CHASSIS = "TCUWP4CanSecurityChassisShrinkPrepareWriter.dll"
CENTRAL = "TCUWP4CanCentralGWPrepareWriter.dll"
POWER = "TCUWP4CanPowerTrainPrepareWriter.dll"
SONAR_WRITE = "TCUWP4CanClearanceSonarFlashWriter.dll"
FINISH_WRITERS = (
    "TCUWP4CanAirbagFlashWriter.dll",
    "TCUWP4CanSecurityAirbagFlashWriter.dll",
    "TCUWP4CanDSS1FlashWriter.dll",
)
HASHES = {
    "TCUWP4CanBodyFlashWriter.dll": "80436ae23cb57e95f105740fbd86e6d559e7af824807ec1aca078cbef822315a",
    "TCUWP4CanBodyFlashWriterForCXPI.dll": "678801c25c59ed6f85a69bae229c9c233c60b8b5ae3a81a68c3209ddebb18b27",
    "TCUWP5CanBodyFlashWriter.dll": "956934d48eaf471d064ad994ed2e9c9663a30dbb43f4b90c1f84d4c982e980aa",
    "TCUWP4CanChassisShrinkFlashWriter.dll": "4b07dcd99b38e137f9adbc8fe25f12afe0568617b295a9cc121ec31abeccb27a",
    "TCUWP4CanSecurityChassisShrinkFlashWriter.dll": "593edef501e797eb81fb082c0f187421168341d2c34fcffa708a13f59db20155",
    SONAR_WRITE: "a93db37eb8d203604be2d7717e93be6ec450936ec914b34cedbbe90a3db710fc",
    POWER: "019b4bb08e03a85fdc57dbe987dfc17d3a556c65ae436e78b89f802d672b92de",
    CENTRAL: "04c8fe7a96b384f3d062eccac2067106667cc6ca41b254bac60f5d0ed54f9c9b",
    AIRBAG: "c727423ad90caaf61ed629bf7e8626def19a6deae1c58ce14a5e4ff43415db9b",
    SONAR: "404046186dc5216793431debc0024834d75fe159a035dce341d919946484cee7",
    SECURITY: "1d43256cb8abff8d02237a9e3cb0acfe475cc57fccc8945544fee8b4bbf2eb40",
    BODY: "9e86daac76bf80303d28d84088319c5124add1b2bff912df46cf5ab00c8015f9",
    CHASSIS: "443bee8560a489866384249e8906ca0f7d6119d0faf3d1703d79390182c7c5bf",
    SECURITY_CHASSIS: "d160206073ffa417aee92dd2b7321764aee696bb194a1f1723176e829b399517",
    "TCUWP4CanAirbagFlashWriter.dll": "e6d91ed2589d7f067d5c5e4738d1e1bf49cb1423e8a0ca5cde0c729714a24577",
    "TCUWP4CanSecurityAirbagFlashWriter.dll": "1806c5a75562d171935efd648b2bedf373f906989ed2e1305ae4c4b0ba5b11ca",
    "TCUWP4CanDSS1FlashWriter.dll": "57b5924df75fd1d37af905f30ce90550e52d9eaead374869c6293a218ef01d77",
}


def identity(module):
    return identify_native_module(HASHES[module], module)


def parameters(key, values):
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(("ParamFileKeySystemProtocolMicon", *values))
    writer.writerow((key, *values.values()))
    return output.getvalue().encode()


def fixture(
    module=AIRBAG,
    *,
    bus=1,
    extra=None,
    cpu_index=0,
    kind="8",
    cpu_a="A",
    operation="prepare",
):
    text = (
        "[Format]\nVersion=7\n[Vehicle]\nKindOfECU=8\nContactType=P4\nNumberOfCalibration=2\n"
        "ECUAuthKey=11111111111111111111111111111111\nServiceAuthKey=22222222222222222222222222222222\n"
        "[CPU01]\nCPUType=A\nCPUImageName=authored.vbf\nLocationID=0108010000000000\nNumberOfTargets=1\n01_TargetCalibration=OLD_A\n"
        "[CPU02]\nCPUType=B\nCPUImageName=authored.vbf\nLocationID=0208020000000000\nNumberOfTargets=1\n01_TargetCalibration=OLD_B\n"
    )
    text = text.replace("KindOfECU=8", "KindOfECU=" + kind).replace(
        "CPUType=A", "CPUType=" + cpu_a
    )
    container = parse_cuw_2026(
        cuw(text, (bytes((bus,)) + b"payload_A", b"\0payload_B"))
    )
    values = {
        "DLLFileNameForPrepareWrite": module,
        "GetCANIDFunctionNameForPrepareWrite": "GetCanIDsFromParamForPrepareWrite",
        "CanIDForPrepareWrite": "0100/0108",
        "SecurityAccessPassword": "1234\nABCD",
        "CANCommunicationSpeedAddress": "0",
        "WaitTimeAfterSeedData": "2",
        "WaitTimeAfterSeedKey": "3",
        "WaitTimeAfterDiagnosticMask": "4",
        "IGOffRetriableFlag": "1",
        "SecurityKey": "1111\n2222\n3333\n4444",
    }
    values.update(extra or {})
    catalogs = {
        kind + "P4" + cpu + ".ini": parameters(kind + "P4" + cpu, values)
        for cpu in (cpu_a, "B")
    }
    selection = bind_native_parameter2026(
        container, catalogs, operation, encoded=False, cpu_index=cpu_index
    )
    context = bind_native_context(container, 1, (), selection, identity(module), {}, {})
    return context, container, selection


def writer_selection(
    module,
    cpu_index=1,
    block_size_info="0:1x1",
    initialize_prepare=False,
    encoded=False,
    first_cpu_endian=False,
    body_flags=None,
    target_count=1,
    gateway_startup=False,
    distinct_images=False,
):
    from scripts.calibration_2026 import (
        native2026_metadata,
        native2026_with_parser_parameters,
    )
    from scripts.programming_2026_common import NativeGeneralParameters2026

    text = "[Format]\nVersion=7\n[Vehicle]\nKindOfECU=8\nContactType=P4\nNumberOfCalibration=2\n"
    for index, cpu in enumerate(("A", "B"), 1):
        text += f"[CPU{index:02}]\nCPUType={cpu}\nNewCID=NEW_{cpu}\nCPUImageName=authored.bin\nLocationID=0108010000000720\nNumberOfTargets=1\n01_TargetCalibration=OLD_{cpu}\n01_TargetData=12345678\n"
    if target_count == 2:
        text = text.replace("NumberOfTargets=1", "NumberOfTargets=2").replace(
            "01_TargetData=12345678\n",
            "01_TargetData=12345678\n02_TargetCalibration=SECOND\n02_TargetData=02030405\n",
        )
        text = text.replace(
            "02_TargetCalibration=SECOND", "02_TargetCalibration=SECOND_A", 1
        )
        text = text.replace(
            "02_TargetCalibration=SECOND\n", "02_TargetCalibration=SECOND_B\n", 1
        )
    if "Security" in module:
        text = text.replace(
            "01_TargetData=12345678\n",
            "01_TargetData=12345678\nNonce="
            + ("11" * 16)
            + "\nSeedKey="
            + ("22" * 16)
            + "\n",
        )
    # Native .bin archives retain the encoded ZV frame, without decompression.
    image = b"ZV\0" + (1019).to_bytes(2, "big") + bytes(1019)
    images = (image, image[:-1] + b"\x01") if distinct_images else (image, image)
    raw = cuw(text, tuple(value.hex().upper().encode() for value in images))
    container = parse_cuw_2026(raw)
    catalogs = {}
    for cpu, address in (
        ("A", "0100/0108\n0300AA/0308AA"),
        ("B", "0200/0208\n0400/0408"),
    ):
        catalogs["8P4" + cpu + ".ini"] = parameters(
            "8P4" + cpu,
            {
                "DLLFileNameForFlashWrite": module,
                **(
                    {
                        "DLLFileNameForPrepareWrite": BODY,
                        "DLLFileNameForGetCID": "TCUWCanCIDGetter.dll",
                        "GetCANIDFunctionNameForGetCID": "GetCanIDsFromParamForGetCID",
                        "CanIDForGetCID": "0100/0108",
                        "ReceiveTimeoutBeforeGetCID": "33",
                        "EnableDLLVersionInformation": "0\n0\n0\n0",
                    }
                    if initialize_prepare
                    else {}
                ),
                "GetCANIDFunctionNameForFlashWrite": "GetCanIDsFromParamForPrepareWrite",
                "GetCANIDFunctionNameForPrepareWrite": "GetCanIDsFromParamForPrepareWrite",
                "CanIDForPrepareWrite": address,
                "BlockSizeInfo": block_size_info,
                "CPUIDNo": "0",
                "BigEndianFlag": "1" if first_cpu_endian and cpu == "A" else "0",
                "ShrinkFlag": "1",
                "PasswordAddress": "0",
                "ReceiveTimeoutBeforeFlashWrite": "33",
                "SendTimeoutBeforePrepareWrite": "44",
                "WaitTimeBetweenSF": "2",
                "WaitTimeAfterReprogrammingMode": "3",
                **(body_flags or {}),
            },
        )
    flags = {
        "M16CTypeFlag": "0",
        "FORESTTypeFlag": "0",
        "FlagToDoIGOFFONAtCPUTypeChange": "0",
        "FlagToChangeToReprogGWModeForCentralGW": "1" if gateway_startup else "0",
    }
    catalogs["Parameter.ini"] = (
        parameters("8P4A", flags) + parameters("8P4B", flags).split(b"\r\n", 1)[1]
    )
    if encoded:
        catalogs = {
            name: bytes(
                (part + 8) << 2 for value in data for part in (value >> 4, value & 15)
            )
            for name, data in catalogs.items()
        }
    general = NativeGeneralParameters2026.from_sources(catalogs, encoded=encoded)
    metadata = native2026_with_parser_parameters(
        native2026_metadata(container, cpu_index=cpu_index), general
    )
    selection = bind_native_parameter2026(
        container,
        catalogs,
        "write",
        cpu_index=cpu_index,
        encoded=encoded,
        metadata_state=metadata,
    )
    return raw, container, selection, general


def sonar_payloads():
    ack, status = b"\x3c", b"\0"
    replies = [ack, b"ID", ack, bytes.fromhex("0000000003ff0100") + b"\0", ack]
    replies += [ack, ack, status, ack]
    replies += [ack, ack, ack, status, ack]
    replies += [ack, ack, status, ack]
    replies += [ack] + [ack, ack, status, ack] * 4
    return replies + [ack]


def runtime(
    replies=(b"\x67\x03\x01\x02\x34", b"\x67\x04\x34", b"\x50"),
    *,
    fault=None,
    cancel=None,
):
    events, replies = [], iter(replies)

    def action(event, remaining):
        if remaining <= 0:
            raise AssertionError("Nonpositive deadline")
        events.append(event)
        if fault is not None:
            fault(event)
        operation = event["operation"]
        if operation == "start_flow_control_filter":
            return 17
        if operation == "decrypt_secret_info":
            return bytes.fromhex("abcd" * 8)
        if operation == "calculate_security_key":
            return b"\x33" * 16
        if operation == "get_timeout":
            return 999
        if operation == "write_messages":
            return event["count"]
        if operation == "read_specified_can_message":
            reply = next(replies)
            if isinstance(reply, BaseException):
                raise reply
            return event["address"] + reply
        return None

    return NativeRuntime2026(
        action, cancelled=(lambda: cancel(events)) if cancel else lambda: False
    ), events


def secret_client():
    secret = Path("runtime/no-car-21/recovered/SecretInfo.dll")
    cuw_image = Path("runtime/no-car-21/recovered/CUW.dll")
    if not secret.is_file() or not cuw_image.is_file():
        raise unittest.SkipTest(
            "Authenticated private native SecretInfo/CUW images absent"
        )
    return SecretInfoClient.from_native_modules(
        secret.read_bytes(), cuw_image.read_bytes()
    )


class Body2026Tests(unittest.TestCase):
    def test_every_preparation_export_host_fault_and_cancellation_at_each_primitive(
        self,
    ):
        plain = (b"\x67\x03\x01\x02\x34", b"\x67\x04\x34", b"\x50")
        body = (b"\x67\x61\x01\x02\x03\x04\x05\x06", b"\x67\x62\x34", b"\x50")
        secure = (b"\x67\x03" + bytes(16) + b"\x34", b"\x67\x04\x34", b"\x50") * 2
        cases = [
            (AIRBAG, {}, plain),
            (SONAR, {}, plain),
            (BODY, {}, body),
            (BODY, {"gateway_only": True}, body),
            (SECURITY, {}, secure),
            (CHASSIS, {}, (b"\x67\x01\x01\x02\x03\x04", b"\x67\x02", b"\x50")),
            (SECURITY_CHASSIS, {}, (b"\x67\x01" + bytes(16), b"\x67\x02", b"\x50")),
        ]
        cases.append((POWER, {}, (b"\x67\x01\x01\x02\x03\x04", b"\x67\x02", b"\x50")))
        for module, options, replies in cases:
            context, _, _ = fixture(module)
            baseline, events = runtime(replies)
            run_native_context(
                context,
                baseline,
                **(
                    {"secret_info": secret_client()}
                    if module in (SECURITY, SECURITY_CHASSIS)
                    else {}
                ),
                **options,
            )
            for index, event in enumerate(events):
                if event["operation"] == "stop_filter" or event.get("parameters") == (
                    (30, 0),
                ):
                    continue
                with self.subTest(
                    module=module,
                    options=options,
                    index=index,
                    operation=event["operation"],
                ):
                    count = [0]

                    def fault(_event, count=count, index=index):
                        current = count[0]
                        count[0] += 1
                        if current == index:
                            raise OSError("Authored per-export primitive fault")

                    rt, _ = runtime(replies, fault=fault)
                    with self.assertRaises(OSError):
                        run_native_context(
                            context,
                            rt,
                            **(
                                {"secret_info": secret_client()}
                                if module in (SECURITY, SECURITY_CHASSIS)
                                else {}
                            ),
                            **options,
                        )
                    self.assertEqual(rt.close(), [])
                    rt, _ = runtime(
                        replies, cancel=lambda es, index=index: len(es) > index
                    )
                    with self.assertRaises(InterruptedError):
                        run_native_context(
                            context,
                            rt,
                            **(
                                {"secret_info": secret_client()}
                                if module in (SECURITY, SECURITY_CHASSIS)
                                else {}
                            ),
                            **options,
                        )
                    self.assertEqual(rt.close(), [])

    def test_all_available_exports_through_real_j2534_device_primitive(self):
        plain = (b"\x67\x03\x01\x02\x34", b"\x67\x04\x34", b"\x50")
        body = (b"\x67\x61\x01\x02\x03\x04\x05\x06", b"\x67\x62\x34", b"\x50")
        secure = (b"\x67\x03" + bytes(16) + b"\x34", b"\x67\x04\x34", b"\x50") * 2
        cases = [
            (AIRBAG, False, plain, 6),
            (SONAR, False, plain, 6),
            (BODY, False, body, 6),
            (BODY, True, body, 3),
            (SECURITY, False, secure, 9),
        ]
        cases += [
            (POWER, False, (b"\x67\x01\x01\x02\x03\x04", b"\x67\x02", b"\x50"), 6)
        ]
        cases += [
            (CHASSIS, False, (b"\x67\x01\x01\x02\x03\x04", b"\x67\x02", b"\x50"), 6),
            (
                SECURITY_CHASSIS,
                False,
                (b"\x67\x01" + bytes(16), b"\x67\x02", b"\x50"),
                6,
            ),
        ]
        cases += [(module, False, (b"\x7e",), 1) for module in FINISH_WRITERS]
        for module, gateway, replies, expected_count in cases:
            with self.subTest(module=module, gateway=gateway):
                calls, echo = [], []
                replies = iter(replies)

                def provider(
                    operation, remaining, calls=calls, echo=echo, replies=replies
                ):
                    calls.append(operation)
                    name = operation["operation"]
                    if name in (
                        "passthru_open",
                        "passthru_connect",
                        "passthru_start_filter",
                    ):
                        return PrimitiveResult(value=17)
                    if name == "passthru_write":
                        message = operation["messages"][0]
                        echo.append(NativeMessage(6, message.data[:4], rx_status=9))
                        return PrimitiveResult(value=operation["count"])
                    if name == "passthru_read":
                        if echo:
                            return PrimitiveResult(value=(echo.pop(0),))
                        return PrimitiveResult(
                            value=(
                                NativeMessage(
                                    6, bytes.fromhex("00000108") + next(replies)
                                ),
                            )
                        )
                    return PrimitiveResult()

                device = J2534Device2026(
                    provider, clock=lambda: 0, background_workers=False
                )
                device.open()
                device.connect(6)

                def action(event, remaining, device=device):
                    if event["operation"] == "decrypt_secret_info":
                        return bytes.fromhex("abcd" * 8)
                    if event["operation"] == "calculate_security_key":
                        return b"\x33" * 16
                    return device.primitive(event, remaining)

                rt = NativeRuntime2026(
                    action, clock=lambda: 0, cleanup_action=device.cleanup_primitive
                )
                if module in (
                    AIRBAG,
                    SONAR,
                    BODY,
                    SECURITY,
                    CHASSIS,
                    SECURITY_CHASSIS,
                    POWER,
                ):
                    context, _, _ = fixture(module)
                    self.assertTrue(
                        run_native_context(
                            context,
                            rt,
                            **(
                                {"secret_info": secret_client()}
                                if module in (SECURITY, SECURITY_CHASSIS)
                                else {}
                            ),
                            **({"gateway_only": gateway} if module == BODY else {}),
                        )["prepared"]
                    )
                else:
                    groups = ((NativeCommunicationAddress(b"\x01\0", b"\x01\x08"),),)
                    self.assertTrue(
                        is_finish_reprogramming(identity(module), rt, groups)
                    )
                sent = [
                    call["messages"][0].data
                    for call in calls
                    if call["operation"] == "passthru_write"
                ]
                if module in (AIRBAG, SONAR):
                    self.assertEqual(
                        sent[:2],
                        [
                            bytes.fromhex("0000010027031234"),
                            bytes.fromhex("000001002704aaca"),
                        ],
                    )
                self.assertEqual(len(sent), expected_count)
                self.assertFalse(device.filters)
                device.disconnect()

    def test_allocation_is_exact_and_not_a_success_claim(self):
        self.assertEqual(
            (len(MODULE_EXPORTS), sum(map(len, MODULE_EXPORTS.values()))), (17, 21)
        )
        self.assertEqual(sum(map(len, IMPLEMENTED_EXPORTS.values())), 12)
        for module in HASHES:
            self.assertEqual(
                set(MODULE_EXPORTS[module]) - set(identity(module).callable_exports),
                set(),
            )

    def test_selected_actual2026_positive_wire_and_cleanup_for_both_preparers(self):
        for module in (AIRBAG, SONAR):
            with self.subTest(module=module):
                context, _, _ = fixture(module)
                rt, events = runtime()
                result = prepare_body(context, rt)
                self.assertEqual(
                    (
                        result["returned"],
                        result["prepared"],
                        result["result_status_update"],
                    ),
                    (True, True, None),
                )
                self.assertFalse(result["programming_completed"])
                writes = [
                    e["data"] for e in events if e["operation"] == "write_messages"
                ]
                self.assertEqual(
                    writes,
                    [
                        bytes.fromhex(h)
                        for h in (
                            "0000010027031234",
                            "000001002704aaca",
                            "00000720a027",
                            "00000720a027",
                            "00000720a027",
                            "000001001002",
                        )
                    ],
                )
                self.assertEqual(
                    events[-2:],
                    [
                        {
                            "operation": "control_io",
                            "ioctl": 2,
                            "parameters": ((30, 0),),
                        },
                        {"operation": "stop_filter", "identifier": 17},
                    ],
                )
                self.assertEqual(rt.close(), [])

    def test_mixed_cpu_uses_selected_catalog_but_cpu_zero_bus(self):
        context, _, _ = fixture(cpu_index=1)
        self.assertEqual(context.binding.cpu_type, "B")
        self.assertEqual(context.bus, 1)
        rt, events = runtime()
        self.assertTrue(prepare_body(context, rt)["prepared"])
        self.assertTrue(any(e.get("parameters") == ((30, 1),) for e in events))

    def test_no_block_size_change_for_non_low_speed_cpu(self):
        for bus in (0, 2):
            context, _, _ = fixture(bus=bus)
            rt, events = runtime()
            self.assertTrue(prepare_body(context, rt)["prepared"])
            self.assertFalse(any(e["operation"] == "control_io" for e in events))

    def test_error_mapping_and_airbag_retry_is_not_sonar_behavior(self):
        for module in (AIRBAG, SONAR):
            for replies, code, driver in (
                ((b"\x67\x03\x01\x02\x35",), 16, None),
                ((b"\x67\x03\x01\x02\x34", b"\x67\x04\x35"), 17, None),
                ((b"\x67\x03\x01\x02\x34", b"\x67\x04\x34", b"\x51"), 18, None),
                ((NativeTransportError(9),), 1, 9),
            ):
                with self.subTest(module=module, code=code):
                    context, _, _ = fixture(module)
                    rt, events = runtime(replies)
                    result = prepare_body(context, rt, retry_notification=True)
                    self.assertEqual(
                        (result["returned"], result["prepared"]),
                        (module == AIRBAG, False),
                    )
                    self.assertEqual(
                        (
                            result["result_status_update"],
                            result["native_error_code"],
                            result["driver_error_code"],
                        ),
                        (1, code, driver),
                    )
                    self.assertEqual(
                        events[-1], {"operation": "stop_filter", "identifier": 17}
                    )
                    self.assertFalse(rt.owns_resource("stop_filter", identifier=17))

    def test_cancel_after_acquired_filter_rolls_back_filter_and_bs(self):
        context, _, _ = fixture()
        rt, events = runtime(
            cancel=lambda es: any(
                e["operation"] == "start_flow_control_filter" for e in es
            )
        )
        with self.assertRaises(InterruptedError):
            prepare_body(context, rt)
        self.assertEqual(
            [e["operation"] for e in events][-2:], ["stop_filter", "control_io"]
        )
        self.assertEqual(rt.close(), [])

    def test_provider_faults_preserve_cleanup_and_do_not_report_success(self):
        context, _, _ = fixture()
        baseline, seen = runtime()
        prepare_body(context, baseline)
        for index in range(len(seen) - 2):
            with self.subTest(index=index):
                count = [0]

                def fault(event, count=count, index=index):
                    current = count[0]
                    count[0] += 1
                    if current == index:
                        raise OSError("Authored primitive fault")

                rt, _ = runtime(fault=fault)
                with self.assertRaises(OSError):
                    prepare_body(context, rt)
                self.assertEqual(rt.close(), [])

    def test_cleanup_failure_attempts_other_release_and_remains_explicit(self):
        context, _, _ = fixture()
        failed = [False]

        def fault(event):
            if event.get("parameters") == ((30, 0),) and not failed[0]:
                failed[0] = True
                raise OSError("Authored restoration failure")

        rt, events = runtime(fault=fault)
        with self.assertRaisesRegex(OSError, "Authored restoration failure"):
            prepare_body(context, rt)
        self.assertEqual(events[-1]["operation"], "stop_filter")
        self.assertTrue(rt.owns_resource("control_io", ioctl=2, parameters=((30, 0),)))
        self.assertEqual(rt.close(), [])

    def test_binding_rejects_overrides_wrong_metadata_and_password(self):
        context, container, selection = fixture()
        for attachments, observations in (
            ({"password": b"ab"}, {}),
            ({}, {"stage": "prepare"}),
        ):
            with self.assertRaises(ValueError):
                bind_native_context(
                    container,
                    1,
                    (),
                    selection,
                    context.identity,
                    attachments,
                    observations,
                )
        with self.assertRaises(ValueError):
            fixture(extra={"SecurityAccessPassword": "1234"})
        with self.assertRaises(ValueError):
            fixture(extra={"SecurityAccessPassword": "ZZZZ\n1234"})
        with self.assertRaises(ValueError):
            replace(context, identity=replace(context.identity, cuw_build="18"))

    def test_real_typed_j2534_errors_preserve_native_and_driver_assignment(self):
        for exception, native, driver in (
            (NativePassThruError2026(16), 16, None),
            (NativeJ2534Error2026(9), 1, 9),
        ):
            for module in (AIRBAG, SONAR, BODY):
                with self.subTest(module=module, exception=type(exception).__name__):
                    context, _, _ = fixture(module)
                    rt, events = runtime((exception,))
                    result = prepare_body(context, rt)
                    self.assertEqual(
                        (
                            result["returned"],
                            result["result_status_update"],
                            result["native_error_code"],
                            result["driver_error_code"],
                        ),
                        (False, 1, native, driver),
                    )
                    self.assertEqual(events[-1]["operation"], "stop_filter")

    def test_each_finish_wrapper_runs_real_shared_wire_and_filter(self):
        groups = ((NativeCommunicationAddress(b"\x01\0", b"\x01\x08"),),)
        for module in FINISH_WRITERS:
            with self.subTest(module=module):
                for reply, expected in (
                    (b"\x7e", True),
                    (NativeTransportError(9), False),
                ):
                    rt, events = runtime((reply,))
                    self.assertIs(
                        is_finish_reprogramming(identity(module), rt, groups), expected
                    )
                    self.assertEqual(
                        [
                            e["data"]
                            for e in events
                            if e["operation"] == "write_messages"
                        ],
                        [bytes.fromhex("000001003e")],
                    )
                    self.assertEqual(
                        events[-1], {"operation": "stop_filter", "identifier": 17}
                    )
                rt, events = runtime(
                    cancel=lambda es: any(
                        e["operation"] == "start_flow_control_filter" for e in es
                    )
                )
                with self.assertRaises(InterruptedError):
                    is_finish_reprogramming(identity(module), rt, groups)
                self.assertEqual(events[-1]["operation"], "stop_filter")

    def test_security_airbag_repeats_global_cpu_count_same_address_and_masks_once(self):
        context, _, _ = fixture(SECURITY, cpu_index=1)
        self.assertEqual((context.cpu_count, context.bus), (2, 2))
        seed = b"\x67\x03" + bytes(range(16)) + b"\x34"
        rt, events = runtime((seed, b"\x67\x04\x34", b"\x50") * 2)
        result = prepare_body(context, rt, secret_info=secret_client())
        self.assertTrue(result["prepared"])
        writes = [e["data"] for e in events if e["operation"] == "write_messages"]
        crypto = [
            e
            for e in events
            if e["operation"] in ("decrypt_secret_info", "calculate_security_key")
        ]
        self.assertEqual(
            [e["operation"] for e in crypto],
            ["decrypt_secret_info", "calculate_security_key"] * 2,
        )
        self.assertEqual(crypto[0]["service_auth_key"], b"\x22" * 16)
        self.assertEqual(crypto[1]["key_hex"], b"ABCD" * 8)
        self.assertEqual(crypto[1]["seed"], bytes(range(16)))
        self.assertEqual(writes.count(bytes.fromhex("00000720a027")), 3)
        self.assertEqual(writes.count(bytes.fromhex("000001002703") + b"\x11" * 16), 2)
        self.assertEqual(writes.count(bytes.fromhex("000001002704") + b"\x33" * 16), 2)
        self.assertFalse(any(e["operation"] == "control_io" for e in events))
        self.assertEqual(events[-1]["operation"], "stop_filter")
        self.assertNotIn("22222222", repr(context))

    def test_security_airbag_key_rejection_maps_1002_and_host_crypto_cancel_propagates(
        self,
    ):
        context, _, _ = fixture(SECURITY)
        seed = b"\x67\x03" + bytes(16) + b"\x34"
        rt, events = runtime((seed, b"\x7f\x27\x35"))
        result = prepare_body(context, rt, secret_info=secret_client())
        self.assertEqual(
            (result["returned"], result["native_error_code"]), (False, 1002)
        )
        self.assertEqual(events[-1]["operation"], "stop_filter")

        def cancel(event):
            if event["operation"] == "calculate_security_key":
                raise InterruptedError("Authored crypto cancellation")

        rt, events = runtime((seed,), fault=cancel)
        with self.assertRaises(InterruptedError):
            prepare_body(context, rt, secret_info=secret_client())
        self.assertEqual(events[-1]["operation"], "stop_filter")
        client = secret_client()
        client.authorize(b"wrong")
        rt, events = runtime((seed,))
        with self.assertRaises(PermissionError):
            prepare_body(context, rt, secret_info=client)
        self.assertEqual(events[-1]["operation"], "stop_filter")
        rt, events = runtime((seed,))
        with self.assertRaises(TypeError):
            prepare_body(context, rt)
        self.assertEqual(events, [])

    def test_body_prepare_and_gateway_have_distinct_wire_mask_and_state(self):
        for gateway in (False, True):
            with self.subTest(gateway=gateway):
                context, _, _ = fixture(BODY)
                rt, events = runtime(
                    (b"\x67\x61\x01\x02\x03\x04\x05\x06", b"\x67\x62\x34", b"\x50")
                )
                result = prepare_body(context, rt, gateway_only=gateway)
                self.assertTrue(result["returned"])
                self.assertEqual(
                    result["gateway_mode_changed"], True if gateway else None
                )
                writes = [
                    e["data"] for e in events if e["operation"] == "write_messages"
                ]
                self.assertEqual(
                    writes[:2],
                    [
                        bytes.fromhex("000001002761"),
                        bytes.fromhex("00000100276204070a0d1a64"),
                    ],
                )
                self.assertEqual(
                    writes[-1],
                    bytes.fromhex("000001001060" if gateway else "000001001002"),
                )
                self.assertEqual(
                    writes.count(bytes.fromhex("00000720a027")), 0 if gateway else 3
                )
                self.assertFalse(any(e["operation"] == "control_io" for e in events))
                self.assertEqual(events[-1]["operation"], "stop_filter")

    def test_body_gateway_skip_and_return_override_are_exact(self):
        for bus, extra in ((0, {}), (2, {}), (1, {"ExternalMemoryFlag": "1"})):
            context, _, _ = fixture(BODY, bus=bus, extra=extra)
            rt, events = runtime(())
            result = prepare_body(context, rt, gateway_only=True)
            self.assertEqual(
                (
                    result["returned"],
                    result["prepared"],
                    result["gateway_mode_changed"],
                    result["state"],
                ),
                (True, False, False, "gateway_skipped"),
            )
            self.assertEqual(events, [])
        for gateway in (False, True):
            context, _, _ = fixture(BODY, extra={"IGOffRetriableFlag": "0"})
            rt, _ = runtime(
                (b"\x67\x61\x01\x02\x03\x04\x05\x06", b"\x67\x62\x34", b"\x51")
            )
            result = prepare_body(
                context, rt, gateway_only=gateway, retry_notification=True
            )
            self.assertEqual(result["returned"], not gateway)
            self.assertFalse(result["prepared"])
            self.assertEqual(result["native_error_code"], 49 if gateway else 18)
            self.assertEqual(result["gateway_mode_changed"], True if gateway else None)

    def test_body_bs_follows_address_extension_and_cancel_releases(self):
        context, _, _ = fixture(
            BODY, bus=0, extra={"CanIDForPrepareWrite": "0100AA/0108AA"}
        )
        rt, events = runtime(
            (b"\x67\x61\x01\x02\x03\x04\x05\x06", b"\x67\x62\x34", b"\x50")
        )
        self.assertTrue(prepare_body(context, rt)["returned"])
        self.assertEqual(
            [e["parameters"] for e in events if e["operation"] == "control_io"],
            [((30, 1),), ((30, 0),)],
        )
        rt, events = runtime(
            cancel=lambda es: any(
                e["operation"] == "start_flow_control_filter" for e in es
            )
        )
        with self.assertRaises(InterruptedError):
            prepare_body(context, rt)
        self.assertEqual(rt.close(), [])

    def test_chassis_one_two_targets_selector_order_same_first_wire_and_mask_each(self):
        from scripts.programming_2026_common import NotificationBool

        for kind, selectors in (("8", (0, 2)), ("13", (1, 0))):
            for module in (CHASSIS, SECURITY_CHASSIS):
                with self.subTest(kind=kind, module=module):
                    context, _, _ = fixture(
                        module,
                        kind=kind,
                        extra={"CanIDForPrepareWrite": "0100/0108\n0200/0208"},
                    )
                    seed = b"\x67\x01" + (
                        bytes(16)
                        if module == SECURITY_CHASSIS
                        else bytes.fromhex("01020304")
                    )
                    rt, events = runtime((seed, b"\x67\x02", b"\x50") * 2)
                    notification = NotificationBool(
                        True,
                        object(),
                        lambda _, flag, events=events: events.append(
                            {"operation": "notification", "value": flag}
                        ),
                    )
                    result = prepare_chassis(
                        context,
                        rt,
                        secret_info=secret_client()
                        if module == SECURITY_CHASSIS
                        else None,
                        completion_notification=notification,
                    )
                    self.assertTrue(result["prepared"])
                    self.assertFalse(result["completion_flag_update"])
                    self.assertFalse(notification.value)
                    self.assertEqual(
                        events[0], {"operation": "notification", "value": False}
                    )
                    writes = [
                        e["data"] for e in events if e["operation"] == "write_messages"
                    ]
                    auth = b"\x11" * 16 if module == SECURITY_CHASSIS else b""
                    self.assertEqual(
                        [data for data in writes if data[4:6] == b"\x27\x01"],
                        [
                            bytes.fromhex("000001002701") + bytes((v,)) + auth
                            for v in selectors
                        ],
                    )
                    self.assertEqual(writes.count(bytes.fromhex("00000720a027")), 6)
                    key = (
                        b"\x33" * 16
                        if module == SECURITY_CHASSIS
                        else bytes.fromhex("23206562")
                    )
                    self.assertEqual(
                        writes.count(bytes.fromhex("000001002702") + key), 2
                    )
                    self.assertFalse(
                        any(e["operation"] == "control_io" for e in events)
                    )
                    self.assertEqual(events[-1]["operation"], "stop_filter")

    def test_chassis_errors_no_retry_override_and_cancel_cleanup(self):
        for module in (CHASSIS, SECURITY_CHASSIS):
            context, _, _ = fixture(module)
            for reply, code, driver in (
                (b"\x7f\x27\x35", 16, None),
                (NativePassThruError2026(22), 22, None),
                (NativeJ2534Error2026(9), 1, 9),
            ):
                rt, events = runtime((reply,))
                result = prepare_chassis(
                    context,
                    rt,
                    secret_info=secret_client() if module == SECURITY_CHASSIS else None,
                )
                self.assertEqual(
                    (
                        result["returned"],
                        result["native_error_code"],
                        result["driver_error_code"],
                        result["completion_flag_update"],
                    ),
                    (False, code, driver, False),
                )
                self.assertEqual(events[-1]["operation"], "stop_filter")
            rt, events = runtime(
                cancel=lambda es: any(
                    e["operation"] == "start_flow_control_filter" for e in es
                )
            )
            with self.assertRaises(InterruptedError):
                prepare_chassis(
                    context,
                    rt,
                    secret_info=secret_client() if module == SECURITY_CHASSIS else None,
                )
            self.assertEqual(rt.close(), [])

    def test_central_gateway_actual_engine_callback_wire_and_native_failure_override(
        self,
    ):
        from scripts.calibration_2026 import (
            native2026_metadata,
            native2026_with_parser_parameters,
        )
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.programming_2026_body import prepare_central_gateway
        from scripts.programming_2026_common import NativeGeneralParameters2026

        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest(
                "Authenticated static CUW2026 image absent; no credential substitute"
            )
        raw = cuw(
            "[Format]\nVersion=7\n[Vehicle]\nKindOfECU=8\nContactType=P4\nNumberOfCalibration=1\n[CPU01]\nCPUType=A\nCPUImageName=authored.vbf\n",
            (b"payload",),
        )
        container = parse_cuw_2026(raw)
        source = parameters(
            "8P4A",
            {
                "DLLFileNameForPrepareWrite": CENTRAL,
                "WaitTimeAfterReprogrammingMode": "19",
            },
        )
        catalogs = {
            "8P4A.ini": source,
            "Parameter.ini": parameters(
                "8P4A", {"M16CTypeFlag": "0", "FORESTTypeFlag": "0"}
            ),
        }
        general = NativeGeneralParameters2026.from_sources(catalogs, encoded=False)
        metadata = native2026_with_parser_parameters(
            native2026_metadata(container), general
        )
        selection = bind_native_parameter2026(
            container, catalogs, "prepare", encoded=False, metadata_state=metadata
        )
        context = bind_native_context(
            container, 1, (), selection, identity(CENTRAL), {}, {}
        )
        for failed, retry in ((False, False), (True, False), (True, True)):
            with (
                self.subTest(failed=failed, retry=retry),
                CUWEngine2026(image.read_bytes()) as engine,
            ):
                engine.configure(struct.pack("<IIddII", 1, 0, 0, 0, 0, 0))
                engine.bind_general_parameters(general)
                engine.load_cuw(raw)
                replies = (
                    (NativeJ2534Error2026(9),)
                    if failed
                    else (b"\x67\x4f" + bytes(16), b"\x67\x50\x34", b"\x50")
                )
                replies, echoes, events = iter(replies), [], []

                def provider(event, remaining, replies=replies, echoes=echoes):
                    name = event["operation"]
                    if name in (
                        "passthru_open",
                        "passthru_connect",
                        "passthru_start_filter",
                    ):
                        return PrimitiveResult(value=17)
                    if name == "passthru_write":
                        message = event["messages"][0]
                        width = 5 if message.tx_flags & 0x80 else 4
                        echoes.append(
                            NativeMessage(6, message.data[:width], rx_status=9)
                        )
                        return PrimitiveResult(value=event["count"])
                    if name == "passthru_read":
                        if echoes:
                            return PrimitiveResult(value=(echoes.pop(0),))
                        reply = next(replies)
                        if isinstance(reply, NativeJ2534Error2026):
                            return PrimitiveResult(status=reply.code)
                        return PrimitiveResult(
                            value=(
                                NativeMessage(6, bytes.fromhex("000007585f") + reply),
                            )
                        )
                    return PrimitiveResult()

                device = J2534Device2026(
                    provider, clock=lambda: 0, background_workers=False
                )
                device.open()
                device.connect(6)

                def action(event, remaining, device=device, events=events):
                    events.append(event)
                    return device.primitive(event, remaining)

                def cleanup(event, remaining, device=device, events=events):
                    events.append(event)
                    return device.cleanup_primitive(event, remaining)

                rt = NativeRuntime2026(action, clock=lambda: 0, cleanup_action=cleanup)
                result = prepare_central_gateway(
                    context, rt, engine=engine, retry_notification=retry
                )
                self.assertEqual(
                    (
                        result["prepared"],
                        result["returned"],
                        result["result_status_update"],
                    ),
                    (not failed, not failed or retry, 1 if failed else None),
                )
                writes = [
                    e["data"] for e in events if e["operation"] == "write_messages"
                ]
                self.assertEqual(writes[0], bytes.fromhex("000007505f274f"))
                if failed:
                    self.assertEqual(
                        result["gateway_callback_error_state"]["primary_error"], 1
                    )
                    self.assertEqual(
                        result["gateway_callback_error_state"]["passthru_error"], 9
                    )
                    self.assertFalse(any(e.get("milliseconds") == 19 for e in events))
                else:
                    self.assertEqual(writes[-1], bytes.fromhex("000007505f1002"))
                    self.assertEqual(
                        events[-1], {"operation": "wait", "milliseconds": 19}
                    )
                self.assertEqual(rt.close(), [])
                device.disconnect()
        with CUWEngine2026(image.read_bytes()) as engine:
            engine.configure(struct.pack("<IIddII", 1, 0, 0, 0, 0, 0))
            engine.bind_general_parameters(general)
            engine.load_cuw(raw)
            replies = (b"\x67\x4f" + bytes(16), b"\x67\x50\x34", b"\x50")
            baseline, events = runtime(replies)
            prepare_central_gateway(context, baseline, engine=engine)
            for index, event in enumerate(events):
                if event["operation"] == "stop_filter" or event.get("parameters") == (
                    (30, 0),
                ):
                    continue
                with self.subTest(
                    gateway_host_fault_at=index, operation=event["operation"]
                ):
                    count = [0]

                    def fault(_event, index=index, count=count):
                        current = count[0]
                        count[0] += 1
                        if current == index:
                            raise OSError("Authored CentralGW primitive fault")

                    rt, _ = runtime(replies, fault=fault)
                    with self.assertRaises(OSError):
                        prepare_central_gateway(context, rt, engine=engine)
                    self.assertEqual(rt.close(), [])
                    rt, _ = runtime(
                        replies, cancel=lambda es, index=index: len(es) > index
                    )
                    with self.assertRaises(InterruptedError):
                        prepare_central_gateway(context, rt, engine=engine)
                    self.assertEqual(rt.close(), [])
        rt, events = runtime(())
        with self.assertRaises(TypeError):
            prepare_central_gateway(context, rt, engine=lambda: True)
        self.assertEqual(events, [])

    def test_native_retry_notification_is_read_after_communication(self):
        from scripts.programming_2026_common import NotificationBool

        notification = NotificationBool(False)
        context, _, _ = fixture(AIRBAG)

        def fault(event):
            if event["operation"] == "read_specified_can_message":
                notification.assign(True)
                raise NativeJ2534Error2026(9)

        rt, _ = runtime((), fault=fault)
        result = prepare_body(context, rt, retry_notification=notification)
        self.assertEqual(
            (result["native_return"], result["prepared"], result["native_error_code"]),
            (True, False, 1),
        )

    def test_p4_powertrain_native_target_skip_filter_lifecycle_and_mode_branches(self):
        from scripts.programming_2026_body import prepare_powertrain

        for kind, cpu, expected_mode, count in (
            ("8", "A", b"\x10\x02", 1),
            ("3", "A", b"\x10\x02", 2),
            ("51", "11", b"\x10\x60", 2),
            ("51", "A", b"\x10\x02", 1),
        ):
            context, _, _ = fixture(
                POWER, kind=kind, cpu_a=cpu, extra={"WaitTimeAfterNormalMode": "5"}
            )
            rt, events = runtime(
                (b"\x67\x01\x01\x02\x03\x04", b"\x67\x02") + (b"\x50",) * count
            )
            result = prepare_powertrain(context, rt)
            self.assertEqual(
                (
                    result["native_return"],
                    result["native_success"],
                    result["prepared_targets"],
                ),
                (True, None, (0,)),
            )
            writes = [e["data"] for e in events if e["operation"] == "write_messages"]
            self.assertEqual(
                writes[:2],
                [bytes.fromhex("000001002701"), bytes.fromhex("00000100270223206562")],
            )
            self.assertEqual(
                writes.count(bytes.fromhex("00000100") + expected_mode), count
            )
            self.assertEqual(sum(e.get("milliseconds") == 5 for e in events), count - 1)
        context, _, _ = fixture(
            POWER,
            extra={
                "CanIDForPrepareWrite": "0100/0108\n0200/0208\n0300/0308\n0400/0408"
            },
        )
        replies = (
            NativeJ2534Error2026(9),
            b"\x7f\x27\x35",
            b"\x67\x01\x01\x02\x03\x04",
            b"\x67\x02",
            b"\x67\x01\x01\x02\x03\x04",
            b"\x67\x02",
            b"\x50",
            b"\x50",
        )
        rt, events = runtime(replies)
        result = prepare_powertrain(context, rt)
        self.assertEqual(result["prepared_targets"], (2, 3))
        self.assertEqual(result["skipped_targets"], ((0, 22), (1, 23)))
        names = [e["operation"] for e in events]
        self.assertEqual(names[:4], ["start_flow_control_filter"] * 4)
        self.assertEqual(names[-4:], ["stop_filter"] * 4)
        self.assertFalse(any(name == "control_io" for name in names))

    def test_airbag_native_cleanup_catchall_preserves_bool_and_host_fault_propagates(
        self,
    ):
        for operation in ("control_io", "stop_filter"):
            for successful in (False, True):
                with self.subTest(operation=operation, successful=successful):
                    context, _, _ = fixture(AIRBAG)

                    def fault(event, operation=operation):
                        if event["operation"] == operation and (
                            operation != "control_io"
                            or event["parameters"] == ((0x1E, 0),)
                        ):
                            raise NativePassThruError2026(24)

                    replies = (
                        (b"\x67\x03\x01\x02\x34", b"\x67\x04\x34", b"\x50")
                        if successful
                        else (b"bad",)
                    )
                    rt, events = runtime(replies, fault=fault)
                    result = prepare_body(context, rt)
                    self.assertEqual(result["native_return"], successful)
                    self.assertEqual(result["prepared"], successful)
                    self.assertEqual(result["host_result"], "cleanup_failed")
                    self.assertEqual(events[-1]["operation"], "stop_filter")
        original = OSError("host stop failed")

        def host_fault(event):
            if event["operation"] == "stop_filter":
                raise original

        context, _, _ = fixture(AIRBAG)
        rt, _ = runtime(fault=host_fault)
        with self.assertRaises(OSError) as caught:
            prepare_body(context, rt)
        self.assertIs(caught.exception, original)

    def test_native_cleanup_catchall_scopes_preserve_preparation_results(self):
        from scripts.programming_2026_common import NativeException2026

        cases = (
            (SONAR, (b"\x67\x03\x01\x02\x34", b"\x67\x04\x34", b"\x50")),
            (BODY, (b"\x67\x61" + bytes(6), b"\x67\x62\x34", b"\x50")),
            (
                SECURITY,
                (b"\x67\x03" + bytes(16) + b"\x34", b"\x67\x04\x34", b"\x50") * 2,
            ),
            (CHASSIS, (b"\x67\x01" + bytes(4), b"\x67\x02", b"\x50")),
            (SECURITY_CHASSIS, (b"\x67\x01" + bytes(16), b"\x67\x02", b"\x50")),
            (POWER, (b"\x67\x01" + bytes(4), b"\x67\x02", b"\x50")),
        )
        for module, replies in cases:
            for success in (False, True):
                with self.subTest(module=module, success=success):
                    context, _, _ = fixture(module)

                    def fault(event):
                        if event["operation"] == "stop_filter":
                            raise NativeException2026("native cleanup")

                    rt, _ = runtime(replies if success else (b"bad",), fault=fault)
                    result = run_native_context(
                        context,
                        rt,
                        **(
                            {"secret_info": secret_client()}
                            if module in (SECURITY, SECURITY_CHASSIS)
                            else {}
                        ),
                    )
                    self.assertEqual(result["native_return"], success)
                    self.assertEqual(result["prepared"], success)
                    self.assertEqual(result["host_result"], "cleanup_failed")
                    self.assertTrue(rt.owns_resource("stop_filter", identifier=17))
                    self.assertNotEqual(result["native_error_code"], 9999)

    def test_unknown_native_body_and_powertrain_inner_scopes_only_map_9999(self):
        from scripts.programming_2026_common import NativeException2026

        for module, operation, payload, mapped in (
            (BODY, "start_flow_control_filter", None, True),
            (BODY, "write_messages", bytes.fromhex("00000720a027"), True),
            (BODY, "control_io", None, False),
            (SONAR, "start_flow_control_filter", None, False),
            (POWER, "write_messages", bytes.fromhex("000001002701"), True),
            (POWER, "write_messages", bytes.fromhex("000001002702"), True),
            (POWER, "start_flow_control_filter", None, False),
            (POWER, "write_messages", bytes.fromhex("00000720a027"), False),
        ):
            for native in (True, False):
                with self.subTest(
                    module=module, operation=operation, payload=payload, native=native
                ):
                    context, _, _ = fixture(
                        module,
                        extra={"CanIDForPrepareWrite": "0100AA/0108AA"}
                        if operation == "control_io"
                        else {},
                    )
                    original = (
                        NativeException2026("native inner")
                        if native
                        else ValueError("host inner")
                    )

                    def fault(
                        event, operation=operation, payload=payload, original=original
                    ):
                        if event["operation"] == operation and (
                            payload is None
                            or event.get("data", b"").startswith(payload)
                        ):
                            raise original

                    replies = (
                        (b"\x67\x61" + bytes(6), b"\x67\x62\x34", b"\x50")
                        if module == BODY
                        else (b"\x67\x01" + bytes(4), b"\x67\x02", b"\x50")
                    )
                    rt, _ = runtime(replies, fault=fault)
                    if mapped and native:
                        result = run_native_context(context, rt)
                        self.assertFalse(result["native_return"])
                        self.assertEqual(result["native_error_code"], 9999)
                        self.assertEqual(result["result_status_update"], 1)
                    else:
                        with self.assertRaises(type(original)) as caught:
                            run_native_context(context, rt)
                        self.assertIs(caught.exception, original)

    def test_powertrain_native_cleanup_catchall_exits_entire_filter_loop(self):
        from scripts.programming_2026_common import NativeException2026

        context, _, _ = fixture(
            POWER, extra={"CanIDForPrepareWrite": "0100/0108\n0200/0208"}
        )
        base, events = runtime(
            (b"\x67\x01" + bytes(4), b"\x67\x02") * 2 + (b"\x50",) * 2
        )
        identifiers, stopped, failed = [], [], [False]

        def action(event, remaining):
            if event["operation"] == "start_flow_control_filter":
                base.action(event, remaining)
                identifier = 17 + len(identifiers)
                identifiers.append(identifier)
                return identifier
            if event["operation"] == "stop_filter":
                stopped.append(event["identifier"])
                if not failed[0]:
                    failed[0] = True
                    raise NativeException2026("native first cleanup")
            return base.action(event, remaining)

        rt = NativeRuntime2026(action)
        result = run_native_context(context, rt)
        self.assertTrue(result["native_return"])
        self.assertEqual(result["host_result"], "cleanup_failed")
        self.assertEqual(stopped, [17])
        self.assertTrue(rt.owns_resource("stop_filter", identifier=17))
        self.assertTrue(rt.owns_resource("stop_filter", identifier=18))
        self.assertEqual(rt.close(), [])
        self.assertEqual(stopped, [17, 18, 17])
        self.assertEqual(events[-1]["operation"], "stop_filter")

    def _sonar_control(
        self,
        *,
        fault=None,
        cancel_after=None,
        typed=False,
        observations=None,
        driver_fault=None,
        context_mutate=None,
        module=SONAR_WRITE,
        engine_mutate=None,
        public_export=False,
        block_size_info="0:1x1",
        capture_state=None,
        issue_worker=False,
        initialize_prepare=False,
        first_cpu_endian=False,
        body_flags=None,
        target_count=1,
        factory_export=False,
        cpu_index=1,
        on_unwind=None,
        receive_cids=False,
        after_write_session=None,
        cid_target_index=0,
        full_raw=False,
        raw_capture=None,
        primitive_rows=None,
        frozen_rows=None,
        distinct_images=False,
    ):
        if issue_worker:
            receive_cids = True
            initialize_prepare = True
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.programming_2026_body import (
            _run_airbag_write_algorithm as run_airbag_write,
        )
        from scripts.programming_2026_body import (
            _run_body_write_algorithm as run_body_write,
        )
        from scripts.programming_2026_body import (
            _run_dss_write_algorithm as run_dss_write,
        )
        from scripts.programming_2026_body import (
            _run_security_airbag_write_algorithm as run_security_airbag_write,
        )
        from scripts.programming_2026_body import (
            _run_shrink_write_algorithm as run_shrink_write,
        )
        from scripts.programming_2026_body import (
            _run_sonar_write_algorithm as run_sonar_write,
        )
        from scripts.programming_2026_body import (
            bind_airbag_write_context,
            bind_body_write_context,
            bind_dss_write_context,
            bind_security_airbag_write_context,
            bind_shrink_write_context,
            bind_sonar_write_context,
        )

        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated CUW2026 image absent")
        raw, container, selection, general = writer_selection(
            module,
            cpu_index=cpu_index,
            block_size_info=block_size_info,
            initialize_prepare=initialize_prepare,
            encoded=initialize_prepare,
            first_cpu_endian=first_cpu_endian,
            body_flags=body_flags,
            target_count=target_count,
            distinct_images=distinct_images,
        )
        if module == SONAR_WRITE:
            binder, runner = bind_sonar_write_context, run_sonar_write
        elif module == "TCUWP4CanAirbagFlashWriter.dll":
            binder, runner = bind_airbag_write_context, run_airbag_write
        elif module == "TCUWP4CanSecurityAirbagFlashWriter.dll":
            binder, runner = (
                bind_security_airbag_write_context,
                run_security_airbag_write,
            )
        elif module == "TCUWP4CanDSS1FlashWriter.dll":
            binder, runner = bind_dss_write_context, run_dss_write
        elif module in (
            "TCUWP4CanBodyFlashWriter.dll",
            "TCUWP4CanBodyFlashWriterForCXPI.dll",
            "TCUWP5CanBodyFlashWriter.dll",
        ):
            binder, runner = bind_body_write_context, run_body_write
        else:
            binder, runner = bind_shrink_write_context, run_shrink_write
        if public_export:
            binder, runner = bind_native_context, run_native_context
        context = binder(
            container, 1, (), selection, identity(module), {}, observations or {}
        )
        if context_mutate is not None:
            context = context_mutate(context)
        replies, events, echoes, driver_events = sonar_payloads(), [], [], []
        if module == "TCUWP4CanBodyFlashWriterForCXPI.dll":
            replies[-1:-1] = [b"\x3c", b"\x3c", b"\0", b"\x3c"] * 4
        if (body_flags or {}).get("FlagToNonVerifyProcess") == "1":
            replies = replies[:18] + replies[-1:]
        if (body_flags or {}).get("ExternalMemoryFlag") == "1":
            replies[3] = bytes.fromhex("00000000000003ff0100") + b"\0"
        if module in (
            "TCUWP4CanSecurityChassisShrinkFlashWriter.dll",
            "TCUWP4CanSecurityAirbagFlashWriter.dll",
        ):
            replies[2:2] = [b"\x3c", b"\x3c"]
            replies[-1:-1] = [b"\x3c", b"\x3c", b"\0", b"\x3c"]
        if full_raw and cpu_index == 0:
            replies *= 2
        if initialize_prepare:
            replies[:0] = [
                bytes.fromhex("6761010203040506"),
                bytes.fromhex("676234"),
                b"\x50",
            ]
        actual_cids = tuple(
            f"{'SECOND' if cid_target_index else 'OLD'}_{cpu}".encode()
            for cpu in ("A", "B")
        )
        if receive_cids:
            replies[:0] = [
                bytes.fromhex("490010000000"),
                b"\x49\x04\x02"
                + b"".join((cid + b"\0").ljust(16, b" ") for cid in actual_cids),
            ]
        response_address = (0x108 + cpu_index * 0x100).to_bytes(4, "big")
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )

        with (
            tempfile.TemporaryDirectory(dir="runtime/no-car-74") as directory,
            CUWEngine2026(image.read_bytes()) as engine,
        ):
            engine.configure(struct.pack("<IIddII", 2, 0, 0, 0, 0, 0))
            engine.bind_general_parameters(general)
            engine.load_cuw(raw, cpu_index=0 if receive_cids else cpu_index)
            persistence = CUWPersistence(
                Path(directory) / "recovery",
                ReproInfoState(
                    (RecoveryCalibration("authored.cuw", raw),),
                    write_cpu_index=0 if receive_cids else cpu_index,
                ),
            )
            engine.bind_persistence(persistence)
            engine.dh_state.set_use_new_password(context.retry_password)
            if engine_mutate is not None:
                engine_mutate(engine)
            device = None
            if typed:

                def driver(operation, remaining):
                    self.assertGreater(remaining, 0)
                    driver_events.append(operation)
                    if driver_fault is not None:
                        injected = driver_fault(operation)
                        if injected is not None:
                            return injected
                    name = operation["operation"]
                    if name in (
                        "create_mutex",
                        "load_library",
                        "get_symbol",
                        "passthru_load_library",
                        "passthru_open",
                        "passthru_connect",
                        "passthru_start_filter",
                    ):
                        return PrimitiveResult(value=17)
                    if name == "wait_handle":
                        return PrimitiveResult(value=0)
                    if name == "passthru_read_version":
                        return PrimitiveResult(value=("1", "1", "1"))
                    if name == "passthru_write":
                        message = operation["messages"][0]
                        echoes.append(NativeMessage(6, message.data[:4], rx_status=9))
                        return PrimitiveResult(value=operation["count"])
                    if name == "passthru_read":
                        message = (
                            echoes.pop(0)
                            if echoes
                            else NativeMessage(
                                6,
                                response_address + replies.pop(0),
                            )
                        )
                        return PrimitiveResult(value=(message,))
                    return PrimitiveResult()

                if not issue_worker:
                    device = J2534Device2026(
                        driver, background_workers=False, clock=lambda: 0
                    )
                    device.open()
                    if not receive_cids:
                        device.connect(6)

            def action(event, remaining):
                nonlocal response_address
                events.append(event)
                if fault is not None:
                    fault(event)
                if event["operation"] == "get_local_milliseconds_of_day":
                    return 0
                if device is not None:
                    if event["operation"] == "read_specified_can_message":
                        response_address = event["address"]
                    if (
                        event["operation"] == "read_specified_can_message"
                        and event["frame"] == 1
                    ):
                        echoes.append(NativeMessage(6, event["address"], rx_status=2))
                    return device.primitive(event, remaining)
                name = event["operation"]
                if name == "get_timeout":
                    return 999
                if name == "get_send_timeout":
                    return 200
                if name == "start_flow_control_filter":
                    return 17
                if name == "write_messages":
                    return event["count"]
                if name == "read_specified_can_message":
                    return event["address"] + replies.pop(0)
                return None

            def cleanup(event, remaining):
                events.append(event)
                if fault is not None:
                    fault(event)
                return (
                    device.cleanup_primitive(event, remaining)
                    if device is not None
                    else None
                )

            prepare_session = None
            if initialize_prepare:
                from scripts.programming_replay import (
                    ProgrammingTrace,
                    load_programming_replay,
                )

                catalogs = dict(selection.catalog_sources)
                modules = {
                    name: Path("runtime/no-car-21/recovered", name).read_bytes()
                    for name in (
                        BODY,
                        module,
                        "CUW.dll",
                        "TCUWControlCommPhase.dll",
                        "TCUWCanCIDGetter.dll",
                        "TCUWJ2534DeviceIF.dll",
                    )
                }
                document = {
                    "schema": "techstream-programming-replay-v1",
                    "source": "recorded_unverified",
                    "calibration_sha256": hashlib.sha256(raw).hexdigest(),
                    "operation": "prepare",
                    "node": 1,
                    "observations": {
                        "current_cids": [],
                        "tester_info_hex": bytes(32).hex(),
                        "system_time": [2026, 10, 2, 20, 1, 2, 3, 4],
                        "timeout_seconds": 300,
                        "cid_mode": 2,
                        "host": {
                            "cpu_index": 0 if receive_cids else cpu_index,
                            **(
                                {"driver_recording": "j2534_2026"}
                                if issue_worker
                                else {}
                            ),
                        },
                    },
                    "events": [],
                }
                prepare_session = load_programming_replay(
                    raw, json.dumps(document).encode(), catalogs, modules
                )
                from types import MethodType

                trace = (
                    ProgrammingTrace.validate(list(frozen_rows))
                    if frozen_rows is not None
                    else ProgrammingTrace(())
                )
                trace.cancelled = lambda: (
                    cancel_after is not None and len(events) > cancel_after
                )

                def driver_value(value):
                    if type(value) is NativeMessage:
                        return {"_native_type": "PASSTHRU_MSG_2026", **vars(value)}
                    if type(value) is tuple:
                        return tuple(driver_value(item) for item in value)
                    return value

                def typed_value(value):
                    if value is None:
                        return {"type": "none", "value": None}
                    if type(value) is bytes:
                        return {"type": "bytes", "value": value.hex()}
                    if type(value) in (bool, int, str):
                        return {
                            "type": {bool: "bool", int: "int", str: "text"}[
                                type(value)
                            ],
                            "value": value,
                        }
                    if type(value) is tuple:
                        return {
                            "type": "tuple",
                            "value": [typed_value(item) for item in value],
                        }
                    if type(value) is dict:
                        return {
                            "type": "mapping",
                            "value": {
                                key: typed_value(item) for key, item in value.items()
                            },
                        }
                    raise TypeError("Authored primitive value must be explicitly typed")

                def remember(request, value):
                    from scripts.programming_replay import _native_request

                    if primitive_rows is not None:
                        primitive_rows.append(
                            {
                                "kind": "action",
                                "request": _native_request(request),
                                "result": typed_value(value),
                                "elapsed_ms": request.get("milliseconds", 0)
                                if request["operation"] == "wait"
                                else 0,
                            }
                        )
                    return value

                def consume(_trace, kind, request, remaining=None):
                    if kind != "action":
                        raise AssertionError("Native body uses primitive actions")
                    _trace.position += 1
                    name = request["operation"]
                    value = None
                    if name.startswith("get_local_"):
                        events.append(request)
                        if fault is not None:
                            fault(request)
                        value = 0
                    elif name == "set_communication_log_mode":
                        value = 0
                    elif name == "get_timeout":
                        value = 999
                    elif name == "get_send_timeout":
                        value = 200
                    return remember(request, value)

                def driver_primitive(_trace, event, remaining):
                    _trace.position += 1
                    reply = driver(event, remaining)
                    remember(
                        event,
                        {"status": reply.status, "value": driver_value(reply.value)},
                    )
                    return reply

                if frozen_rows is None:
                    trace.consume = MethodType(consume, trace)
                    trace.driver_primitive = MethodType(driver_primitive, trace)
                prepare_session.trace = trace
                rt = NativeRuntime2026(
                    trace.action,
                    clock=trace.clock,
                    cancelled=trace.cancelled,
                    local_seconds_of_day=trace.native_local_seconds_of_day,
                    local_milliseconds_of_day=trace.native_local_milliseconds_of_day,
                )
                if issue_worker:
                    from scripts.j2534_2026 import DriverMetadata2026

                    prepare_session.bind_runtime2026(rt)
                    pair = trace.interface_pair
                    assert pair is not None
                    for view in (pair.engine, pair.control):
                        view.set_current_driver(
                            DriverMetadata2026("Authored", "authored.dll")
                        )
                    engine.bind_interface_pair(pair)
                    device = pair.control
                    if not receive_cids:
                        pair.engine.open()
            else:
                rt = NativeRuntime2026(
                    action,
                    cleanup_action=cleanup,
                    cancelled=lambda: (
                        cancel_after is not None and len(events) > cancel_after
                    ),
                )
            if issue_worker:
                from scripts.cuw_2026 import identity_2026
                from scripts.programming_2026_common import ControlCommPhase2026

                controller = ControlCommPhase2026(
                    identity_2026(
                        Path(
                            "runtime/no-car-21/recovered/TCUWControlCommPhase.dll"
                        ).read_bytes(),
                        "TCUWControlCommPhase.dll",
                    ),
                    rt,
                )
                engine.bind_worker(controller)
            from contextlib import ExitStack
            from unittest.mock import patch

            from scripts.programming_replay import (
                ProgrammingReplay,
                load_programming_replay,
            )

            with ExitStack() as observers:
                if initialize_prepare:
                    original_action = ProgrammingTrace.action
                    original_cleanup = ProgrammingTrace.cleanup_primitive

                    def observed(original, traced, event, remaining):
                        nonlocal response_address
                        if traced is trace:
                            events.append(event)
                            if fault is not None:
                                fault(event)
                            if event["operation"] == "read_specified_can_message":
                                response_address = event["address"]
                                if event.get("frame") == 1:
                                    echoes.append(
                                        NativeMessage(6, event["address"], rx_status=2)
                                    )
                        return original(traced, event, remaining)

                    observers.enter_context(
                        patch.object(
                            ProgrammingTrace,
                            "action",
                            lambda traced, event, remaining: observed(
                                original_action, traced, event, remaining
                            ),
                        )
                    )
                    observers.enter_context(
                        patch.object(
                            ProgrammingTrace,
                            "cleanup_primitive",
                            lambda traced, event, remaining: observed(
                                original_cleanup, traced, event, remaining
                            ),
                        )
                    )
                    # Rebind only the observer methods before any runtime action.
                    rt.action = trace.action
                    rt.cleanup_action = trace.cleanup_primitive

                def root_session(operation):
                    document["operation"] = operation
                    document["observations"]["host"]["cpu_index"] = (
                        engine.native_metadata.cpu_index
                    )
                    following = load_programming_replay(
                        raw, json.dumps(document).encode(), catalogs, modules
                    )
                    following.trace = trace
                    following.bind_runtime2026(rt)
                    return following

                try:
                    if receive_cids:
                        getter_session = root_session("get_cid")
                        with engine.controller_execution(controller, 0):
                            held = controller.native_control_context2026(engine)
                            received = controller.execute(engine, getter_session)
                            engine.worker.import_control_getter_return2026(held)
                            self.assertTrue(engine.worker.mark_cid_reception_complete())
                        self.assertEqual(received["identifiers"], actual_cids)
                        self.assertEqual(engine.received_identifiers, actual_cids)
                        engine.select_target(1, cpu_index, controller=controller)
                        prepare_session = root_session("prepare")
                        if device is not None:
                            wire = engine.engine_runtime_device()
                            if not wire.opened:
                                wire.open()
                            if not wire.connecting:
                                wire.connect(6)
                    if full_raw:
                        stages = []
                        run_bound = ProgrammingReplay.run_bound2026

                        def record_stage(stage, runtime):
                            report = run_bound(stage, runtime)
                            stages.append((stage._control_export2026, stage, report))
                            return report

                        with (
                            patch.object(
                                ProgrammingReplay, "run_bound2026", record_stage
                            ),
                            engine.controller_execution(controller, 1),
                        ):
                            pair = engine.interface_pair
                            assert pair is not None
                            with patch.object(
                                pair, "import_into", wraps=pair.import_into
                            ) as transfers:
                                raw_result = controller.execute(engine, prepare_session)
                            self.assertEqual(
                                [call.args[0] for call in transfers.call_args_list],
                                [pair.control],
                            )
                            self.assertTrue(
                                raw_result["native_return"], repr(raw_result)
                            )
                            self.assertEqual(raw_result["native_phase"], 1)
                            self.assertIsNotNone(raw_result["control_snapshot"])
                            self.assertEqual(
                                [export for export, _, _ in stages],
                                ["StartPrepareWrite"]
                                + ["StartFlashWrite"] * (2 - cpu_index),
                            )
                            self.assertTrue(
                                all(
                                    stage._runtime2026 is rt and stage.trace is trace
                                    for _, stage, _ in stages
                                )
                            )
                            writes = [
                                report
                                for export, _stage, report in stages
                                if export == "StartFlashWrite"
                            ]
                            self.assertTrue(writes, repr(raw_result))
                            result = writes[-1]
                            if raw_capture is not None:
                                raw_capture(raw_result, stages, engine)
                    else:
                        if prepare_session is not None:
                            prepare_session.bind_controller2026(controller)
                            with engine.controller_execution(controller, 1):
                                controller._begin_execute_pair(engine)
                                prepare_session.bind_engine2026(engine)
                                prepared = prepare_session.run_bound2026(rt)
                            self.assertTrue(prepared["native_return"], repr(prepared))
                        if factory_export:
                            assert prepare_session is not None
                            write_session = prepare_session.next_session2026(
                                "write",
                                node=engine.native_metadata.node,
                                cpu_index=engine.native_metadata.cpu_index,
                            )
                            with engine.controller_execution(controller, 2):
                                result = write_session.run_bound2026(rt)
                            if after_write_session is not None:
                                after_write_session(write_session, engine)
                        else:
                            if public_export and issue_worker:
                                metadata = engine.native_metadata
                                live_selection = bind_native_parameter2026(
                                    metadata.source_container,
                                    dict(selection.catalog_sources),
                                    "write",
                                    node=metadata.node,
                                    cpu_index=metadata.cpu_index,
                                    encoded=selection.encoded,
                                    metadata_state=metadata,
                                )
                                context = binder(
                                    metadata.source_container,
                                    metadata.node,
                                    (),
                                    live_selection,
                                    identity(module),
                                    {},
                                    observations or {},
                                )
                                if context_mutate is not None:
                                    context = context_mutate(context)
                            if issue_worker:
                                with engine.controller_execution(controller, 2):
                                    result = runner(context, rt, engine=engine)
                            else:
                                result = runner(context, rt, engine=engine)
                    if capture_state is not None:
                        capture_state(engine)
                finally:
                    if on_unwind is not None:
                        on_unwind(engine)
                    self.assertEqual(rt.close(), [])
                    if device is not None:
                        device.disconnect()
            if frozen_rows is not None:
                self.assertEqual(trace.position, len(trace.rows))
            return result, events, replies, driver_events

    def test_nine_writers_use_normal_source_factory_and_actual_phase2(self):
        from scripts.programming_2026_body import _WRITER_MODULES

        for module in _WRITER_MODULES:
            with self.subTest(module=module):
                rows = []
                result, _, replies, _ = self._sonar_control(
                    module=module,
                    typed=True,
                    public_export=True,
                    issue_worker=True,
                    initialize_prepare=True,
                    factory_export=True,
                    full_raw=True,
                    target_count=2,
                    primitive_rows=rows,
                )
                replayed = self._sonar_control(
                    module=module,
                    typed=True,
                    public_export=True,
                    issue_worker=True,
                    initialize_prepare=True,
                    factory_export=True,
                    full_raw=True,
                    target_count=2,
                    frozen_rows=tuple(rows),
                )[0]
                self.assertEqual(result, replayed)
                self.assertTrue(result["native_return"], repr(result))
                self.assertEqual(result["state"], "writer_completed")
                self.assertFalse(result["programming_completed"])
                self.assertEqual(
                    replies, [b"\x3c"] if "ChassisShrink" in module else []
                )
                self.assertNotIn("StartFlashWrite", IMPLEMENTED_EXPORTS.get(module, ()))

    def test_nine_writers_receive_actual_cids_before_normal_prepare_and_write(self):
        from scripts.programming_2026_body import _WRITER_MODULES

        for module in _WRITER_MODULES:
            with self.subTest(module=module):
                rows = []
                result, events, replies, _ = self._sonar_control(
                    module=module,
                    typed=True,
                    public_export=True,
                    issue_worker=True,
                    initialize_prepare=True,
                    factory_export=True,
                    full_raw=True,
                    receive_cids=True,
                    primitive_rows=rows,
                )
                replayed = self._sonar_control(
                    module=module,
                    typed=True,
                    public_export=True,
                    issue_worker=True,
                    initialize_prepare=True,
                    factory_export=True,
                    full_raw=True,
                    receive_cids=True,
                    frozen_rows=tuple(rows),
                )[0]
                self.assertEqual(result, replayed)
                self.assertTrue(result["native_return"], repr(result))
                self.assertEqual(result["state"], "writer_completed")
                self.assertFalse(result["programming_completed"])
                self.assertEqual(
                    replies, [b"\x3c"] if "ChassisShrink" in module else []
                )
                operations = [event["operation"] for event in events]
                self.assertLess(
                    operations.index("connect"),
                    operations.index("start_flow_control_filter"),
                )
                self.assertLess(
                    operations.index("disconnect"),
                    len(operations)
                    - 1
                    - operations[::-1].index("start_flow_control_filter"),
                )

    def test_raw_body_two_cpu_chain_writes_each_source_once(self):
        for module in (SONAR_WRITE, "TCUWP4CanBodyFlashWriter.dll"):
            rows = []
            reports = []

            def capture(raw_result, stages, engine, reports=reports):
                self.assertTrue(raw_result["native_return"], repr(raw_result))
                self.assertEqual(
                    [export for export, _, _ in stages],
                    ["StartPrepareWrite", "StartFlashWrite", "StartFlashWrite"],
                )
                writes = [
                    (stage._executed_selection2026.metadata.cpu_index, report)
                    for export, stage, report in stages
                    if export == "StartFlashWrite"
                ]
                self.assertEqual([cpu for cpu, _ in writes], [0, 1])
                self.assertTrue(all(report["native_return"] for _, report in writes))
                self.assertIsNotNone(raw_result["control_snapshot"])
                reports.append(tuple(report for _, report in writes))

            options = {
                "module": module,
                "typed": True,
                "public_export": True,
                "issue_worker": True,
                "full_raw": True,
                "cpu_index": 0,
                "distinct_images": True,
                "raw_capture": capture,
            }
            with self.subTest(module=module, pass_kind="capture"):
                _, _, replies, driver_events = self._sonar_control(
                    **options, primitive_rows=rows
                )
                self.assertEqual(replies, [])
                image = b"ZV\0" + (1019).to_bytes(2, "big") + bytes(1019)
                writes = [
                    event["messages"][0].data
                    for event in driver_events
                    if event["operation"] == "passthru_write"
                ]
                # Distinct source archives must each be downloaded exactly once.
                self.assertEqual(writes.count(bytes.fromhex("00000100") + image), 1)
                self.assertEqual(
                    writes.count(bytes.fromhex("00000200") + image[:-1] + b"\x01"), 1
                )
            with self.subTest(module=module, pass_kind="frozen_from_zero"):
                self._sonar_control(**options, frozen_rows=tuple(rows))
                self.assertEqual(reports[0], reports[1])

    def test_nine_writer_retry_preflight_retains_executed_source_row(self):
        """Standalone retained family sessions; no expired CONTROL target reuse."""
        from scripts.programming_2026_body import _WRITER_MODULES

        for module in _WRITER_MODULES:
            checked = []

            def after_write(session, engine, module=module, checked=checked):
                original = session._executed_selection2026
                self.assertIsNotNone(original)
                position = session.trace.position
                for make_auxiliary, operation in (
                    (session.next_retry2026, "recovery"),
                    (session.next_finish2026, "probe"),
                ):
                    auxiliary = make_auxiliary()
                    retained = auxiliary._selection2026
                    self.assertIsNotNone(retained)
                    self.assertEqual(auxiliary.selected_binding2026(), retained)
                    self.assertEqual(auxiliary.operation, operation)
                    self.assertEqual(retained.operation, "write")
                    self.assertEqual(retained.module_name, module)
                    self.assertEqual(retained.source_name, original.source_name)
                    self.assertEqual(retained.source_sha256, original.source_sha256)
                    self.assertEqual(retained.key, original.key)
                    self.assertIs(retained.values, original.values)
                    self.assertIs(retained.headers, original.headers)
                    self.assertIs(retained.rows, original.rows)
                    self.assertEqual(auxiliary.selected_identity().module_name, module)
                    self.assertEqual(session.trace.position, position)
                with self.assertRaisesRegex(ValueError, "source|metadata|target"):
                    original.rebind_writer_metadata(
                        replace(engine.native_metadata, source_sha256="0" * 64)
                    )
                with self.assertRaisesRegex(ValueError, "source|metadata|target"):
                    original.rebind_writer_metadata(
                        replace(engine.native_metadata, cpu_index=0)
                    )
                checked.append(True)

            with self.subTest(module=module):
                self._sonar_control(
                    module=module,
                    typed=True,
                    public_export=True,
                    issue_worker=True,
                    initialize_prepare=True,
                    factory_export=True,
                    after_write_session=after_write,
                )
                self.assertEqual(checked, [True])

    def test_nine_factory_writers_preserve_native_failure_without_completion(self):
        """Standalone real factory exports preserve each original failure report."""
        from scripts.programming_2026_body import _WRITER_MODULES
        from scripts.programming_2026_common import CommonResponseError

        for module in _WRITER_MODULES:
            failed = False

            def fault(event):
                nonlocal failed
                if (
                    event.get("data") == bytes.fromhex("0000020000")
                    and event["operation"] == "write_messages"
                    and not failed
                ):
                    failed = True
                    raise CommonResponseError(10)

            with self.subTest(module=module):
                result, _, _, _ = self._sonar_control(
                    module=module,
                    typed=True,
                    public_export=True,
                    issue_worker=True,
                    initialize_prepare=True,
                    factory_export=True,
                    target_count=2,
                    fault=fault,
                )
                self.assertTrue(failed)
                self.assertFalse(result["native_return"])
                self.assertEqual(result["native_error_code"], 10)
                self.assertNotEqual(result["state"], "writer_completed")
                self.assertFalse(result["programming_completed"])

    def test_secondary_cpu_native_success_queues_concrete_continuation(self):
        """One real standalone family writer; the outer job has not consumed it."""
        for module in (
            "TCUWP4CanChassisShrinkFlashWriter.dll",
            "TCUWP4CanSecurityChassisShrinkFlashWriter.dll",
            "TCUWP4CanSecurityAirbagFlashWriter.dll",
            "TCUWP4CanDSS1FlashWriter.dll",
            "TCUWP5CanBodyFlashWriter.dll",
        ):
            state = []

            def unwind(engine, state=state):
                continuation = engine.worker.take_continuation()
                state.append((engine.native_metadata.cpu_index, continuation))
                self.assertIsNone(engine.worker.take_continuation())

            with self.subTest(module=module):
                result, events, replies, _ = self._sonar_control(
                    module=module,
                    typed=True,
                    public_export=True,
                    issue_worker=True,
                    initialize_prepare=True,
                    factory_export=True,
                    cpu_index=0,
                    on_unwind=unwind,
                )
                self.assertTrue(result["native_return"], repr(result))
                self.assertEqual(result["state"], "writer_completed")
                self.assertFalse(result["programming_completed"])
                self.assertEqual(replies, [])
                self.assertEqual(state[0][0], 1)
                continuation = state[0][1]
                self.assertIsNotNone(continuation)
                self.assertEqual(continuation.kind, "cpu")
                self.assertEqual(continuation.cpu_index, 1)
                self.assertEqual(continuation.target_index, 0)
                self.assertFalse(continuation.ig_cycle_required)
                self.assertTrue(
                    any(
                        event.get("data") == bytes.fromhex("0000010065")
                        for event in events
                    )
                )

    def test_secondary_cpu_native_failure_defers_until_concrete_continuation(self):
        from scripts.programming_2026_common import (
            CommonResponseError,
            NativeException2026,
        )

        for module in (
            "TCUWP4CanChassisShrinkFlashWriter.dll",
            "TCUWP4CanSecurityChassisShrinkFlashWriter.dll",
            "TCUWP4CanSecurityAirbagFlashWriter.dll",
            "TCUWP4CanDSS1FlashWriter.dll",
            "TCUWP5CanBodyFlashWriter.dll",
        ):
            for original, code in (
                (CommonResponseError(10), 10),
                (NativeException2026("Authored native unknown ChangeNextCpu"), 9999),
            ):
                state = []
                fired = False

                def fault(event, original=original):
                    nonlocal fired
                    if event.get("data") == bytes.fromhex("0000010065"):
                        fired = True
                        raise original

                def unwind(engine, state=state):
                    state.append(
                        (
                            engine.native_metadata.cpu_index,
                            engine.worker.take_continuation(),
                        )
                    )

                with self.subTest(module=module, native_code=code):
                    result, _, _, _ = self._sonar_control(
                        module=module,
                        typed=True,
                        public_export=True,
                        issue_worker=True,
                        initialize_prepare=True,
                        factory_export=True,
                        cpu_index=0,
                        fault=fault,
                        on_unwind=unwind,
                    )
                    self.assertTrue(fired)
                    self.assertFalse(result["native_return"])
                    self.assertEqual(result["native_error_code"], code)
                    self.assertFalse(result["programming_completed"])
                    self.assertEqual(state[0][0], 1)
                    self.assertEqual(state[0][1].kind, "cpu")
                    self.assertEqual(state[0][1].cpu_index, 1)

    def test_secondary_cpu_host_failure_never_queues_native_continuation(self):
        for module in (
            "TCUWP4CanChassisShrinkFlashWriter.dll",
            "TCUWP4CanSecurityChassisShrinkFlashWriter.dll",
            "TCUWP4CanSecurityAirbagFlashWriter.dll",
            "TCUWP4CanDSS1FlashWriter.dll",
            "TCUWP5CanBodyFlashWriter.dll",
        ):
            for exception_type in (OSError, InterruptedError, KeyboardInterrupt):
                original = exception_type("Authored ChangeNextCpu host interruption")
                state = []
                fired = False

                def fault(event, original=original):
                    nonlocal fired
                    if event.get("data") == bytes.fromhex("0000010065"):
                        fired = True
                        raise original

                def unwind(engine, state=state):
                    state.append(
                        (
                            engine.native_metadata.cpu_index,
                            engine.worker.take_continuation(),
                        )
                    )

                with self.subTest(module=module, exception=exception_type.__name__):
                    with self.assertRaises(exception_type) as caught:
                        self._sonar_control(
                            module=module,
                            typed=True,
                            public_export=True,
                            issue_worker=True,
                            initialize_prepare=True,
                            cpu_index=0,
                            factory_export=True,
                            fault=fault,
                            on_unwind=unwind,
                        )
                    self.assertTrue(fired)
                    self.assertIs(caught.exception, original)
                    self.assertEqual(state, [(0, None)])

    def test_public_writer_target_vector_selects_second_source_target_password(self):
        for module in (
            SONAR_WRITE,
            "TCUWP4CanAirbagFlashWriter.dll",
            "TCUWP4CanSecurityAirbagFlashWriter.dll",
            "TCUWP4CanDSS1FlashWriter.dll",
            "TCUWP4CanChassisShrinkFlashWriter.dll",
            "TCUWP4CanSecurityChassisShrinkFlashWriter.dll",
            "TCUWP4CanBodyFlashWriter.dll",
            "TCUWP4CanBodyFlashWriterForCXPI.dll",
            "TCUWP5CanBodyFlashWriter.dll",
        ):
            with self.subTest(module=module):
                is_body = module in (
                    "TCUWP4CanBodyFlashWriter.dll",
                    "TCUWP4CanBodyFlashWriterForCXPI.dll",
                    "TCUWP5CanBodyFlashWriter.dll",
                )
                result, _, _, driver_events = self._sonar_control(
                    module=module,
                    typed=True,
                    public_export=True,
                    issue_worker=True,
                    initialize_prepare=is_body,
                    observations={"target_index": 1},
                    cid_target_index=1,
                    target_count=2,
                )
                self.assertTrue(result["native_return"])
                messages = [
                    event["messages"][0].data
                    for event in driver_events
                    if event["operation"] == "passthru_write"
                ]
                self.assertIn(bytes.fromhex("0000020005040302"), messages)
                self.assertNotIn(bytes.fromhex("0000020078563412"), messages)
        with self.assertRaisesRegex(ValueError, "target index differs"):
            self._sonar_control(
                module=SONAR_WRITE,
                typed=True,
                public_export=True,
                issue_worker=True,
                target_count=2,
                observations={"target_index": 1},
            )

    def test_body_public_writers_every_typed_host_fault_and_cancellation_after_phase1(
        self,
    ):
        for module in (
            "TCUWP4CanBodyFlashWriter.dll",
            "TCUWP4CanBodyFlashWriterForCXPI.dll",
            "TCUWP5CanBodyFlashWriter.dll",
        ):
            options = {
                "module": module,
                "typed": True,
                "public_export": True,
                "issue_worker": True,
                "initialize_prepare": True,
            }
            _, baseline, _, _ = self._sonar_control(**options)
            clocks = [
                index
                for index, event in enumerate(baseline)
                if event["operation"] == "get_local_milliseconds_of_day"
            ]
            # Entry and exit timing both belong to the real phase2 scope.
            start = clocks[-2] + 1
            self.assertTrue(
                any(
                    event["operation"] == "write_messages" for event in baseline[start:]
                )
            )
            for index in range(start, clocks[-1]):
                with (
                    self.subTest(module=module, index=index, control="cancel"),
                    self.assertRaises(InterruptedError),
                ):
                    self._sonar_control(**options, cancel_after=index)
                calls = 0
                original = OSError("Authored public Body typed host failure")

                def fault(_event, index=index, original=original):
                    nonlocal calls
                    current, calls = calls, calls + 1
                    if current == index:
                        raise original

                with (
                    self.subTest(module=module, index=index, control="host_fault"),
                    self.assertRaises(OSError) as caught,
                ):
                    self._sonar_control(**options, fault=fault)
                self.assertIs(caught.exception, original)

    def test_body_public_source_flags_nonverify_external_memory_and_header_error(self):
        for module in (
            "TCUWP4CanBodyFlashWriter.dll",
            "TCUWP4CanBodyFlashWriterForCXPI.dll",
            "TCUWP5CanBodyFlashWriter.dll",
        ):
            for flags in (
                {"FlagToNonVerifyProcess": "1"},
                {"ExternalMemoryFlag": "1"},
                {"ReadBlockRangeFromS0HeaderFlag": "1"},
            ):
                with self.subTest(module=module, flags=flags):
                    result, _, replies, driver_events = self._sonar_control(
                        module=module,
                        typed=True,
                        public_export=True,
                        issue_worker=True,
                        initialize_prepare=True,
                        body_flags=flags,
                    )
                    payloads = [
                        event["messages"][0].data[4:]
                        for event in driver_events
                        if event["operation"] == "passthru_write"
                    ]
                    if "ReadBlockRangeFromS0HeaderFlag" in flags:
                        self.assertFalse(result["native_return"])
                        self.assertEqual(result["native_error_code"], 6)
                        self.assertEqual(result["native_context_978_update"], 1)
                        self.assertEqual(result["counts"], (0, 0))
                    else:
                        self.assertTrue(result["native_return"])
                        self.assertEqual(replies, [])
                        self.assertEqual(result["percentages"], (0, 100))
                        self.assertEqual(
                            result["counts"],
                            (0, 1024 if "FlagToNonVerifyProcess" in flags else 2048),
                        )
                        if "FlagToNonVerifyProcess" in flags:
                            self.assertNotIn(bytes.fromhex("1600000000"), payloads)
                            self.assertNotIn(bytes.fromhex("1800000000"), payloads)

    def test_body_public_writers_use_actual_phase1_retained_getter_cpu_producer(self):
        # This proves native phase1→public writer source inputs; full CID/worker
        # orchestration is reviewed separately and is not mocked here.
        for module in (
            "TCUWP4CanBodyFlashWriter.dll",
            "TCUWP4CanBodyFlashWriterForCXPI.dll",
            "TCUWP5CanBodyFlashWriter.dll",
        ):
            with self.subTest(module=module):
                result, _, replies, driver_events = self._sonar_control(
                    module=module,
                    typed=True,
                    public_export=True,
                    issue_worker=True,
                    initialize_prepare=True,
                    first_cpu_endian=True,
                )
                self.assertTrue(result["native_return"])
                self.assertEqual(result["counts"], (0, 2048))
                self.assertEqual(replies, [])
                messages = [
                    event["messages"][0].data
                    for event in driver_events
                    if event["operation"] == "passthru_write"
                ]
                self.assertIn(bytes.fromhex("0000020012345678"), messages)
                self.assertNotIn(bytes.fromhex("0000020078563412"), messages)
                self.assertEqual(
                    messages[-1],
                    bytes.fromhex("000004000080" if "CXPI" in module else "0000040080"),
                )

    def test_six_public_writer_exports_use_actual_worker_issued_target_and_flag(self):
        # Real getter/outer import retains34e10; phase1 applies36800/3e710.
        # These standalone writer calls consume actual worker73c/980, not a
        # fabricated CONTROL target or the complete multiCPU/IG lifecycle.
        for module in (
            SONAR_WRITE,
            "TCUWP4CanAirbagFlashWriter.dll",
            "TCUWP4CanSecurityAirbagFlashWriter.dll",
            "TCUWP4CanDSS1FlashWriter.dll",
            "TCUWP4CanChassisShrinkFlashWriter.dll",
            "TCUWP4CanSecurityChassisShrinkFlashWriter.dll",
        ):
            with self.subTest(module=module):
                result, _, _, _ = self._sonar_control(
                    module=module, typed=True, public_export=True, issue_worker=True
                )
                self.assertTrue(result["native_return"])
                self.assertEqual(result["counts"], (0, 2048))

    def test_security_and_dss_candidates_every_typed_host_fault_and_cancellation(self):
        for module in (
            "TCUWP4CanSecurityAirbagFlashWriter.dll",
            "TCUWP4CanSecurityChassisShrinkFlashWriter.dll",
            "TCUWP4CanDSS1FlashWriter.dll",
        ):
            _, baseline, _, _ = self._sonar_control(module=module, typed=True)
            for index in range(len(baseline)):
                with (
                    self.subTest(module=module, index=index, control="cancel"),
                    self.assertRaises(InterruptedError),
                ):
                    self._sonar_control(module=module, typed=True, cancel_after=index)
                calls = 0
                original = OSError("Authored typed writer host failure")

                def fault(_event, index=index, original=original):
                    nonlocal calls
                    current, calls = calls, calls + 1
                    if current == index:
                        raise original

                with (
                    self.subTest(module=module, index=index, control="host_fault"),
                    self.assertRaises(OSError) as caught,
                ):
                    self._sonar_control(module=module, typed=True, fault=fault)
                self.assertIs(caught.exception, original)

    def test_writer_candidates_native_business_unknown_and_cleanup_scopes(self):
        from scripts.programming_2026_common import (
            CommonResponseError,
            NativeException2026,
            NativePassThruException2026,
        )

        for module, status in (
            (SONAR_WRITE, 2),
            ("TCUWP4CanAirbagFlashWriter.dll", 1),
            ("TCUWP4CanSecurityAirbagFlashWriter.dll", 1),
            ("TCUWP4CanDSS1FlashWriter.dll", 1),
            ("TCUWP4CanChassisShrinkFlashWriter.dll", 2),
            ("TCUWP4CanSecurityChassisShrinkFlashWriter.dll", 2),
        ):
            fired = False

            def business(event):
                nonlocal fired
                if event["operation"] == "write_messages" and not fired:
                    fired = True
                    raise CommonResponseError(10)

            with self.subTest(module=module, scope="typed_business"):
                result, _, _, _ = self._sonar_control(
                    module=module, typed=True, fault=business
                )
                self.assertFalse(result["native_return"])
                self.assertEqual(result["native_error_code"], 10)
                self.assertEqual(result["result_status_update"], status)
                self.assertEqual(result["counts"], (0, 0))

            fired = False
            original = NativeException2026("authored unknown native failure")

            def unknown(event, original=original):
                nonlocal fired
                if event["operation"] == "write_messages" and not fired:
                    fired = True
                    raise original

            # Keep the post-call assertion inside the subTest scope: an absent
            # private image skips the control call and must skip this check too.
            with self.subTest(module=module, scope="unknown_business"):
                with self.assertRaises(NativeException2026) as caught:
                    self._sonar_control(module=module, typed=True, fault=unknown)
                self.assertIs(caught.exception, original)

            fired = False

            def cleanup(event):
                nonlocal fired
                if event["operation"] == "stop_filter" and not fired:
                    fired = True
                    raise NativePassThruException2026(99, "authored", 1)

            with self.subTest(module=module, scope="native_cleanup_catchall"):
                result, _, _, _ = self._sonar_control(
                    module=module, typed=True, fault=cleanup
                )
                self.assertTrue(result["native_return"])
                self.assertEqual(result["host_result"], "cleanup_failed")

    def test_shrink_empty_ranges_reject_native_undefined_dereference(self):
        with self.assertRaisesRegex(ValueError, "Native block rows"):
            self._sonar_control(
                module="TCUWP4CanChassisShrinkFlashWriter.dll",
                typed=True,
                block_size_info="",
            )

    def test_shrink_native_inserts_leading_zero_sizes_for_nonzero_first_range(self):
        result, _, replies, driver_events = self._sonar_control(
            module="TCUWP4CanChassisShrinkFlashWriter.dll",
            typed=True,
            block_size_info="2:1x1",
        )
        self.assertTrue(result["native_return"])
        self.assertEqual(result["counts"], (0, 2048))
        self.assertEqual(replies, [b"\x3c"])
        payloads = [
            event["messages"][0].data[4:]
            for event in driver_events
            if event["operation"] == "passthru_write"
        ]
        self.assertIn(bytes.fromhex("2600020002"), payloads)

    def test_cxpi_native_erase_keepalive_four_sleeps_three_extended_writes(self):
        from scripts.programming_2026_body import (
            _cxpi_erase_block,
            bind_body_write_context,
        )
        from scripts.programming_2026_legacy import CommonFlash2026

        module = "TCUWP4CanBodyFlashWriterForCXPI.dll"
        _, container, selected, _ = writer_selection(module)
        context = bind_body_write_context(
            container, 1, (), selected, identity(module), {}, {}
        )
        rt, events = runtime((b"\x3c", b"\x3c", b"\0", b"\x3c"))
        _cxpi_erase_block(
            context,
            CommonFlash2026(rt),
            bytes.fromhex("00000200"),
            bytes.fromhex("00000208"),
            2,
            5,
            selected.parameter,
        )
        writes = [event for event in events if event["operation"] == "write_messages"]
        self.assertEqual(writes[0]["data"], bytes.fromhex("000002002600010004"))
        self.assertEqual(
            [event["data"] for event in writes[1:4]],
            [bytes.fromhex("00000200003e02")] * 3,
        )
        self.assertEqual([event["tx_flags"] for event in writes[1:4]], [0x80] * 3)
        waits = [
            event["milliseconds"] for event in events if event["operation"] == "wait"
        ]
        self.assertEqual(waits, [2000] * 4 + [0])
        self.assertEqual(writes[-1]["data"], bytes.fromhex("0000020050"))
        self.assertEqual(rt.close(), [])

    def test_public_writer_exports_reject_unissued_native_target_before_io(self):
        for module in (
            SONAR_WRITE,
            "TCUWP4CanAirbagFlashWriter.dll",
            "TCUWP4CanSecurityAirbagFlashWriter.dll",
            "TCUWP4CanDSS1FlashWriter.dll",
            "TCUWP4CanChassisShrinkFlashWriter.dll",
            "TCUWP4CanSecurityChassisShrinkFlashWriter.dll",
            "TCUWP4CanBodyFlashWriter.dll",
            "TCUWP4CanBodyFlashWriterForCXPI.dll",
            "TCUWP5CanBodyFlashWriter.dll",
        ):
            with (
                self.subTest(module=module),
                self.assertRaisesRegex(
                    ValueError, "73c|target|3cb90|actual CUW engine worker"
                ),
            ):
                self._sonar_control(
                    module=module,
                    typed=True,
                    public_export=True,
                    fault=lambda _event: self.fail(
                        "Unissued target reached native I/O"
                    ),
                )

    def test_body_writers_unissued_getter_type_fails_with_owned_cleanup(self):
        for module in (
            "TCUWP4CanBodyFlashWriter.dll",
            "TCUWP4CanBodyFlashWriterForCXPI.dll",
            "TCUWP5CanBodyFlashWriter.dll",
        ):
            events = []
            # The skip for an absent private image must cover the retained-event
            # assertions as well, not only the control call itself.
            with self.subTest(module=module):
                with self.assertRaisesRegex(
                    ValueError, "984|36800|retained|getter|actual CUW engine worker"
                ):
                    self._sonar_control(module=module, typed=True, fault=events.append)
                self.assertEqual(
                    events[-1], {"operation": "set_timeout", "milliseconds": 0}
                )
                self.assertIn("stop_filter", [event["operation"] for event in events])
                if "CXPI" in module:
                    self.assertIn(
                        {
                            "operation": "control_io",
                            "ioctl": 2,
                            "parameters": ((30, 0),),
                        },
                        events,
                    )
                self.assertNotIn(
                    "write_messages", [event["operation"] for event in events]
                )

    def test_body_gateway_distinct_native_parameter_phase(self):
        context, _, selected = fixture(
            BODY,
            operation="change_gateway",
            extra={
                "DLLFileNameForChangeToReprogGatewayMode": BODY,
                "GetCANIDFunctionNameForChangeToReprogGatewayMode": "GetCanIDsFromParamForPrepareWrite",
            },
        )
        self.assertEqual(selected.operation, "change_gateway")
        rt, events = runtime(
            (b"\x67\x61\x01\x02\x03\x04\x05\x06", b"\x67\x62\x34", b"\x50")
        )
        result = run_native_context(context, rt)
        self.assertTrue(result["gateway_mode_changed"])
        writes = [
            event["data"] for event in events if event["operation"] == "write_messages"
        ]
        self.assertEqual(writes[-1], bytes.fromhex("000001001060"))
        with self.assertRaises(ValueError):
            run_native_context(context, rt, gateway_only=False)

    def test_security_airbag_final_cpu_typed_wire(self):
        result, _baseline, replies, driver_events = self._sonar_control(
            module="TCUWP4CanSecurityAirbagFlashWriter.dll", typed=True
        )
        self.assertTrue(result["native_return"])
        self.assertEqual(replies, [])
        self.assertTrue(result["completion_notification"])
        self.assertFalse(result["retry_password"])
        payloads = [
            event["messages"][0].data[4:]
            for event in driver_events
            if event["operation"] == "passthru_write"
        ]
        self.assertIn(b"\x37" + b"\x11" * 6, payloads)
        self.assertIn(b"\x3a" + b"\x22" * 6, payloads)
        self.assertIn(b"\x47", payloads)
        self.assertEqual(payloads[-1], bytes.fromhex("aa80"))

    def test_dss_final_cpu_typed_wire(self):
        module = "TCUWP4CanDSS1FlashWriter.dll"
        result, _baseline, replies, driver_events = self._sonar_control(
            module=module, typed=True
        )
        self.assertTrue(result["native_return"])
        self.assertEqual(replies, [])
        self.assertEqual(result["counts"], (0, 2048))
        self.assertTrue(result["retry_notification"])
        messages = [
            event["messages"][0].data
            for event in driver_events
            if event["operation"] == "passthru_write"
        ]
        self.assertEqual(messages[-1], bytes.fromhex("00000300aa80"))

    def test_security_shrink_writer_typed_nonce_seed_and_falsification(self):
        result, _, replies, driver_events = self._sonar_control(
            module="TCUWP4CanSecurityChassisShrinkFlashWriter.dll", typed=True
        )
        self.assertTrue(result["native_return"])
        self.assertEqual(replies, [b"\x3c"])
        payloads = [
            event["messages"][0].data[4:]
            for event in driver_events
            if event["operation"] == "passthru_write"
        ]
        for payload in (
            b"\x37" + b"\x11" * 6,
            b"\x38" + b"\x11" * 6,
            b"\x39" + b"\x11" * 4,
            b"\x3a" + b"\x22" * 6,
            b"\x3b" + b"\x22" * 6,
            b"\x3c" + b"\x22" * 4,
            b"\x47",
        ):
            self.assertIn(payload, payloads)

    def test_shrink_writer_final_cpu_no_finish_response_and_fault_controls(self):
        module = "TCUWP4CanChassisShrinkFlashWriter.dll"
        result, baseline, replies, driver_events = self._sonar_control(
            module=module, typed=True
        )
        self.assertTrue(result["native_return"])
        self.assertEqual(replies, [b"\x3c"])
        messages = [
            event["messages"][0].data
            for event in driver_events
            if event["operation"] == "passthru_write"
        ]
        self.assertEqual(messages[-1], bytes.fromhex("0000030080"))
        self.assertFalse(result["retry_notification"])
        self.assertTrue(result["completion_notification"])
        for index in range(len(baseline)):
            with (
                self.subTest(index=index, control="cancel"),
                self.assertRaises(InterruptedError),
            ):
                self._sonar_control(module=module, typed=True, cancel_after=index)
            calls = 0
            original = OSError("Shrink typed primitive fault")

            def fault(_event, index=index, original=original):
                nonlocal calls
                current, calls = calls, calls + 1
                if current == index:
                    raise original

            with (
                self.subTest(index=index, control="host_fault"),
                self.assertRaises(OSError) as caught,
            ):
                self._sonar_control(module=module, typed=True, fault=fault)
            self.assertIs(caught.exception, original)

    def test_airbag_native_retry_and_status_notification_checkpoint(self):
        from scripts.programming_2026_common import CommonResponseError

        module = "TCUWP4CanAirbagFlashWriter.dll"
        failed = False

        def once(event):
            nonlocal failed
            if event["operation"] == "write_messages" and not failed:
                failed = True
                raise CommonResponseError(7)

        result, events, replies, _ = self._sonar_control(
            module=module,
            fault=once,
            engine_mutate=lambda engine: engine.notification.assign(True),
        )
        self.assertTrue(result["native_return"])
        self.assertEqual(result["native_error_code"], 7)
        self.assertEqual(replies, [])
        self.assertTrue(failed)
        self.assertIn({"operation": "wait", "milliseconds": 0}, events)

        engine_ref = []
        failed = False

        def late_notification(event):
            nonlocal failed
            if event["operation"] == "write_messages" and not failed:
                failed = True
                raise CommonResponseError(10)
            if event["operation"] == "stop_filter":
                engine_ref[0].notification.assign(False)

        after = {}
        result, _, _, _ = self._sonar_control(
            module=module,
            fault=late_notification,
            capture_state=lambda engine: after.update(
                comm_phase=engine.dh_state.comm_phase,
                write_complete=engine.dh_state.write_complete,
            ),
            engine_mutate=lambda engine: (
                engine_ref.append(engine),
                engine.notification.assign(True),
            ),
        )
        self.assertFalse(result["native_return"])
        self.assertEqual(result["result_status_update"], 1)
        self.assertEqual(result["native_context_978_update"], 1)
        self.assertEqual(after, {"comm_phase": 1, "write_complete": False})

    def test_airbag_writer_actual_shared_wire_and_typed_host_faults(self):
        module = "TCUWP4CanAirbagFlashWriter.dll"
        result, baseline, replies, _ = self._sonar_control(module=module, typed=True)
        self.assertTrue(result["native_return"])
        self.assertEqual(replies, [])
        self.assertEqual(result["counts"], (0, 2048))
        self.assertTrue(result["retry_notification"])
        self.assertTrue(result["completion_notification"])
        self.assertNotIn("get_send_timeout", [event["operation"] for event in baseline])
        for index in range(len(baseline)):
            with (
                self.subTest(index=index, control="cancel"),
                self.assertRaises(InterruptedError),
            ):
                self._sonar_control(module=module, typed=True, cancel_after=index)
            calls = 0
            original = OSError("Airbag typed primitive fault")

            def fault(_event, index=index, original=original):
                nonlocal calls
                current, calls = calls, calls + 1
                if current == index:
                    raise original

            with self.subTest(index=index, control="host_fault"):
                with self.assertRaises(OSError) as caught:
                    self._sonar_control(module=module, typed=True, fault=fault)
                self.assertIs(caught.exception, original)

    def test_sonar_writer_rejects_forged_source_address_before_io(self):
        from dataclasses import replace

        from scripts.j2534_2026 import NativeCommunicationAddress

        forged = NativeCommunicationAddress(
            bytes.fromhex("0500"), bytes.fromhex("0508")
        )
        for mutate in (
            lambda context: replace(context, address=forged),
            lambda context: replace(context, image=b"\x01" + context.image[1:]),
            lambda context: replace(context, flash_size=1),
            lambda context: replace(context, location_id=bytes(8)),
            lambda context: replace(context, password=context.password ^ 1),
            lambda context: replace(context, target_index=999),
            lambda context: replace(context, finish_address=forged),
            lambda context: replace(context, address_groups=((forged, forged),) * 2),
        ):
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self._sonar_control(
                    context_mutate=mutate,
                    fault=lambda _event: self.fail("Forged context reached driver I/O"),
                )

    def test_sonar_writer_typed_j2534_complete_wire_and_host_primitive_controls(self):
        result, _events, replies, driver_events = self._sonar_control(typed=True)
        self.assertTrue(
            result["native_return"],
            repr((result, _events[-8:], driver_events[-8:]))
            if not result["native_return"]
            else "",
        )
        self.assertEqual(replies, [])
        self.assertEqual(result["counts"], (0, 2048))
        messages = [
            event["messages"][0].data
            for event in driver_events
            if event["operation"] == "passthru_write"
        ]
        self.assertEqual(messages[-1], bytes.fromhex("00000300aa80"))
        _, baseline, _, _ = self._sonar_control()
        for index, event in enumerate(baseline):
            with self.subTest(index=index, operation=event["operation"]):
                calls, failed = [0], [False]
                original = OSError("Sonar host primitive fault")

                def fault(
                    _event, index=index, calls=calls, failed=failed, original=original
                ):
                    current = calls[0]
                    calls[0] += 1
                    if current == index and not failed[0]:
                        failed[0] = True
                        raise original

                with self.assertRaises(OSError) as caught:
                    self._sonar_control(fault=fault)
                self.assertIs(caught.exception, original)
                with self.assertRaises(InterruptedError):
                    self._sonar_control(cancel_after=index)

    def test_sonar_writer_actual_j2534_status_fault_and_cancellation_controls(self):
        def status_fault(operation):
            if operation["operation"] == "passthru_write":
                return PrimitiveResult(status=24)
            return None

        result, _, _, driver_events = self._sonar_control(
            typed=True, driver_fault=status_fault
        )
        self.assertFalse(result["native_return"])
        self.assertEqual(
            (result["native_error_code"], result["driver_error_code"]), (7, 24)
        )
        self.assertIn(
            "passthru_stop_filter", [event["operation"] for event in driver_events]
        )
        _, baseline, _, _ = self._sonar_control(typed=True)
        for index, event in enumerate(baseline):
            with self.subTest(index=index, operation=event["operation"]):
                with self.assertRaises(InterruptedError):
                    self._sonar_control(typed=True, cancel_after=index)
                calls, failed = [0], [False]
                original = ValueError("typed Sonar host fault")

                def fault(
                    _event, index=index, calls=calls, failed=failed, original=original
                ):
                    current = calls[0]
                    calls[0] += 1
                    if current == index and not failed[0]:
                        failed[0] = True
                        raise original

                with self.assertRaises(ValueError) as caught:
                    self._sonar_control(typed=True, fault=fault)
                self.assertIs(caught.exception, original)

    def test_sonar_writer_native_business_cleanup_and_restore_scopes(self):
        from scripts.programming_2026_common import NativeException2026

        _, baseline, _, _ = self._sonar_control()
        stop = next(
            index
            for index, event in enumerate(baseline)
            if event["operation"] == "stop_filter"
        )
        first_business = next(
            index
            for index, event in enumerate(baseline)
            if event["operation"] == "start_flow_control_filter"
        )
        cases: list[tuple[int, Exception, int | None]] = [
            (index, NativeException2026("native unknown"), None)
            for index in range(len(baseline))
        ]
        known = {
            bytes.fromhex("0000020000"): 7,
            bytes.fromhex("0000020076"): 10,
            bytes.fromhex("0000020026"): 12,
            bytes.fromhex("0000020041"): 13,
            bytes.fromhex("0000020048"): 14,
            bytes.fromhex("0000020016"): 15,
            bytes.fromhex("00000300aa80"): 35,
        }
        seen = set()
        for index, event in enumerate(baseline):
            prefix = next(
                (
                    prefix
                    for prefix in known
                    if prefix not in seen and event.get("data", b"").startswith(prefix)
                ),
                None,
            )
            if prefix is not None:
                seen.add(prefix)
            expected = (
                1
                if index == first_business
                else known[prefix]
                if prefix is not None
                else None
            )
            if expected is not None or index < first_business or index >= stop:
                cases.extend(
                    (
                        (
                            index,
                            NativePassThruError2026(24),
                            expected if expected in (13, 15) else 24,
                        ),
                        (index, NativeJ2534Error2026(24), expected),
                    )
                )
        for index, error, expected in cases:
            with self.subTest(
                index=index,
                operation=baseline[index]["operation"],
                error=type(error).__name__,
            ):
                calls, failed = [0], [False]

                def fault(_event, index=index, calls=calls, failed=failed, error=error):
                    current = calls[0]
                    calls[0] += 1
                    if current == index and not failed[0]:
                        failed[0] = True
                        raise error

                if index == stop:
                    result, events, _, _ = self._sonar_control(fault=fault)
                    self.assertTrue(result["native_return"])
                    self.assertEqual(result["host_result"], "cleanup_failed")
                    self.assertIsNone(result["native_error_code"])
                    self.assertEqual(
                        sum(event["operation"] == "stop_filter" for event in events), 2
                    )
                elif (
                    index < first_business
                    or index > stop
                    or type(error) is NativeException2026
                ):
                    with self.assertRaises(type(error)) as caught:
                        self._sonar_control(fault=fault)
                    self.assertIs(caught.exception, error)
                else:
                    result, _, _, _ = self._sonar_control(fault=fault)
                    self.assertFalse(result["native_return"])
                    self.assertEqual(result["result_status_update"], 2)
                    self.assertEqual(result["counts"], (0, 0))
                    self.assertEqual(result["percentages"], (0, 0))
                    self.assertEqual(result["native_error_code"], expected)
                    self.assertEqual(
                        result["driver_error_code"],
                        24 if isinstance(error, NativeJ2534Error2026) else None,
                    )

    def test_sonar_writer_retry_password_mutation_before_finish_and_native_initial_timeout(
        self,
    ):
        for after_finish in (False, True):
            with self.subTest(after_finish=after_finish):
                target = (
                    bytes.fromhex("00000300aa80")
                    if after_finish
                    else bytes.fromhex("0000020000")
                )

                def fault(event, target=target):
                    if event.get("data") == target:
                        raise NativePassThruError2026(7)

                result, _, _, _ = self._sonar_control(
                    fault=fault, observations={"retry_password": True}
                )
                self.assertFalse(result["native_return"])
                self.assertEqual(result["native_error_code"], 7)
                self.assertEqual(result["retry_password"], after_finish)
                self.assertEqual(result["flashing_ended"], after_finish)
        result, events, _, _ = self._sonar_control(
            observations={
                "native_initial_command_retry_980": True,
                "retry_password": True,
            }
        )
        self.assertTrue(result["native_return"])
        self.assertIn({"operation": "set_timeout", "milliseconds": 10000}, events)
        writes = [
            event["data"] for event in events if event["operation"] == "write_messages"
        ]
        # GetNewPassword retains the first DWORD of the authored native ZV frame.
        self.assertEqual(writes[4], bytes.fromhex("000002005A560003"))

    def test_sonar_writer_actual_shared_wire_selected_cpu_and_first_cpu_finish(self):
        from scripts.cuw_2026 import CUWEngine2026
        from scripts.programming_2026_body import (
            _run_sonar_write_algorithm as run_sonar_write,
        )
        from scripts.programming_2026_body import (
            bind_sonar_write_context,
        )

        image = Path("runtime/no-car-21/recovered/CUW.dll")
        if not image.is_file():
            self.skipTest("Authenticated CUW2026 image absent")
        raw, container, selection, general = writer_selection(SONAR_WRITE)
        context = bind_sonar_write_context(
            container, 1, (), selection, identity(SONAR_WRITE), {}, {}
        )
        self.assertEqual(context.address.request, bytes.fromhex("0200"))
        self.assertEqual(context.finish_address.request, bytes.fromhex("0300aa"))
        ack, status = b"\x3c", b"\0"
        replies = [ack, b"ID", ack, bytes.fromhex("0000000003ff0100") + b"\0", ack]
        replies += [ack, ack, status, ack]
        replies += [ack, ack, ack, status, ack]
        replies += [ack, ack, status, ack]
        replies += [ack] + [ack, ack, status, ack] * 4
        replies += [ack]
        from scripts.cuw_persistence import (
            CUWPersistence,
            RecoveryCalibration,
            ReproInfoState,
        )

        with (
            tempfile.TemporaryDirectory(dir="runtime/no-car-74") as directory,
            CUWEngine2026(image.read_bytes()) as engine,
        ):
            engine.configure(struct.pack("<IIddII", 2, 0, 0, 0, 0, 0))
            engine.bind_general_parameters(general)
            engine.load_cuw(raw, cpu_index=1)
            persistence = CUWPersistence(
                Path(directory) / "recovery",
                ReproInfoState(
                    (RecoveryCalibration("authored.cuw", raw),), write_cpu_index=1
                ),
            )
            engine.bind_persistence(persistence)
            engine.dh_state.set_use_new_password(context.retry_password)
            base, events = runtime(replies)

            def action(event, remaining):
                if event["operation"] == "get_send_timeout":
                    events.append(event)
                    return 200
                return base.action(event, remaining)

            observed = []
            rt = NativeRuntime2026(action)
            result = run_sonar_write(
                context, rt, engine=engine, notify=lambda *event: observed.append(event)
            )
            self.assertTrue(result["native_return"])
            self.assertEqual(result["counts"], (0, 2048))
            self.assertEqual(result["percentages"], (0, 100))
            self.assertEqual(engine.dh_state.transferred_bytes, (0, 2048))
            self.assertEqual(engine.dh_state.progress, (0, 100))
            self.assertFalse(result["retry_notification"])
            self.assertFalse(result["completion_notification"])
            self.assertEqual(result["native_context_75c_update"], False)
            self.assertIn(("native_callback7",), observed)
            writes = [
                event["data"]
                for event in events
                if event["operation"] == "write_messages"
            ]
            self.assertEqual(writes[-1], bytes.fromhex("00000300aa80"))
            self.assertEqual(
                events[-2:],
                [
                    {"operation": "set_timeout", "milliseconds": 999},
                    {"operation": "set_send_timeout", "milliseconds": 200},
                ],
            )
            self.assertEqual(rt.close(), [])

    def test_selected_finish_probe_binding_uses_actual_cpu_zero_first_group(self):
        from scripts.programming_2026_body import bind_finish_context

        for module in (
            "TCUWP4CanAirbagFlashWriter.dll",
            "TCUWP4CanSecurityAirbagFlashWriter.dll",
            "TCUWP4CanDSS1FlashWriter.dll",
        ):
            with self.subTest(module=module):
                _, container, selected, _ = writer_selection(module)
                context = bind_finish_context(
                    container, 1, ("IGNORED_CID",), selected, identity(module), {}, {}
                )
                self.assertEqual(context.groups[0][0].request, bytes.fromhex("0100"))
                self.assertEqual(context.groups[1][0].request, bytes.fromhex("0200"))
                rt, events = runtime((b"\x3c",))
                self.assertTrue(
                    is_finish_reprogramming(context.identity, rt, context.groups)
                )
                writes = [
                    event["data"]
                    for event in events
                    if event["operation"] == "write_messages"
                ]
                self.assertEqual(writes, [bytes.fromhex("000001003e")])
                with self.assertRaises(ValueError):
                    bind_finish_context(
                        container, 1, (), selected, identity(module), {}, {"groups": ()}
                    )

    def test_source_binding_accepts_approved_cpu_overrides_and_rejects_tampering(self):
        from scripts.calibration_2026 import (
            native2026_metadata,
            native2026_with_cpu_type,
        )

        for module in (
            AIRBAG,
            SONAR,
            SECURITY,
            BODY,
            CHASSIS,
            SECURITY_CHASSIS,
            CENTRAL,
            POWER,
        ):
            with self.subTest(module=module):
                context, container, binding = fixture(module)
                state = native2026_with_cpu_type(
                    native2026_metadata(container, cpu_index=1), 0, "C"
                )
                state = native2026_with_cpu_type(state, 1, "D")
                catalogs = dict(binding.catalog_sources)
                for cpu in ("C", "D"):
                    catalogs["8P4" + cpu + ".ini"] = catalogs["8P4A.ini"].replace(
                        b"8P4A", ("8P4" + cpu).encode()
                    )
                selected = bind_native_parameter2026(
                    container,
                    catalogs,
                    "prepare",
                    encoded=False,
                    cpu_index=1,
                    metadata_state=state,
                )
                bound = bind_native_context(
                    container, 1, (), selected, context.identity, {}, {}
                )
                self.assertEqual(bound.binding.cpu_type, "D")
                self.assertEqual(bound.binding.module_binding.cpu_type, "C")
                with self.assertRaises(ValueError):
                    bind_native_context(
                        container,
                        1,
                        (),
                        replace(selected, key="unrelated"),
                        context.identity,
                        {},
                        {},
                    )

    def test_p4_powertrain_all_unavailable_retry_flag_and_fatal_key_timeout(self):
        from scripts.programming_2026_body import prepare_powertrain

        context, _, _ = fixture(POWER)
        for flag, retry in ((False, False), (False, True), (True, False)):
            rt, _ = runtime((NativeJ2534Error2026(9),))
            result = prepare_powertrain(
                replace(context, native_retry_flag_964=flag),
                rt,
                retry_notification=retry,
            )
            self.assertEqual(result["prepared_targets"], ())
            self.assertEqual(result["native_return"], flag or retry)
            self.assertEqual(result["native_error_code"], None if flag else 17)
            self.assertEqual(result["native_retry_skip"], flag)
        for replies, native, driver in (
            ((NativeJ2534Error2026(5),), 1, 5),
            ((b"\x67\x01\x01\x02\x03\x04", NativeJ2534Error2026(9)), 1, 9),
            ((b"\x67\x01\x01\x02\x03\x04", b"\x7f\x27\x35"), 17, None),
        ):
            rt, events = runtime(replies)
            result = prepare_powertrain(context, rt)
            self.assertEqual(
                (
                    result["native_return"],
                    result["native_error_code"],
                    result["driver_error_code"],
                ),
                (False, native, driver),
            )
            self.assertEqual(result["skipped_targets"], ())
            self.assertEqual(events[-1]["operation"], "stop_filter")


if __name__ == "__main__":
    unittest.main()
