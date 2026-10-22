"""Authored wire vectors over actual2026 CUW/parameter/address producers."""

import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from scripts import programming_2026_common as shared
from scripts.calibration_2026 import (
    native2026_metadata,
    native2026_with_cpu_type,
    parse_cuw_2026,
)
from scripts.j2534_2026 import (
    J2534Device2026,
    NativeJ2534Error2026,
    NativeMessage,
    NativePassThruError2026,
    PrimitiveResult,
)
from scripts.native_modules import identify_native_module
from scripts.programming import NativeTransportError
from scripts.programming_2026_common import (
    NativeException2026,
    NativeJ2534Exception2026,
    NativePassThruException2026,
    NativeRuntime2026,
    NativeSecurityComposer2026,
    NotificationBool,
    SecretInfoClient,
    bind_native_parameter2026,
    seed_key_four_round,
    seed_key_six_byte,
)
from scripts.programming_2026_p5_prepare import (
    BODY,
    DUAL,
    MODULE_EXPORTS,
    POWER,
    SECURITY,
    SOLAR,
    P5PrepareContext2026,
    bind_native_context,
    run_native_context,
)
from tests.test_calibration_2026 import cuw
from tests.test_programming_2026_body import parameters

HASHES = {
    "TCUWP4P5CanPowerTrainPrepareWriter.dll": "ab75226350266c2ff7923791b0dcfb4567e9aae172835eb627df4ca895fb5bb8",
    "TCUWP5CanPowerTrainPrepareWriter.dll": "34998145137882e47c6b831590883449e9b5c12ddb1b619dc52c30fd709e9ba8",
    "TCUWP5CanPowerTrainPrepareWriterForBodyMicon.dll": "fcafe832794438d5db98855af788e1f2cc3c2df055090e79ecc81e1bc8c4bd44",
    "TCUWP5CanPowerTrainPrepareWriterForSolar.dll": "54fe7fd72f3750b850a7f8db0011f031a445e2988386817a73becb3cc3e3b2b8",
    "TCUWP5CanSecurityPowerTrainPrepareWriter.dll": "29a837ac6acf794da9748ac96df89a0828c137b7cf7ba825a44edffda010a26c",
}


def secret_client():
    # The test explicitly issues synthetic authorization, never a production
    # native identity. Production clients must come from authenticated PE bytes.
    client = SecretInfoClient(
        b"authored-client", tuple((i, b"authored-secret") for i in range(64)), "a" * 64
    )
    shared._SECRET_INFO_CLIENTS[id(client)] = client
    client.authorize(b"authored-client")
    return client


def fixture(
    module=POWER,
    *,
    addresses=None,
    retry=False,
    return_inputs=False,
    ig_off_retriable=True,
):
    if addresses is None:
        addresses = "0100/0108\n0200/0208" if module == DUAL else "0100/0108"
    text = (
        "[Format]\nVersion=7\n[Vehicle]\nKindOfECU=8\nContactType=P4\nNumberOfCalibration=2\n"
        "ECUAuthKey=11111111111111111111111111111111\nServiceAuthKey=22222222222222222222222222222222\n"
        "[CPU01]\nCPUType=A\nCPUImageName=authored.vbf\nLocationID=0108010000000000\n"
        "NumberOfTargets=1\n01_TargetCalibration=OLD_A\n"
        "[CPU02]\nCPUType=B\nCPUImageName=second.vbf\nLocationID=0208020000000000\n"
        "NumberOfTargets=1\n01_TargetCalibration=OLD_B\n"
    )
    container = parse_cuw_2026(cuw(text, (b"\0authored", b"\0second")))
    values = {
        "DLLFileNameForPrepareWrite": module,
        "GetCANIDFunctionNameForPrepareWrite": "GetCanIDsFromParamForPrepareWrite",
        "CanIDForPrepareWrite": addresses,
        "SecurityKey": "1111\n2222\n3333\n4444",
        "WaitTimeAfterSeedData": "2",
        "WaitTimeAfterSeedKey": "3",
        "WaitTimeAfterDiagnosticMask": "4",
        "IGOffRetriableFlag": "1" if ig_off_retriable else "0",
    }
    binding = bind_native_parameter2026(
        container, {"8P4A.ini": parameters("8P4A", values)}, "prepare", encoded=False
    )
    identity = identify_native_module(HASHES[module], module)
    context = bind_native_context(
        container, 1, (), binding, identity, {}, {"native_retry_flag_964": retry}
    )
    return (context, container, binding) if return_inputs else context


def runtime(replies, fault=None, cancelled=lambda: False):
    events = []
    replies = iter(replies)

    def action(event, remaining):
        events.append(event)
        if fault:
            fault(event)
        operation = event["operation"]
        if operation == "start_flow_control_filter":
            return len(events)
        if operation == "get_timeout":
            return 999
        if operation == "write_messages":
            return 1
        if operation == "read_specified_can_message":
            value = next(replies)
            if isinstance(value, BaseException):
                raise value
            return event["address"] + value
        if operation == "decrypt_secret_info":
            return b"\xaa" * 16
        if operation == "calculate_security_key":
            return b"\xbb" * 16
        return None

    return NativeRuntime2026(action, cancelled=cancelled), events


PROBE = bytes.fromhex("500200000000")
ROUTINE = bytes.fromhex("71011003")


class P5PrepareTests(unittest.TestCase):
    def setUp(self):
        scope = patch.dict(shared._SECRET_INFO_CLIENTS)
        scope.start()
        self.addCleanup(scope.stop)

    def test_all_five_selected_sources_and_wire(self):
        for module in MODULE_EXPORTS:
            with self.subTest(module=module):
                size = 16 if module == SECURITY else 6 if module == BODY else 4
                replies = [
                    PROBE,
                    b"\x67\x01" + bytes(range(size)),
                    b"\x67\x02",
                    ROUTINE,
                ]
                if module == DUAL:
                    replies = [
                        PROBE,
                        b"\x67\x01" + bytes(range(4)),
                        b"\x67\x02",
                        b"\x67\x01" + bytes(range(4)),
                        b"\x67\x02",
                        ROUTINE,
                        b"\x50",
                    ]
                rt, events = runtime(replies)
                result = run_native_context(
                    fixture(module),
                    rt,
                    secret_info=secret_client() if module == SECURITY else None,
                )
                self.assertTrue(result["native_return"])
                self.assertTrue(result["prepared"])
                self.assertEqual(result["source_sha256"], HASHES[module])
                writes = [
                    e["data"][4:] for e in events if e["operation"] == "write_messages"
                ]
                self.assertEqual(writes[0], b"\x10\x02")
                seed_request = b"\x27\x01" + (
                    b"\x11" * 16 if module == SECURITY else b""
                )
                self.assertEqual(writes[1], seed_request)
                expected = (
                    b"\xbb" * 16
                    if module == SECURITY
                    else seed_key_six_byte(bytes(range(size)))
                    if module == BODY
                    else seed_key_four_round(
                        bytes(range(size)),
                        tuple(
                            bytes.fromhex(v) for v in ("1111", "2222", "3333", "4444")
                        ),
                    )
                )
                self.assertEqual(writes[2], b"\x27\x02" + expected)
                if module == DUAL:
                    full_writes = [
                        e["data"] for e in events if e["operation"] == "write_messages"
                    ]
                    self.assertEqual(full_writes[3][:4], bytes.fromhex("00000200"))
                    self.assertEqual(full_writes[4][:4], bytes.fromhex("00000200"))
                    self.assertEqual(full_writes[-1], bytes.fromhex("000002001002"))
                self.assertEqual(
                    sum(e["operation"] == "stop_filter" for e in events),
                    2 if module == DUAL else 1,
                )
                self.assertFalse(rt._resources)

    def test_real_typed_j2534_all_exports_and_cleanup(self):
        for module in MODULE_EXPORTS:
            with self.subTest(module=module):
                size = 16 if module == SECURITY else 6 if module == BODY else 4
                replies = [
                    PROBE,
                    b"\x67\x01" + bytes(range(size)),
                    b"\x67\x02",
                    ROUTINE,
                ]
                if module == DUAL:
                    replies = [
                        PROBE,
                        b"\x67\x01" + bytes(range(4)),
                        b"\x67\x02",
                        b"\x67\x01" + bytes(range(4)),
                        b"\x67\x02",
                        ROUTINE,
                        b"\x50",
                    ]
                reply_stream = iter(replies)
                calls, echo = [], []

                def provider(
                    event, remaining, calls=calls, echo=echo, reply_stream=reply_stream
                ):
                    calls.append(event)
                    name = event["operation"]
                    if name in (
                        "passthru_open",
                        "passthru_connect",
                        "passthru_start_filter",
                    ):
                        return PrimitiveResult(value=17)
                    if name == "passthru_write":
                        msg = event["messages"][0]
                        echo.append(NativeMessage(6, msg.data[:4], rx_status=9))
                        return PrimitiveResult(value=event["count"])
                    if name == "passthru_read":
                        if echo:
                            return PrimitiveResult(value=(echo.pop(0),))
                        sent = next(
                            c
                            for c in reversed(calls)
                            if c["operation"] == "passthru_write"
                        )["messages"][0].data
                        response = (int.from_bytes(sent[:4], "big") + 8).to_bytes(
                            4, "big"
                        )
                        return PrimitiveResult(
                            value=(NativeMessage(6, response + next(reply_stream)),)
                        )
                    return PrimitiveResult()

                device = J2534Device2026(
                    provider, clock=lambda: 0, background_workers=False
                )
                device.open()
                device.connect(6)

                def action(event, remaining, device=device):
                    if event["operation"] == "decrypt_secret_info":
                        return b"\xaa" * 16
                    if event["operation"] == "calculate_security_key":
                        return b"\xbb" * 16
                    return device.primitive(event, remaining)

                rt = NativeRuntime2026(
                    action, clock=lambda: 0, cleanup_action=device.cleanup_primitive
                )
                result = run_native_context(
                    fixture(module),
                    rt,
                    secret_info=secret_client() if module == SECURITY else None,
                )
                self.assertTrue(result["native_return"])
                self.assertFalse(device.filters)
                self.assertFalse(rt._resources)
                device.disconnect()
                device.close()

    def test_power_probe_literal_sid_with_real_j2534(self):
        cases = (
            ("single", 0x27, True, (b"\x7f\x27\x22",), True, None),
            ("single", 0x10, True, (b"\x7f\x10\x22",), False, 41),
            (
                "multi",
                0x27,
                False,
                (
                    b"\x7f\x27\x22",
                    PROBE,
                    b"\x67\x01\x00\x01\x02\x03",
                    b"\x67\x02",
                    ROUTINE,
                ),
                True,
                None,
            ),
            (
                "multi",
                0x27,
                True,
                (
                    b"\x7f\x27\x22",
                    PROBE,
                    b"\x67\x01\x00\x01\x02\x03",
                    b"\x67\x02",
                    ROUTINE,
                ),
                True,
                None,
            ),
            (
                "multi",
                0x10,
                False,
                (
                    b"\x7f\x10\x22",
                    PROBE,
                    b"\x67\x01\x00\x01\x02\x03",
                    b"\x67\x02",
                    ROUTINE,
                ),
                False,
                41,
            ),
            (
                "multi",
                0x10,
                True,
                (
                    b"\x7f\x10\x22",
                    PROBE,
                    b"\x67\x01\x00\x01\x02\x03",
                    b"\x67\x02",
                    ROUTINE,
                ),
                False,
                41,
            ),
        )
        for scope, sid, retry, replies, prepared, error_code in cases:
            with self.subTest(scope=scope, sid=hex(sid), retry=retry):
                addresses = "0100/0108" if scope == "single" else "0100/0108\n0200/0208"
                context = fixture(
                    POWER,
                    addresses=addresses,
                    retry=retry,
                    ig_off_retriable=False,
                )
                assert isinstance(context, P5PrepareContext2026)
                self.assertEqual(context.identity.sha256, HASHES[POWER])
                self.assertFalse(
                    context.binding.parameter.boolean("IGOffRetriableFlag")
                )
                reply_stream = iter(replies)
                calls, echo, released = [], [], []
                next_filter = iter((101, 202))

                def provider(
                    event,
                    remaining,
                    calls=calls,
                    echo=echo,
                    next_filter=next_filter,
                    released=released,
                    reply_stream=reply_stream,
                ):
                    calls.append(event)
                    operation = event["operation"]
                    if operation in ("passthru_open", "passthru_connect"):
                        return PrimitiveResult(value=17)
                    if operation == "passthru_start_filter":
                        return PrimitiveResult(value=next(next_filter))
                    if operation == "passthru_stop_filter":
                        released.append(event["identifier"])
                        return PrimitiveResult()
                    if operation == "passthru_write":
                        message = event["messages"][0]
                        echo.append(NativeMessage(6, message.data[:4], rx_status=9))
                        return PrimitiveResult(value=event["count"])
                    if operation == "passthru_read":
                        if echo:
                            return PrimitiveResult(value=(echo.pop(0),))
                        sent = next(
                            item
                            for item in reversed(calls)
                            if item["operation"] == "passthru_write"
                        )["messages"][0].data
                        response_address = (
                            int.from_bytes(sent[:4], "big") + 8
                        ).to_bytes(4, "big")
                        return PrimitiveResult(
                            value=(
                                NativeMessage(6, response_address + next(reply_stream)),
                            )
                        )
                    return PrimitiveResult()

                device = J2534Device2026(
                    provider, clock=lambda: 0, background_workers=False
                )
                device.open()
                device.connect(6)
                rt = NativeRuntime2026(
                    device.primitive,
                    clock=lambda: 0,
                    cleanup_action=device.cleanup_primitive,
                )
                notification = NotificationBool()
                try:
                    result = run_native_context(
                        context, rt, retry_notification=notification
                    )
                    self.assertFalse(bool(notification))
                    self.assertEqual(result["prepared"], prepared, result)
                    self.assertEqual(result["native_return"], prepared)
                    self.assertEqual(result["native_error_code"], error_code)
                    writes = [
                        event["messages"][0].data
                        for event in calls
                        if event["operation"] == "passthru_write"
                    ]
                    expected_probe_ids = ["00000100"]
                    if scope == "multi" and sid == 0x27:
                        expected_probe_ids.append("00000200")
                    self.assertEqual(
                        [
                            write[:4].hex()
                            for write in writes
                            if write[4:] == b"\x10\x02"
                        ],
                        expected_probe_ids,
                    )
                    if prepared and scope == "multi":
                        key = seed_key_four_round(
                            bytes.fromhex("00010203"), context.materials
                        )
                        key_and_routine = [
                            write
                            for write in writes
                            if write[4:].startswith(
                                (b"\x27\x01", b"\x27\x02", b"\x31\x01")
                            )
                        ]
                        self.assertEqual(
                            key_and_routine,
                            [
                                bytes.fromhex("000002002701"),
                                b"\x00\x00\x02\x00\x27\x02" + key,
                                bytes.fromhex("0000020031011003"),
                            ],
                        )
                        self.assertEqual(writes[-1], bytes.fromhex("0000020031011003"))
                    elif scope == "multi":
                        self.assertFalse(
                            any(write[4:] != b"\x10\x02" for write in writes)
                        )
                    stop_calls = [
                        event["identifier"]
                        for event in calls
                        if event["operation"] == "passthru_stop_filter"
                    ]
                    expected_filters = 1 if scope == "single" else 2
                    self.assertEqual(len(stop_calls), expected_filters)
                    self.assertEqual(sorted(released), sorted(stop_calls))
                    self.assertEqual(len(set(stop_calls)), expected_filters)
                    self.assertFalse(device.filters)
                    self.assertFalse(rt._resources)
                finally:
                    device.disconnect()
                    device.close()

    def test_private_actual_secret_authorization_when_available(self):
        root = Path(__file__).resolve().parents[1] / "runtime/no-car-21/recovered"
        if not all((root / name).exists() for name in ("SecretInfo.dll", "CUW.dll")):
            self.skipTest("Private exact native authorization corpus unavailable")
        client = SecretInfoClient.from_native_modules(
            (root / "SecretInfo.dll").read_bytes(), (root / "CUW.dll").read_bytes()
        )
        rt, _ = runtime([PROBE, b"\x67\x01" + bytes(16), b"\x67\x02", ROUTINE])
        self.assertTrue(
            run_native_context(fixture(SECURITY), rt, secret_info=client)[
                "native_return"
            ]
        )

    def test_private_concrete_crypto_typed_j2534_selected_input_composition(self):
        root = Path(__file__).resolve().parents[1] / "runtime/no-car-21/recovered"
        if not all((root / name).exists() for name in ("SecretInfo.dll", "CUW.dll")):
            self.skipTest("Private exact native crypto corpus unavailable")
        composer = NativeSecurityComposer2026.from_native_modules(
            (root / "SecretInfo.dll").read_bytes(), (root / "CUW.dll").read_bytes()
        )
        seed = bytes(range(16))
        cases = [
            ([PROBE, b"\x67\x01" + seed, b"\x67\x02", ROUTINE], None),
            ([PROBE, b"\x67\x01" + seed, b"\x7f\x27\x35"], 1002),
            ([PROBE, b"\x7f\x27\x22"], 16),
            ([PROBE, b"\x67\x01" + seed, b"\x67\x02", b"\x7f\x31\x22"], 25),
        ]
        for replies, expected_error in cases:
            with self.subTest(native_error=expected_error):
                calls, echo = [], []
                reply_stream = iter(replies)

                def provider(
                    event, remaining, calls=calls, echo=echo, reply_stream=reply_stream
                ):
                    calls.append(event)
                    op = event["operation"]
                    if op in (
                        "passthru_open",
                        "passthru_connect",
                        "passthru_start_filter",
                    ):
                        return PrimitiveResult(value=17)
                    if op == "passthru_write":
                        echo.append(
                            NativeMessage(6, event["messages"][0].data[:4], rx_status=9)
                        )
                        return PrimitiveResult(value=event["count"])
                    if op == "passthru_read":
                        if echo:
                            return PrimitiveResult(value=(echo.pop(0),))
                        return PrimitiveResult(
                            value=(
                                NativeMessage(
                                    6, bytes.fromhex("00000108") + next(reply_stream)
                                ),
                            )
                        )
                    return PrimitiveResult()

                device = J2534Device2026(
                    provider, clock=lambda: 0, background_workers=False
                )
                device.open()
                device.connect(6)

                rt = NativeRuntime2026(device.primitive, clock=lambda: 0)
                rt.bind_security_composer(composer)
                context = fixture(SECURITY)
                assert isinstance(context, P5PrepareContext2026)
                result = run_native_context(context, rt, secret_info=composer.client)
                self.assertEqual(result["native_error_code"], expected_error)
                self.assertEqual(result["native_return"], expected_error is None)
                if expected_error != 16:
                    sent = [
                        c["messages"][0].data
                        for c in calls
                        if c["operation"] == "passthru_write"
                    ]
                    self.assertEqual(
                        sent[2],
                        bytes.fromhex("000001002702")
                        + composer.derive(seed, context.service_auth_key),
                    )
                self.assertFalse(device.filters)
                self.assertEqual(rt.close(), [])
                device.disconnect()
                device.close()

    def test_extended_record_is_truncated_by_every_native_core(self):
        for module in MODULE_EXPORTS:
            with self.subTest(module=module):
                context = fixture(
                    module,
                    addresses="0100E9/0108E9\n0200E9/0208E9"
                    if module == DUAL
                    else "0100E9/0108E9",
                )
                rt, events = runtime([NativeTransportError(9)])
                run_native_context(
                    context,
                    rt,
                    secret_info=secret_client() if module == SECURITY else None,
                )
                first = next(e for e in events if e["operation"] == "write_messages")
                self.assertEqual(first["data"], bytes.fromhex("000001001002"))
                self.assertEqual(first["tx_flags"], 0)

    def test_multi_address_probe_selection_and_order(self):
        context = fixture(addresses="0100/0108\n0200/0208\n0300/0308")
        rt, events = runtime(
            [
                NativeTransportError(9),
                PROBE,
                PROBE,
                b"\x67\x01" + bytes(4),
                b"\x67\x02",
                b"\x67\x01" + bytes(4),
                b"\x67\x02",
                ROUTINE,
                ROUTINE,
            ]
        )
        result = run_native_context(context, rt)
        self.assertTrue(result["prepared"])
        writes = [e["data"] for e in events if e["operation"] == "write_messages"]
        self.assertEqual(
            [v[:4] for v in writes[:3]],
            [bytes.fromhex(v) for v in ("00000100", "00000200", "00000300")],
        )
        self.assertEqual(
            [v[:4] for v in writes[-2:]],
            [bytes.fromhex(v) for v in ("00000200", "00000300")],
        )
        self.assertEqual(sum(e["operation"] == "stop_filter" for e in events), 3)
        self.assertTrue(any(e.get("milliseconds") == 10 for e in events))

    def test_native_fault_fields_and_native_catch_all(self):
        cases = [
            (NativeJ2534Error2026(7), 1, 7),
            (NativePassThruError2026(49), 49, None),
            (NativeJ2534Exception2026(8, "authored", 1), 1, 8),
            (NativePassThruException2026(48, "authored", 1), 48, None),
        ]
        for error, native, driver in cases:
            rt, _ = runtime([error])
            result = run_native_context(fixture(), rt)
            self.assertEqual(
                (result["native_error_code"], result["driver_error_code"]),
                (native, driver),
            )
            self.assertFalse(result["native_return"])
        rt, _ = runtime([PROBE, NativeException2026("authored")])
        with self.assertRaises(NativeException2026):
            run_native_context(fixture(), rt)
        rt, _ = runtime([NativeException2026("authored")])
        result = run_native_context(fixture(), rt)
        self.assertFalse(result["native_return"])
        self.assertEqual(result["native_error_code"], 9999)
        rt, _ = runtime([NativeException2026("authored")])
        with self.assertRaises(NativeException2026):
            run_native_context(fixture(DUAL), rt)

    def test_pending_response_does_not_repeat_send(self):
        rt, events = runtime(
            [b"\x7f\x10\x78", PROBE, b"\x67\x01" + bytes(4), b"\x67\x02", ROUTINE]
        )
        self.assertTrue(run_native_context(fixture(), rt)["native_return"])
        writes = [e["data"] for e in events if e["operation"] == "write_messages"]
        self.assertEqual(sum(v[4:] == b"\x10\x02" for v in writes), 1)
        self.assertEqual(
            sum(e["operation"] == "lock" for e in events),
            sum(e["operation"] == "unlock" for e in events),
        )

    def test_native_receive_cancel_flag_is_false_in_these_exports(self):
        def forbidden():
            raise AssertionError(
                "Native receive cancellation was not requested by the source"
            )

        rt, _ = runtime([PROBE, b"\x67\x01" + bytes(4), b"\x67\x02", ROUTINE])
        rt.native_cancelled = forbidden
        self.assertTrue(run_native_context(fixture(), rt)["native_return"])

    def test_cleanup_failure_is_host_failure_and_retryable(self):
        attempts = []

        def fail(event):
            if event["operation"] == "stop_filter" and not attempts:
                attempts.append(1)
                raise OSError("authored release failure")

        rt, _ = runtime([PROBE, b"\x67\x01" + bytes(4), b"\x67\x02", ROUTINE], fail)
        with self.assertRaises(OSError):
            run_native_context(fixture(), rt)
        self.assertEqual(len(rt._resources), 1)
        self.assertEqual(rt.close(), [])

    def test_dual_native_retry_branches_and_p4_mapping(self):
        # Both legacy probes fail in an already-retried controller: no mask/mode.
        rt, events = runtime([NativeTransportError(9), NativeTransportError(16)])
        result = run_native_context(fixture(DUAL, retry=True), rt)
        self.assertTrue(result["native_return"])
        self.assertEqual(
            len([e for e in events if e["operation"] == "write_messages"]), 2
        )
        # Without retry state, P4 seed timeout/negative maps22/23.
        for fault, expected in ((NativeTransportError(9), 22), (b"\x7f\x27\x22", 23)):
            rt, _ = runtime([PROBE, b"\x67\x01" + bytes(4), b"\x67\x02", fault])
            result = run_native_context(fixture(DUAL), rt)
            self.assertEqual(result["native_error_code"], expected)
            self.assertFalse(result["native_return"])

    def test_dual_seed_and_key_negative_use_distinct_native_buffers(self):
        prefix = [PROBE, b"\x67\x01" + bytes(4), b"\x67\x02"]
        rt, _ = runtime(prefix + [b"\x7f\x27\x22"])
        self.assertEqual(run_native_context(fixture(DUAL), rt)["native_error_code"], 23)
        rt, _ = runtime(prefix + [b"\x67\x01" + bytes(4), b"\x7f\x27\x22"])
        self.assertEqual(run_native_context(fixture(DUAL), rt)["native_error_code"], 17)
        # Retry964 skips only the native22/23 branch; key NRC17 still fails.
        rt, _ = runtime(prefix + [b"\x67\x01" + bytes(4), b"\x7f\x27\x22"])
        self.assertFalse(
            run_native_context(fixture(DUAL, retry=True), rt)["native_return"]
        )

    def test_body_probe_negative_sid_difference(self):
        for reply, expected in ((b"\x7f\x10\x22", 41), (b"\x7f\x27\x22", 41)):
            rt, _ = runtime([reply])
            result = run_native_context(fixture(BODY), rt)
            self.assertEqual(result["native_error_code"], expected)
        # The native BODY SID27 catch marks only that address nonresponsive.
        rt, _ = runtime([b"\x7f\x27\x22"])
        self.assertTrue(
            run_native_context(fixture(BODY, retry=True), rt)["native_return"]
        )
        rt, _ = runtime([b"\x7f\x10\x22"])
        self.assertFalse(
            run_native_context(fixture(BODY, retry=True), rt)["native_return"]
        )

    def test_each_export_per_primitive_host_cancel_and_native_fault(self):
        for module in MODULE_EXPORTS:
            size = 16 if module == SECURITY else 6 if module == BODY else 4
            replies = [PROBE, b"\x67\x01" + bytes(size), b"\x67\x02", ROUTINE]
            if module == DUAL:
                replies = [
                    PROBE,
                    b"\x67\x01" + bytes(4),
                    b"\x67\x02",
                    b"\x67\x01" + bytes(4),
                    b"\x67\x02",
                    ROUTINE,
                    b"\x50",
                ]
            rt, events = runtime(replies)
            run_native_context(
                fixture(module),
                rt,
                secret_info=secret_client() if module == SECURITY else None,
            )
            for index, event in enumerate(events):
                if event["operation"] == "stop_filter" or event.get("parameters") == (
                    (0x1E, 0),
                ):
                    continue
                with self.subTest(
                    module=module, index=index, operation=event["operation"]
                ):
                    for failure in (
                        OSError("authored host fault"),
                        NativePassThruError2026(71),
                    ):
                        calls = [0]

                        def fail(_event, calls=calls, index=index, failure=failure):
                            current = calls[0]
                            calls[0] += 1
                            if current == index:
                                raise failure

                        rt, _ = runtime(replies, fail)
                        if type(failure) is OSError:
                            with self.assertRaises(OSError):
                                run_native_context(
                                    fixture(module),
                                    rt,
                                    secret_info=secret_client()
                                    if module == SECURITY
                                    else None,
                                )
                        else:
                            result = run_native_context(
                                fixture(module),
                                rt,
                                secret_info=secret_client()
                                if module == SECURITY
                                else None,
                            )
                            self.assertFalse(result["native_return"])
                        self.assertEqual(rt.close(), [])
                    rt, events_cancel = runtime(replies)
                    rt.cancelled = lambda events_cancel=events_cancel, index=index: (
                        len(events_cancel) > index
                    )
                    with self.assertRaises(InterruptedError):
                        run_native_context(
                            fixture(module),
                            rt,
                            secret_info=secret_client() if module == SECURITY else None,
                        )
                    self.assertEqual(rt.close(), [])

    def test_native_stop_filter_fault_preserves_bool_and_host_failure(self):
        for module in MODULE_EXPORTS:
            for native_failure in (
                NativeJ2534Error2026(7),
                NativePassThruError2026(71),
                NativeException2026("authored"),
            ):
                with self.subTest(module=module, fault=type(native_failure).__name__):
                    size = 16 if module == SECURITY else 6 if module == BODY else 4
                    replies = [PROBE, b"\x67\x01" + bytes(size), b"\x67\x02", ROUTINE]
                    if module == DUAL:
                        replies = [
                            PROBE,
                            b"\x67\x01" + bytes(4),
                            b"\x67\x02",
                            b"\x67\x01" + bytes(4),
                            b"\x67\x02",
                            ROUTINE,
                            b"\x50",
                        ]
                    attempts = []

                    def fail(event, attempts=attempts, native_failure=native_failure):
                        if event["operation"] == "stop_filter" and not attempts:
                            attempts.append(1)
                            raise native_failure

                    rt, events = runtime(replies, fail)
                    result = run_native_context(
                        fixture(module),
                        rt,
                        secret_info=secret_client() if module == SECURITY else None,
                    )
                    self.assertTrue(result["native_return"])
                    self.assertEqual(result["host_result"], "cleanup_failed")
                    self.assertFalse(result["host_succeeded"])
                    self.assertIsNone(result["native_error_code"])
                    self.assertEqual(len(rt._resources), 1)
                    self.assertEqual(
                        sum(e["operation"] == "stop_filter" for e in events),
                        2 if module == DUAL else 1,
                    )
                    self.assertEqual(rt.close(), [])

        # A native business failure stays false even when cleanup also fails.
        def stop_failure(event):
            if event["operation"] == "stop_filter":
                raise NativePassThruError2026(71)

        rt, _ = runtime([b"\x7f\x10\x22"], stop_failure)
        result = run_native_context(fixture(), rt)
        self.assertFalse(result["native_return"])
        self.assertEqual(result["native_error_code"], 41)
        self.assertEqual(result["host_result"], "cleanup_failed")

    def test_solar_native_cleanup_failure_preserves_delayed_status_assignment(self):
        def fail(event):
            if event["operation"] == "stop_filter":
                raise NativePassThruError2026(71)

        rt, _ = runtime(
            [PROBE, b"\x67\x01" + bytes(4), b"\x67\x02", b"\x7f\x31\x22"], fail
        )
        note = NotificationBool()
        result = run_native_context(fixture(SOLAR), rt, retry_notification=note)
        self.assertTrue(bool(note))
        self.assertFalse(result["native_return"])
        self.assertEqual(result["native_error_code"], 25)
        self.assertEqual(result["result_status_update"], 2)
        self.assertTrue(result["native_retry_flag_964_update"])
        self.assertEqual(result["host_result"], "cleanup_failed")

    def test_body_micon_block_size_order_empty_addresses_and_native_restore_fault(self):
        context = fixture(BODY)
        assert isinstance(context, P5PrepareContext2026)
        rt, events = runtime([PROBE, b"\x67\x01" + bytes(6), b"\x67\x02", ROUTINE])
        self.assertTrue(run_native_context(context, rt)["native_return"])
        self.assertEqual(
            events[0],
            {"operation": "control_io", "ioctl": 2, "parameters": ((0x1E, 1),)},
        )
        self.assertEqual(events[-2]["parameters"], ((0x1E, 0),))
        self.assertEqual(events[-1]["operation"], "stop_filter")
        rt, events = runtime([])
        result = run_native_context(replace(context, addresses=()), rt)
        self.assertEqual(result["native_error_code"], 41)
        self.assertEqual(
            [e["parameters"] for e in events], [((0x1E, 1),), ((0x1E, 0),)]
        )

        def fail_restore(event):
            if event.get("parameters") == ((0x1E, 0),):
                raise NativePassThruError2026(71)

        rt, events = runtime(
            [PROBE, b"\x67\x01" + bytes(6), b"\x67\x02", ROUTINE], fail_restore
        )
        result = run_native_context(context, rt)
        self.assertTrue(result["native_return"])
        self.assertEqual(result["host_result"], "cleanup_failed")
        self.assertEqual(
            rt._resources,
            [{"operation": "control_io", "ioctl": 2, "parameters": ((0x1E, 0),)}],
        )
        self.assertEqual(events[-1]["operation"], "stop_filter")

    def test_approved_cpu_state_override_selects_cpu_catalog_and_global_module(self):
        inputs = fixture(return_inputs=True)
        assert isinstance(inputs, tuple)
        context, container, binding = inputs
        state = native2026_with_cpu_type(
            native2026_metadata(container, cpu_index=1), 0, "C"
        )
        state = native2026_with_cpu_type(state, 1, "D")
        catalogs = dict(binding.catalog_sources)
        catalogs["8P4C.ini"] = catalogs["8P4A.ini"].replace(b"8P4A", b"8P4C")
        catalogs["8P4D.ini"] = catalogs["8P4A.ini"].replace(b"8P4A", b"8P4D")
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
        self.assertIsNotNone(bound.binding.module_binding)
        assert bound.binding.module_binding is not None
        self.assertEqual(bound.binding.module_binding.cpu_type, "C")
        self.assertEqual(bound.binding.metadata.cpu_index, 1)
        self.assertEqual(bound.binding.metadata.cpu_type_overrides[1], "D")
        rt, _ = runtime([PROBE, b"\x67\x01" + bytes(4), b"\x67\x02", ROUTINE])
        self.assertTrue(run_native_context(bound, rt)["native_return"])

    def test_probe_skip_and_no_responsive_error(self):
        for retry in (False, True):
            rt, _ = runtime([NativeTransportError(9)])
            result = run_native_context(fixture(retry=retry), rt)
            self.assertEqual(result["native_return"], retry)
            self.assertEqual(result["native_error_code"], None if retry else 41)

    def test_native_return_distinct_from_retry_success(self):
        rt, _ = runtime([b"\x7f\x10\x22"])
        result = run_native_context(
            fixture(), rt, retry_notification=NotificationBool(True)
        )
        self.assertTrue(result["native_return"])
        self.assertFalse(result["prepared"])
        self.assertEqual(result["native_error_code"], 41)

    def test_solar_notification_before_routine_and_fault_status(self):
        notices = []
        note = NotificationBool(
            False, notices, lambda _target, value: notices.append(value)
        )
        rt, _ = runtime(
            [PROBE, b"\x67\x01\x01\x02\x03\x04", b"\x67\x02", b"\x7f\x31\x22"]
        )
        result = run_native_context(fixture(SOLAR), rt, retry_notification=note)
        self.assertEqual(notices, [True])
        self.assertFalse(result["native_return"])
        self.assertEqual(result["result_status_update"], 2)
        self.assertTrue(result["native_retry_flag_964_update"])

    def test_security_nrc35_mapping(self):
        rt, _ = runtime([PROBE, b"\x67\x01" + b"s" * 16, b"\x7f\x27\x35"])
        result = run_native_context(fixture(SECURITY), rt, secret_info=secret_client())
        self.assertEqual(result["native_error_code"], 1002)

    def test_host_fault_and_cancel_release(self):
        for exception in (
            ValueError("primitive"),
            InterruptedError("cancel"),
            TimeoutError("deadline"),
        ):
            rt, events = runtime([exception])
            with self.assertRaises(type(exception)):
                run_native_context(fixture(), rt)
            self.assertTrue(any(e["operation"] == "stop_filter" for e in events))

    def test_source_mismatch_and_manual_override(self):
        context = fixture()
        assert isinstance(context, P5PrepareContext2026)
        with self.assertRaises(ValueError):
            replace(context, identity=replace(context.identity, cuw_build="18"))
        with self.assertRaises(TypeError):
            run_native_context(context, runtime([])[0], retry_notification=True)

    def test_every_primitive_fault_preserves_cleanup(self):
        rt, events = runtime([PROBE, b"\x67\x01\x01\x02\x03\x04", b"\x67\x02", ROUTINE])
        run_native_context(fixture(), rt)
        operations = {e["operation"] for e in events} - {"stop_filter"}
        for operation in operations:
            with self.subTest(operation=operation):

                def fail(event, operation=operation):
                    if event["operation"] == operation:
                        raise ValueError("fault")

                rt, events = runtime(
                    [PROBE, b"\x67\x01\x01\x02\x03\x04", b"\x67\x02", ROUTINE], fail
                )
                with self.assertRaises(ValueError):
                    run_native_context(fixture(), rt)
                if operation != "start_flow_control_filter":
                    self.assertTrue(
                        any(e["operation"] == "stop_filter" for e in events)
                    )


if __name__ == "__main__":
    unittest.main()
