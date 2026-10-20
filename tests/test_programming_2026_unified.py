"""Authored literal vectors for exact2026 Unified/Ethernet primitives."""

import unittest
from typing import cast

from scripts.programming_2026_common import (
    NativePassThruException2026,
    NativeRuntime2026,
)
from scripts.programming_2026_unified import (
    ADS_ADDRESS,
    DEVICE_ADDRESS,
    ESW1_ADDRESS,
    FUNCTIONAL_ADDRESS,
    EthernetUtils2026,
    convert_specific_char,
    ecu_information_dids,
    parse_software_ids,
)


class Primitive:
    def __init__(self, reads=()):
        self.events = []
        self.reads = iter(reads)
        self.timeout = 3000
        self.fail: str | None = None

    def __call__(self, event, remaining):
        self.events.append(event)
        if self.fail == event["operation"]:
            raise OSError("authored primitive failure")
        operation = event["operation"]
        if operation == "get_timeout":
            return self.timeout
        if operation == "set_timeout":
            self.timeout = event["milliseconds"]
        if operation in ("queue_messages", "write_tcp"):
            return 1
        if operation in ("read_tcp", "read_messages"):
            value = next(self.reads)
            if isinstance(value, Exception):
                raise value
            return value
        if operation == "control_io":
            return 1


class EthernetTests(unittest.TestCase):
    def test_four_native_static_address_exports(self):
        self.assertEqual(
            (ADS_ADDRESS, ESW1_ADDRESS, FUNCTIONAL_ADDRESS, DEVICE_ADDRESS),
            (b"\x01\0", b"\x01\x03", b"\xe4\0", b"\x0e\x80"),
        )

    def test_utility_copy_and_move_assign_share_runtime_without_consuming_source(self):
        import copy

        first, second = NativeRuntime2026(Primitive()), NativeRuntime2026(Primitive())
        source = EthernetUtils2026(first, seconds_clock=lambda: 123)
        target = EthernetUtils2026(second)
        copied = copy.copy(source)
        self.assertIs(copied.runtime, first)
        self.assertIs(target.assign(source, move=True), target)
        self.assertIs(target.runtime, first)
        self.assertIs(source.runtime, first)
        self.assertEqual(target._seconds(), 123)
        self.assertEqual(first.close(), [])
        self.assertEqual(second.close(), [])

    def test_cid_slots_and_extended_unified_header(self):
        for ethernet, header in (
            (True, bytes.fromhex("01000E8062F18102")),
            (False, bytes.fromhex("000007E862F18102")),
            (False, bytes.fromhex("000007E8F162F18102")),
        ):
            data = header + b"CID\0ignored".ljust(16, b" ") + b"\0".ljust(16, b" ")
            self.assertEqual(parse_software_ids(data, ethernet=ethernet), (b"CID",))
        for data, line in ((b"", 0x255), (b"\0" * 24, 0x25D)):
            with self.assertRaises(NativePassThruException2026) as caught:
                parse_software_ids(data, ethernet=True)
            self.assertEqual((caught.exception.error, caught.exception.line), (3, line))

    def test_su_byte_contract_and_information_order(self):
        self.assertEqual(
            convert_specific_char(b'a\0"\\/\x1f\x7f z', 1, 7),
            b"a\0______z".replace(b"______z", b"_____ z"),
        )
        self.assertEqual(
            ecu_information_dids(bytes(8) + b"\x18\0\x18"), (1, 0x11, 0x21, 0x31)
        )
        with self.assertRaises(ValueError):
            convert_specific_char(b"a", 1, 1)

    def test_literal_frame_address_filter_pending_and_cleanup(self):
        target = b"\x01\x00"
        good = target + DEVICE_ADDRESS + b"\x62\xf1\x81\x01" + b"A" * 16
        action = Primitive(
            (
                b"",
                b"\x01\0\x0e",
                b"\xff\xff" + DEVICE_ADDRESS,
                target + DEVICE_ADDRESS + b"\x7f\x22\x78",
                good,
            )
        )
        runtime = NativeRuntime2026(action, native_cancelled=lambda: False)
        self.assertEqual(
            EthernetUtils2026(runtime).send_request(
                target, b"\x22\xf1\x81", b"\x62\xf1\x81", minimum=8, error=3
            ),
            good,
        )
        write = next(e for e in action.events if e["operation"] == "write_tcp")
        self.assertEqual(write["data"], bytes.fromhex("02FD8001000000070E80010022F181"))
        self.assertEqual(action.timeout, 3000)
        self.assertEqual(runtime.close(), [])
        self.assertEqual(
            [e["operation"] for e in action.events].count("lock"),
            [e["operation"] for e in action.events].count("unlock"),
        )

    def test_errors_and_provider_fault_restore_timeout_and_lock(self):
        for data, line in (
            (b"\x01\0\x0e\x80", 0x4F6),
            (b"\x01\0\x0e\x80\x7f\x22\x13", 0x4FE),
        ):
            action = Primitive((data,))
            runtime = NativeRuntime2026(action, native_cancelled=lambda: False)
            with self.assertRaises(NativePassThruException2026) as caught:
                EthernetUtils2026(runtime).send_request(
                    b"\x01\0", b"\x22", b"\x62", minimum=5, error=77
                )
            self.assertEqual(
                (caught.exception.error, caught.exception.line), (77, line)
            )
            self.assertEqual(action.timeout, 3000)
            self.assertEqual(runtime.close(), [])

        action = Primitive()
        action.fail = "write_tcp"
        runtime = NativeRuntime2026(action, native_cancelled=lambda: False)
        with self.assertRaises(OSError):
            EthernetUtils2026(runtime).send_request(
                b"\x01\0", b"\x22", None, minimum=4, error=3
            )
        self.assertEqual(action.timeout, 3000)
        self.assertEqual(runtime.close(), [])

    def test_host_transport_fault_survives_timeout_restoration_fault(self):
        for method, failed_operation in (
            ("link_up", "control_io"),
            ("request_vehicle_identification", "queue_messages"),
            ("send_request", "write_tcp"),
        ):
            with self.subTest(method=method):
                original = OSError("authored transport failure")

                def action(
                    event,
                    remaining,
                    failed_operation=failed_operation,
                    original=original,
                ):
                    operation = event["operation"]
                    if operation == "get_timeout":
                        return 3000
                    if operation == failed_operation:
                        raise original
                    if operation == "set_timeout" and event["milliseconds"] == 3000:
                        raise ValueError("authored restoration failure")

                runtime = NativeRuntime2026(action)
                client = EthernetUtils2026(runtime)
                with self.assertRaises(OSError) as caught:
                    if method == "send_request":
                        client.send_request(
                            b"\x01\0", b"\x22", None, minimum=4, error=3
                        )
                    else:
                        getattr(client, method)()
                self.assertIs(caught.exception, original)
                self.assertEqual(runtime.close(), [])

    def test_pending_expiry_sends_one_byte_tester_present(self):
        action = Primitive((b"\x01\0\x0e\x80\x7f\x22\x78",))
        runtime = NativeRuntime2026(action, native_cancelled=lambda: False)
        with self.assertRaises(NativePassThruException2026) as caught:
            EthernetUtils2026(runtime).send_request(
                b"\x01\0", b"\x22", None, minimum=4, error=3, pending_seconds=0
            )
        self.assertEqual(caught.exception.line, 0x4E4)
        queued = next(e for e in action.events if e["operation"] == "queue_messages")
        self.assertEqual(queued["data"], bytes.fromhex("02FD8001000000050E8001003E"))
        self.assertEqual(runtime.close(), [])

    def test_base_passthru_enum9_is_not_a_driver_timeout(self):
        from scripts.j2534_2026 import NativeJ2534Error2026, NativePassThruError2026

        response = bytes.fromhex("01000E806201")
        for failure in (NativePassThruError2026(9), NativeJ2534Error2026(9)):
            with self.subTest(failure=type(failure).__name__):
                primitive = Primitive((response,))
                reads = []

                def action(
                    event, remaining, failure=failure, reads=reads, primitive=primitive
                ):
                    if event["operation"] == "read_tcp":
                        reads.append(True)
                        if len(reads) == 1:
                            raise failure
                    return primitive(event, remaining)

                runtime = NativeRuntime2026(action)
                client = EthernetUtils2026(runtime)
                if isinstance(failure, NativeJ2534Error2026):
                    self.assertEqual(
                        client.send_request(
                            b"\x01\0", b"\x22\x01", b"\x62\x01", minimum=6, error=3
                        ),
                        response,
                    )
                    self.assertEqual(len(reads), 2)
                else:
                    with self.assertRaises(NativePassThruError2026) as caught:
                        client.send_request(
                            b"\x01\0", b"\x22\x01", b"\x62\x01", minimum=6, error=3
                        )
                    self.assertIs(caught.exception, failure)
                    self.assertEqual(len(reads), 1)
                self.assertEqual(runtime.close(), [])

    def test_logical_cleanup_attempts_all_channels_and_preserves_host_fault(self):
        for during_host_fault in (False, True):
            calls = []
            failure = OSError("authored logical release failure")

            def action(event, remaining, calls=calls, failure=failure):
                calls.append(event)
                if len(calls) == 1:
                    raise failure

            runtime = NativeRuntime2026(action)
            for protocol in (0x8203, 0x8205, 0x8206):
                runtime.own("logical_disconnect", protocol=protocol)
            client = EthernetUtils2026(runtime)
            original = ValueError("authored provider host fault")
            if during_host_fault:
                try:
                    raise original
                except ValueError:
                    with self.assertRaises(ValueError) as caught:
                        client.finish_diag_comm()
                    self.assertIs(caught.exception, original)
            else:
                with self.assertRaises(OSError) as caught:
                    client.finish_diag_comm()
                self.assertIs(caught.exception, failure)
            self.assertEqual(
                [event["protocol"] for event in calls], [0x8206, 0x8205, 0x8203]
            )
            self.assertEqual(runtime.close(), [])

    def test_discovery_prepare_and_full_reverse_teardown(self):
        action = Primitive((b"\xc0\xa8\x01\x02more", bytes(4) + b"\x10" + bytes(4)))
        runtime = NativeRuntime2026(action, native_cancelled=lambda: False)
        client = EthernetUtils2026(runtime)
        client.prepare_diag_comm()
        self.assertEqual(client.finish_diag_comm(), ())
        self.assertEqual(
            [
                e["protocol"]
                for e in action.events
                if e["operation"] == "logical_disconnect"
            ],
            [0x8206, 0x8205, 0x8203],
        )
        discovery = next(e for e in action.events if e["operation"] == "queue_messages")
        self.assertEqual(
            discovery["data"], bytes.fromhex("FFFFFFFF3458FF00000100000000")
        )
        self.assertEqual(runtime.close(), [])

    def test_cancellation_after_channel_acquisition_rolls_back(self):
        action = Primitive()
        cancel = [False]

        def provider(event, remaining):
            result = action(event, remaining)
            if event["operation"] == "logical_connect":
                cancel[0] = True
            return result

        runtime = NativeRuntime2026(provider, cancelled=lambda: cancel[0])
        with self.assertRaises(InterruptedError):
            EthernetUtils2026(runtime).prepare_diag_comm()
        self.assertEqual(
            [
                e["protocol"]
                for e in action.events
                if e["operation"] == "logical_disconnect"
            ],
            [0x8203],
        )
        self.assertEqual(runtime.close(), [])

    def test_routing_failure_cleans_every_owned_channel(self):
        action = Primitive((b"1234", b"bad"))
        runtime = NativeRuntime2026(action, native_cancelled=lambda: False)
        with self.assertRaises(NativePassThruException2026) as caught:
            EthernetUtils2026(runtime).prepare_diag_comm()
        self.assertEqual((caught.exception.error, caught.exception.line), (0x5D, 0x205))
        self.assertEqual(
            [
                e["protocol"]
                for e in action.events
                if e["operation"] == "logical_disconnect"
            ],
            [0x8206, 0x8205, 0x8203],
        )
        self.assertEqual(runtime.close(), [])


class ImportedContextTests(unittest.TestCase):
    def test_non_ascii_native_cid_keeps_exact_bytes_for_report(self):
        from scripts.programming_2026_unified import execute_context
        from scripts.programming_replay import _report

        raw = b"\xff "
        response = bytes.fromhex("01000E8062F18101") + raw.ljust(16, b"\0")
        primitive = Primitive((b"1234", bytes(4) + b"\x10" + bytes(4), response))
        runtime = NativeRuntime2026(primitive, native_cancelled=lambda: False)
        result = execute_context(self.context(), runtime)
        self.assertEqual(result["identifiers"], [raw])
        report = _report({"state": "read_completed", **result})
        self.assertEqual(report["identifier_bytes_hex"], ["ff20"])
        self.assertEqual(runtime.close(), [])

    def test_host_cid_fault_does_not_become_information_success(self):
        from scripts.programming_2026_unified import (
            bind_native_context,
            execute_context,
        )

        original = self.context()
        context = bind_native_context(
            original.metadata.source_container,
            1,
            original.observed_cids,
            original.parameter,
            original.identity,
            {},
            {"native_cid_flag_9c4": 1},
        )
        primitive = Primitive((b"1234", bytes(4) + b"\x10" + bytes(4)))
        fault = ValueError("authored provider host failure")

        def action(event, remaining):
            if event["operation"] == "write_tcp":
                raise fault
            return primitive(event, remaining)

        runtime = NativeRuntime2026(action, native_cancelled=lambda: False)
        with self.assertRaises(ValueError) as caught:
            execute_context(context, runtime)
        self.assertIs(caught.exception, fault)
        self.assertEqual(runtime.close(), [])

    def test_binding_rejects_replaced_context_and_parameter_rows_before_io(self):
        from dataclasses import replace

        from scripts.programming_2026_unified import (
            bind_native_context,
            execute_context,
        )

        context = self.context(False)
        provider = Primitive()
        runtime = NativeRuntime2026(provider)
        with self.assertRaises(ValueError):
            execute_context(replace(context, addresses=()), runtime)
        bad_values = dict(context.parameter.values)
        bad_values["CanIDForGetCID"] = ("0300/0308",)
        with self.assertRaises(ValueError):
            bind_native_context(
                context.metadata.source_container,
                1,
                context.observed_cids,
                replace(context.parameter, values=bad_values),
                context.identity,
                {},
                {},
            )
        self.assertEqual(provider.events, [])

    def test_binding_preserves_authenticated_runtime_cpu_type(self):
        from scripts.calibration_2026 import native2026_with_cpu_type
        from scripts.demo_calibration import table
        from scripts.programming_2026_common import bind_native_parameter2026
        from scripts.programming_2026_unified import bind_native_context

        original = self.context(False)
        metadata = native2026_with_cpu_type(original.metadata, 0, "M2")
        values = {name: value[0] for name, value in original.parameter.values.items()}
        key = "1P5-UnifiedM2"
        values["ParamFileKeySystemProtocolMicon"] = key
        selection = bind_native_parameter2026(
            metadata.source_container,
            {key + ".ini": table(tuple(values), [tuple(values.values())])},
            "get_cid",
            encoded=False,
            metadata_state=metadata,
        )
        context = bind_native_context(
            metadata.source_container,
            1,
            original.observed_cids,
            selection,
            original.identity,
            {},
            {},
        )
        self.assertEqual(context.metadata.cpu_type_overrides, {0: "M2"})

    @staticmethod
    def context(ethernet=True, stage="get_cid", charge_flow=None):
        from scripts.calibration_2026 import parse_cuw_2026
        from scripts.demo_calibration import table
        from scripts.native_modules import identify_native_module
        from scripts.programming_2026_common import bind_native_parameter2026
        from scripts.programming_2026_unified import bind_native_context
        from tests.test_calibration_2026 import cuw

        module = (
            "TCUWEthernetCIDGetter.dll" if ethernet else "TCUWCanUnifiedCIDGetter.dll"
        )
        digest = (
            "ce65b540d4c6100df9c4245461d806a21afff3c0ec55f0dbb524446ad31cd89c"
            if ethernet
            else "3a715d74227c7e74b9cf04f1cc1662325d69989cec0bb6d0abfa976aebeed767"
        )
        text = (
            "[Format]\nVersion=105\n[Vehicle]\nNumberOfNode=1\nKindOfECU=1\nContactType="
            + ("Ethernet" if ethernet else "P5-Unified")
            + "\n[Node01]\nNumberOfCalibration=1\nRequiredSpecReproVer=02\nDiagID=0100\nLogicalAddress=0100\nWakeUpTimeAfterReset=02\n[CPU11]\nCPUImageName=authored.vbf\nLocationID=0108010000000720\n"
        )
        if charge_flow is not None:
            text = text.replace(
                "[Node01]",
                "[Node01]\nChargeLocalBusEcuReprogrammingFlow="
                + charge_flow
                + "\nChargeLocalBusPowerOnControllingEcuDiagID=0750\nChargeLocalBusEcuStartTimeAfterPowerOn=01",
            )
        container = parse_cuw_2026(cuw(text, (bytes(64),)))
        key = "1" + ("Ethernet" if ethernet else "P5-Unified")
        values = {
            "ParamFileKeySystemProtocolMicon": key,
            "DLLFileNameForGetCID": module,
            "GetCANIDFunctionNameForGetCID": "GetCanIDsFromParamForGetCID",
            "CanIDForGetCID": "0100/0108",
            "ReceiveTimeoutBeforeGetCID": "3000",
        }
        selection = bind_native_parameter2026(
            container,
            {key + ".ini": table(tuple(values), [tuple(values.values())])},
            stage,
            encoded=False,
        )
        identity = identify_native_module(digest, module)
        return bind_native_context(
            container, 1, ("AUTHORED",), selection, identity, {}, {}
        )

    def test_actual_import_parameter_address_to_ethernet_getter(self):
        from scripts.programming_2026_unified import execute_context

        context = self.context()
        response = bytes.fromhex("01000E8062F18101") + b"ACTUAL-CID".ljust(16, b"\0")
        action = Primitive((b"1234", bytes(4) + b"\x10" + bytes(4), response))
        runtime = NativeRuntime2026(action, native_cancelled=lambda: False)
        result = execute_context(context, runtime)
        self.assertEqual(result["cids"], ["ACTUAL-CID"])
        self.assertEqual(result["nodes"][0]["address"], "0100")
        self.assertEqual(
            next(e for e in action.events if e["operation"] == "wait")["milliseconds"],
            100,
        )
        self.assertEqual(action.events[-1]["operation"], "disconnect")
        self.assertEqual(runtime.close(), [])

    def test_imported_charge_bus_native_start_getter_end(self):
        from scripts.programming_2026_unified import execute_context

        for flow in ("01", "02"):
            with self.subTest(flow=flow):
                events, reads = [], []

                def action(event, remaining, events=events, reads=reads):
                    events.append(event)
                    op = event["operation"]
                    if op == "get_timeout":
                        return 3000
                    if op == "start_flow_control_filter":
                        return len(events)
                    if op == "write_messages":
                        data = event["data"]
                        request, payload = data[:4], data[4:]
                        response = (
                            b"\x18\xda\xe0\x49"
                            if request[:2] == b"\x18\xda"
                            else request[:3] + bytes((request[3] + 8,))
                        )
                        if payload[:1] == b"\x10":
                            body = b"\x50" + payload[1:] + bytes(4)
                        elif payload[:1] == b"\x31":
                            body = b"\x71" + payload[1:]
                        elif payload == b"\x22\xf1\x81":
                            body = b"\x62\xf1\x81\x01" + b"CHARGED-CID".ljust(16, b"\0")
                        else:
                            raise AssertionError("Unexpected authored CAN request")
                        reads.append(response + body)
                        return 1
                    if op == "read_specified_can_message":
                        return reads.pop(0)

                runtime = NativeRuntime2026(action, native_cancelled=lambda: False)
                result = execute_context(self.context(False, charge_flow=flow), runtime)
                self.assertEqual(result["cids"], ["CHARGED-CID"])
                writes = [
                    e["data"][4:] for e in events if e["operation"] == "write_messages"
                ]
                self.assertEqual(
                    writes,
                    [
                        b"\x10\x03",
                        b"\x31\x01\x11\x7e",
                        b"\x22\xf1\x81",
                        b"\x31\x02\x11\x7e",
                        b"\x10\x01",
                    ],
                )
                self.assertEqual(runtime.close(), [])

    def test_charge_cancellation_keeps_protocol_restoration_unconfirmed(self):
        from scripts.programming_2026_unified import (
            NativeRestorationCancelled,
            execute_context,
        )

        events, reads = [], []
        cancelled = [False]

        def action(event, remaining):
            events.append(event)
            op = event["operation"]
            if op == "get_timeout":
                return 3000
            if op == "start_flow_control_filter":
                return len(events)
            if op == "write_messages":
                payload = event["data"][4:]
                if payload == b"\x22\xf1\x81":
                    cancelled[0] = True
                else:
                    reply = (
                        b"\x50" + payload[1:] + bytes(4)
                        if payload[:1] == b"\x10"
                        else b"\x71" + payload[1:]
                    )
                    reads.append(bytes.fromhex("00000758") + reply)
                return 1
            if op == "read_specified_can_message":
                return reads.pop(0)

        runtime = NativeRuntime2026(
            action, native_cancelled=lambda: False, cancelled=lambda: cancelled[0]
        )
        with self.assertRaises(NativeRestorationCancelled) as caught:
            execute_context(self.context(False, charge_flow="01"), runtime)
        self.assertFalse(caught.exception.evidence["protocol_restored"])
        with self.assertRaises(TypeError):
            cast(dict, caught.exception.evidence)["protocol_restored"] = True
        writes = [e["data"][4:] for e in events if e["operation"] == "write_messages"]
        self.assertEqual(writes, [b"\x10\x03", b"\x31\x01\x11\x7e", b"\x22\xf1\x81"])
        self.assertIn("stop_sync_periodic", [e["operation"] for e in events])
        self.assertEqual(events[-1]["operation"], "disconnect")
        self.assertEqual(runtime.close(), [])

    def test_exact_current48_composition(self):
        for cid in (b"ACTUAL-CID", b"\xff\x20"):
            with self.subTest(cid_hex=cid.hex()):
                self.check_exact_current48_composition(cid)

    def check_exact_current48_composition(self, cid):
        from scripts.j2534_2026 import (
            BufferRead2026,
            J2534Device2026,
            NativeMessage,
            PrimitiveResult,
        )
        from scripts.programming_2026_unified import execute_context

        response = bytes.fromhex("01000E8062F18101") + cid.ljust(16, b"\0")
        native_reads = iter(
            (
                b"1234",
                bytes.fromhex("02FD000600000009"),
                bytes(4) + b"\x10" + bytes(4),
                bytes.fromhex("02FD800200000004"),
                bytes.fromhex("01000E80"),
                bytes.fromhex("02FD800100000018"),
                response,
            )
        )
        calls = []

        def provider(event, remaining):
            calls.append(event)
            name = event["operation"]
            if name in (
                "passthru_open",
                "passthru_connect",
                "passthru_connect_0500",
                "passthru_logical_connect",
            ):
                return PrimitiveResult(value=len(calls))
            if name == "passthru_scan_devices":
                return PrimitiveResult(value=1)
            if name == "passthru_next_device":
                return PrimitiveResult(value="AUTHORED")
            if name == "passthru_ioctl":
                return PrimitiveResult(value=1 if event["ioctl"] == 1 else None)
            if name == "passthru_queue":
                return PrimitiveResult(value=event["count"])
            if name == "passthru_read_buffer":
                return PrimitiveResult(
                    value=BufferRead2026(
                        NativeMessage(event["protocol"], next(native_reads)), 1
                    )
                )
            return PrimitiveResult()

        device = J2534Device2026(provider, background_workers=False)
        device.version = 1
        runtime = NativeRuntime2026(device.primitive, native_cancelled=lambda: False)
        result = execute_context(self.context(), runtime)
        from scripts.programming_replay import _report

        self.assertEqual(result["identifiers"], [cid])
        self.assertEqual(_report(result)["identifier_bytes_hex"], [cid.hex()])
        self.assertEqual(runtime.close(), [])
        self.assertEqual(device.logical, {})


WRITER_IDENTITIES = {
    "TCUWCanUnifiedFlashWriter.dll": "0db51f86238bc40b7a1ed3c67bf48d398d393d7110fba3e426764b16a9eb17de",
    "TCUWCanUnifiedFlashWriterEachArea.dll": "26821db78790387c8b7d81cfcfed009f156ad5b0cd529d9cad8520b79a86d58e",
}


class UnifiedWriterTests(unittest.TestCase):
    @staticmethod
    def context(each_area=False, smc_gateway=False):
        from scripts.calibration_2026 import parse_cuw_2026
        from scripts.demo_calibration import table
        from scripts.native_modules import identify_native_module
        from scripts.programming_2026_common import bind_native_parameter2026
        from scripts.programming_2026_unified import bind_native_context
        from tests.test_calibration_2026 import cuw, srecord

        name = (
            "TCUWCanUnifiedFlashWriterEachArea.dll"
            if each_area
            else "TCUWCanUnifiedFlashWriter.dll"
        )
        # Literal identities are included here, original source files are not needed.
        digests = WRITER_IDENTITIES
        text = (
            "[Format]\nVersion=105\n[Vehicle]\nNumberOfNode=1\nKindOfECU=1\nContactType=P5-Unified\n[Node01]\nNumberOfCalibration=1\nRequiredSpecReproVer=02\nDiagID=0100\nWakeUpTimeAfterReset=00\n[CPU11]\nCPUImageName=authored.srec\nNumberOfTargets=1\n01_TargetCalibration=AUTHORED\nLocationID=0108010000000720\nOffsetAddress=0000000000\nSeedKey="
            + "AA" * 16
            + "\nNonce="
            + "BB" * 16
            + "\nSecurityProperty2=08\n[CPUImage11]\nNumberOfAreaSettings=1\n01_StartAddress=00001002\n01_Length=00000004\n[WriteRoutine11]\nNumberOfAreaSettings=1\n01_StartAddress=00001002\n01_Length=00000002\n[EraseRoutine11]\nNumberOfAreaSettings=1\n01_StartAddress=00001000\n01_Length=00000002\n"
        )
        if smc_gateway:
            text = text.replace(
                "[Node01]", "[Node01]\nNumberOfGateway=1\n01_GatewayDiagID=0751"
            )
        data = (
            srecord(0, 0, b"authored")
            + b"\n"
            + b"\n".join(
                srecord(3, start, payload)
                for start, payload in (
                    (0x1000, b"AB"),
                    (0x1002, b"CD"),
                    (0x1004, b"EF"),
                )
            )
            + b"\n"
            + srecord(7, 0)
        )
        container = parse_cuw_2026(cuw(text, (data,)))
        values = {
            "ParamFileKeySystemProtocolMicon": "1P5-Unified",
            "DLLFileNameForFlashWrite": name,
            "GetCANIDFunctionNameForFlashWrite": "GetCanIDsFromParamForPrepareWrite",
            "CanIDForPrepareWrite": "0100/0108",
        }
        selection = bind_native_parameter2026(
            container,
            {"1P5-Unified.ini": table(tuple(values), [tuple(values.values())])},
            "write",
            encoded=False,
        )
        return bind_native_context(
            container,
            1,
            ("AUTHORED",),
            selection,
            identify_native_module(digests[name], name),
            {},
            {},
        )

    def test_complete_unified_native_byte_sequence(self):
        for each_area in (False, True):
            with self.subTest(each_area=each_area):
                self.check_complete_unified_native_byte_sequence(each_area)

    def check_complete_unified_native_byte_sequence(
        self,
        each_area,
        native_callback=None,
        fault_operation=None,
        expected_return: bool | None = True,
        smc_reply_size=None,
    ):
        from scripts.j2534_2026 import NativeJ2534Error2026
        from scripts.programming_2026_unified import execute_context

        calls = []
        reads = []
        faulted = []

        def action(event, remaining):
            calls.append(event)
            op = event["operation"]
            if op == fault_operation and not faulted:
                faulted.append(True)
                raise NativeJ2534Error2026(5)
            if op in ("get_timeout", "get_send_timeout"):
                return 3000
            if op == "get_programming_notification":
                return True
            if op == "start_flow_control_filter":
                return 0
            if op == "write_messages":
                payload = event["data"][4:]
                if payload[:1] == b"\x2e":
                    reply = b"\x6e" + payload[1:3]
                elif payload[:1] == b"\x34":
                    reply = b"\x74\x20\x00\x06"
                elif payload[:1] == b"\x36":
                    reply = b"\x76" + payload[1:2]
                elif payload[:1] == b"\x31":
                    reply = b"\x71" + payload[1:4]
                elif payload == b"\x37":
                    reply = b"\x77"
                elif payload == b"\x11\x01":
                    reply = b"\x51\x01"
                elif payload == b"\x10\x01" and smc_reply_size is not None:
                    reply = b"\x50\x01" + bytes(smc_reply_size - 2)
                elif payload == b"\x22\x10\x05":
                    reply = b"\x62\x10\x05\0"
                else:
                    return 1
                response = (
                    bytes.fromhex("00000761")
                    if event["data"][:4] == bytes.fromhex("00000751")
                    else bytes.fromhex("00000108")
                )
                reads.append(response + reply)
                return 1
            if op == "read_specified_can_message":
                return reads.pop(0)

        runtime = NativeRuntime2026(
            action, native_cancelled=native_callback or (lambda: False)
        )
        result = execute_context(
            self.context(each_area, smc_reply_size is not None), runtime
        )
        self.assertIs(result["native_return"], expected_return)
        if expected_return is False:
            self.assertEqual(result["native_primary_error"], 0x3F9)
            self.assertEqual(runtime.close(), [])
            return
        if expected_return is None:
            self.assertFalse(result["complete"])
            self.assertEqual(
                (result["native_primary_error"], result["native_passthru_error"]),
                (1, 5),
            )
            self.assertEqual(runtime.close(), [])
            return
        self.assertTrue(result["complete"])
        self.assertEqual(result["transferred"], 8)
        self.assertEqual(
            [
                e["data"][4:]
                for e in calls
                if e["operation"] == "write_messages" and e["data"][4:5] == b"\x36"
            ],
            [b"\x36\x01AB", b"\x36\x01CD", b"\x36\x01CDEF"],
        )
        self.assertEqual(runtime.close(), [])

    def test_smc_default_session_minimum_counts_native_can_address(self):
        self.check_complete_unified_native_byte_sequence(False, smc_reply_size=6)
        self.check_complete_unified_native_byte_sequence(
            False, smc_reply_size=5, expected_return=False
        )

    def test_native_filter_fault_is_suppressed_but_unreturned_export_is_unknown(self):
        self.check_complete_unified_native_byte_sequence(
            False, fault_operation="stop_filter"
        )
        self.check_complete_unified_native_byte_sequence(
            False, fault_operation="set_history_enabled", expected_return=None
        )

    def test_host_fault_keeps_original_when_filter_cleanup_also_fails(self):
        from scripts.programming_2026_unified import execute_context

        original = OSError("authored provider failure")
        releases = []

        def action(event, remaining):
            operation = event["operation"]
            if operation == "get_timeout":
                return 3000
            if operation == "start_flow_control_filter":
                return 1
            if operation == "write_messages":
                raise original
            if operation == "stop_filter":
                releases.append(True)
                if len(releases) == 1:
                    raise ValueError("authored host cleanup failure")

        runtime = NativeRuntime2026(action)
        with self.assertRaises(OSError) as caught:
            execute_context(self.context(), runtime)
        self.assertIs(caught.exception, original)
        self.assertEqual(runtime.close(), [])

    def test_native_writer_fault_resets_progress_and_preserves_driver_status(self):
        from scripts.j2534_2026 import NativeJ2534Error2026
        from scripts.programming_2026_unified import execute_context

        calls = []

        def action(event, remaining):
            calls.append(event)
            if event["operation"] in ("get_timeout", "get_send_timeout"):
                return 3000
            if event["operation"] == "start_flow_control_filter":
                return 1
            if event["operation"] == "write_messages":
                raise NativeJ2534Error2026(5)
            if event["operation"] == "get_programming_notification":
                return True

        runtime = NativeRuntime2026(action, native_cancelled=lambda: False)
        runtime.own("stop_sync_periodic")
        result = execute_context(self.context(), runtime)
        self.assertEqual(
            (
                result["native_return"],
                result["native_primary_error"],
                result["native_passthru_error"],
                result["native_outcome"],
            ),
            (False, 1, 5, 2),
        )
        self.assertEqual(
            [
                event["enabled"]
                for event in calls
                if event["operation"] == "set_history_enabled"
            ],
            [False, True],
        )
        self.assertEqual(
            [event["value"] for event in calls if event["operation"] == "progress"],
            [0, 0],
        )
        self.assertEqual(runtime.close(), [])

    def test_native_writer_false_cancel_argument_does_not_query_callback(self):
        queried = []

        def native_callback():
            queried.append(True)
            return True

        self.check_complete_unified_native_byte_sequence(False, native_callback)
        self.assertEqual(queried, [])

    def test_malformed_declared_optional_header_fails_before_io(self):
        from scripts.calibration_2026 import parse_cuw_2026
        from scripts.programming_2026_common import bind_native_parameter2026
        from scripts.programming_2026_unified import (
            bind_native_context,
            execute_context,
        )
        from tests.test_calibration_2026 import cuw

        original = self.context()
        source = original.metadata.source_container
        text = source.attached.data.decode("ascii").replace(
            "01_Length=00000002", "01_Length=malformed"
        )
        container = parse_cuw_2026(
            cuw(
                text,
                tuple(record.data for record in source.records),
                encode_fields=False,
            )
        )
        selection = bind_native_parameter2026(
            container, original.parameter.catalog_sources, "write", encoded=False
        )
        context = bind_native_context(
            container, 1, original.observed_cids, selection, original.identity, {}, {}
        )
        provider = Primitive()
        with self.assertRaises(ValueError):
            execute_context(context, NativeRuntime2026(provider))
        self.assertEqual(provider.events, [])

    def test_second_node_uses_global_cpu_security_fields(self):
        from scripts.calibration_2026 import encode_metadata_string_2026, parse_cuw_2026
        from scripts.demo_calibration import table
        from scripts.programming_2026_common import bind_native_parameter2026
        from scripts.programming_2026_unified import (
            bind_native_context,
            execute_context,
        )
        from tests.test_calibration_2026 import cuw

        original = self.context()
        source = original.metadata.source_container
        head, node = source.attached.data.decode("ascii").split("[Node01]", 1)
        second = (
            ("[Node01]" + node)
            .replace("Node01", "Node02")
            .replace("CPU11", "CPU21")
            .replace("CPUImage11", "CPUImage21")
            .replace("WriteRoutine11", "WriteRoutine21")
            .replace("EraseRoutine11", "EraseRoutine21")
        )
        second = second.replace("OffsetAddress=0000000000", "OffsetAddress=0000000010")
        for old, new in (("AA", "CC"), ("BB", "DD")):
            second = second.replace(
                encode_metadata_string_2026(old * 16),
                encode_metadata_string_2026(new * 16),
            )
        container = parse_cuw_2026(
            cuw(
                head.replace("NumberOfNode=1", "NumberOfNode=2")
                + "[Node01]"
                + node
                + second,
                tuple(record.data for record in source.records) * 2,
                encode_fields=False,
            )
        )
        values = {name: value[0] for name, value in original.parameter.values.items()}
        values["CanIDForPrepareWrite"] = "0100/0108\n0200/0208"
        selection = bind_native_parameter2026(
            container,
            {"1P5-Unified.ini": table(tuple(values), [tuple(values.values())])},
            "write",
            node=2,
            encoded=False,
        )
        context = bind_native_context(
            container, 2, original.observed_cids, selection, original.identity, {}, {}
        )
        writes, reads = [], []

        def action(event, remaining):
            operation = event["operation"]
            if operation in ("get_timeout", "get_send_timeout"):
                return 3000
            if operation == "start_flow_control_filter":
                return 1
            if operation == "write_messages":
                payload = event["data"][4:]
                if payload[:1] != b"\x2e":
                    raise OSError("authored stop after fingerprints")
                writes.append(payload)
                reads.append(bytes.fromhex("00000208") + b"\x6e" + payload[1:3])
                return 1
            if operation == "read_specified_can_message":
                return reads.pop(0)

        runtime = NativeRuntime2026(action, native_cancelled=lambda: False)
        with self.assertRaises(OSError):
            execute_context(context, runtime)
        self.assertEqual(
            writes,
            [
                bytes.fromhex("2E02030000000010"),
                bytes.fromhex("2E0201") + b"\xcc" * 16,
                bytes.fromhex("2E0202") + b"\xdd" * 16,
            ],
        )
        self.assertEqual(runtime.close(), [])


class EthernetWriterCodecTests(unittest.TestCase):
    def test_literal_fingerprint_dids_and_systemtime_words(self):
        from scripts.programming_2026_unified import ethernet_programming_information

        words = (2026, 10, 2, 20, 1, 2, 3, 4)
        result = ethernet_programming_information(1, b"N" * 16, bytes(range(64)), words)
        self.assertEqual(result[1][0][3:], bytes(range(32)) + bytes(32))
        self.assertEqual(len(result[1][0]), 67)
        self.assertEqual(
            ethernet_programming_information(1, b"N" * 16, bytes(range(32)), words)[1],
            result[1],
        )
        self.assertEqual(
            [value[0][:3] for value in result],
            [bytes.fromhex("2E0202"), bytes.fromhex("2E0220"), bytes.fromhex("2E0230")],
        )
        self.assertEqual(
            result[2][0][3:], bytes.fromhex("07EA000A000200140001000200030004")
        )
        last = ethernet_programming_information(16, b"N" * 16, b"I" * 64, words)
        self.assertEqual(
            [value[0][:3] for value in last],
            [bytes.fromhex("2E024F"), bytes.fromhex("2E022F"), bytes.fromhex("2E023F")],
        )
        for slot in (0, 17, True):
            with self.assertRaises(ValueError):
                ethernet_programming_information(slot, b"N" * 16, b"I" * 64, words)

    def test_ethernet_routine_is_distinct_from_phase6(self):
        from scripts.calibration_2026 import NativeLogicalArea2026
        from scripts.programming_2026_unified import ethernet_routine_request

        area = NativeLogicalArea2026(
            "ReproData", 0x1000, 4, None, b"C" * 16, b"S" * 256, None, b"DATA", {}
        )
        payload, expected, error = ethernet_routine_request(0, area, "03")
        self.assertEqual(
            payload,
            bytes.fromhex("310110F544000010000000000400FFFFFFFF0010") + b"C" * 16,
        )
        self.assertEqual((expected, error), (bytes.fromhex("710110F5"), 0x56))
        self.assertEqual(
            ethernet_routine_request(1, area, "04")[0],
            bytes.fromhex("3101FF00440000100000000004"),
        )
        self.assertEqual(len(ethernet_routine_request(2, area, "04")[0]), 276)


class EthernetStreamTests(unittest.TestCase):
    def test_first_s1_flag_and_zero_tail_counter_restart(self):
        from scripts.programming_2026_unified import ethernet_srecord_stream_blocks
        from tests.test_calibration_2026 import srecord

        data = (
            b"PREFIX"
            + srecord(1, 0x1000, b"HEAD")
            + b"\n"
            + srecord(3, 0x1004, b"DATA")
            + b"\n"
        )
        self.assertEqual(
            list(
                ethernet_srecord_stream_blocks(
                    data, len(data) - 1, ((0x1000, 6, 0),), 0x1000, 8, 4
                )
            ),
            [(1, b"DATA"), (1, bytes(4))],
        )
        self.assertEqual(
            list(
                ethernet_srecord_stream_blocks(
                    data, len(data) - 1, ((0x1000, 6, 1),), 0x1000, 8, 4
                )
            ),
            [(1, b"HEAD"), (2, b"DATA")],
        )

    def test_unmatched_group_and_malformed_record_native_errors(self):
        from scripts.programming_2026_unified import ethernet_srecord_stream_blocks

        with self.assertRaises(NativePassThruException2026) as caught:
            list(
                ethernet_srecord_stream_blocks(
                    b"Xbroken", 6, ((0x1000, 1, 0),), 0x1001, 4, 4
                )
            )
        self.assertEqual(caught.exception.line, 0x42F)
        with self.assertRaises(ValueError):
            list(
                ethernet_srecord_stream_blocks(
                    b"Xbroken", 6, ((0x1000, 1, 0),), 0x1000, 4, 4
                )
            )


ETHERNET_WRITER_IDENTITY = (
    "d99d23f9f6a5b47fd63719d8897a3f95fed069be06e3a2473ea3e4801243bde9"
)


class EthernetFullWriterTests(unittest.TestCase):
    @staticmethod
    def context(observations=None, attachments=None, *, whole=False):
        from scripts.calibration_2026 import parse_cuw_2026
        from scripts.demo_calibration import table
        from scripts.native_modules import identify_native_module
        from scripts.programming_2026_common import bind_native_parameter2026
        from scripts.programming_2026_unified import bind_native_context
        from tests.test_calibration_2026 import cuw, logical_text

        text = (
            logical_text(method="01" if whole else "02", routine=whole)
            .replace("ContactType=P5-Unified", "ContactType=Ethernet\nKindOfECU=1")
            .replace("[Node01]", "[Node01]\nLogicalAddress=0100\nDiagID=0100")
            .replace("44" * 64, "44" * 16)
            .replace("55" * 384, "55" * 256)
        )
        if whole:
            text += f"CMAC={'66' * 16}\nDigitalSignature={'77' * 256}\n"
        container = parse_cuw_2026(
            cuw(text, (b"DATA", b"ROUT") if whole else (b"DATA",))
        )
        name = "TCUWEthernetReprostdFlashWriter.dll"
        values = {
            "ParamFileKeySystemProtocolMicon": "1Ethernet03",
            "DLLFileNameForFlashWrite": name,
            "ReceiveTimeoutBeforeGetCID": "3000",
        }
        selection = bind_native_parameter2026(
            container,
            {"1Ethernet03.ini": table(tuple(values), [tuple(values.values())])},
            "write",
            encoded=False,
        )
        fields = (
            "IFVersion",
            "SoftwareID",
            "SoftwareVersion",
            "LicenseKey",
            "SUBARU_LicenseKey",
            "SUZUKI_LicenseKey",
            "DAIHATSU_LicenseKey",
            "VehicleIdentificationNumber",
            "RequesterKind",
            "KeypairID",
            "DAIHATSU_KeypairID",
        )
        text = "[ReproKeyRequest]\n" + "\n".join(
            name + "=" + ("A" * 64 if name == "SoftwareID" else "authored")
            for name in fields
        )
        encoded = bytearray()
        for value in text.encode("latin1"):
            value = (value - 0x78) & 255
            encoded.extend(((value >> 4) << 2, (value & 15) << 2))
        return bind_native_context(
            container,
            1,
            ("authored-old",),
            selection,
            identify_native_module(ETHERNET_WRITER_IDENTITY, name),
            {"rks_ini": bytes(encoded)} if attachments is None else attachments,
            {} if observations is None else observations,
        )

    def run_writer(self, context):
        from scripts.programming_2026_unified import execute_context

        calls, reads = [], []

        def action(event, remaining):
            calls.append(event)
            op = event["operation"]
            if op == "get_timeout":
                return 3000
            if op == "get_system_time":
                return (2026, 10, 2, 20, 1, 2, 3, 4)
            if op == "write_tcp":
                data = event["data"]
                payload = data[12:]
                if data[10:12] == bytes.fromhex("E400"):
                    return 1
                if payload[:1] == b"\x2e":
                    reply = b"\x6e" + payload[1:3]
                elif payload[:1] == b"\x34":
                    reply = b"\x74\x20\0\x06"
                elif payload[:1] == b"\x36":
                    reply = b"\x76" + payload[1:2]
                elif payload[:1] == b"\x31":
                    reply = b"\x71" + payload[1:4]
                elif payload == b"\x37":
                    reply = b"\x77"
                elif payload == b"\x11\x01":
                    reply = b"\x51\x01"
                else:
                    raise AssertionError("Unexpected authored Ethernet request")
                reads.append(data[10:12] + data[8:10] + reply)
                return 1
            if op == "read_tcp":
                return reads.pop(0)

        runtime = NativeRuntime2026(action, native_cancelled=lambda: False)
        for protocol in (0x8203, 0x8205, 0x8206):
            runtime.own("logical_disconnect", protocol=protocol)
        runtime.own("stop_sync_periodic")
        result = execute_context(context, runtime)
        self.assertEqual(runtime.close(), [])
        return result, calls

    def test_complete_raw_ethernet_writer_from_imported_files(self):
        result, calls = self.run_writer(self.context())
        self.assertTrue(result["complete"])
        self.assertEqual(result["transferred"], 4)
        self.assertEqual(
            [
                e["data"][12:]
                for e in calls
                if e["operation"] == "write_tcp" and e["data"][12:13] == b"\x36"
            ],
            [b"\x36\x01DATA"],
        )
        self.assertEqual(
            [e["protocol"] for e in calls if e["operation"] == "logical_disconnect"],
            [0x8206, 0x8205, 0x8203],
        )

    def test_whole_package_downloads_and_authenticates_routine_before_erase(self):
        result, calls = self.run_writer(self.context(whole=True))
        self.assertTrue(result["native_return"])
        self.assertEqual(result["transferred"], 8)
        requests = [
            event["data"][12:] for event in calls if event["operation"] == "write_tcp"
        ]
        self.assertEqual(
            [request for request in requests if request[:1] == b"\x36"],
            [b"\x36\x01ROUT", b"\x36\x01DATA"],
        )
        routines = [request[:4] for request in requests if request[:1] == b"\x31"]
        self.assertEqual(
            routines, [b"\x31\x01\x10\xf5", b"\x31\x01\xff\0", b"\x31\x01\x10\xf6"]
        )
        count = [
            event["value"]
            for event in calls
            if event["operation"] == "progress" and event["field"] == "percent"
        ]
        self.assertEqual(count, [100])

    def test_retained_rks_identity_precedes_new_source_and_rejects_fabrication(self):
        from scripts.cuw_2026 import rks_software_identity2026

        original = self.context()
        identity = rks_software_identity2026(original.attachments["rks_ini"])
        retained = self.context(
            {"rks_software_identity": identity}, {"rks_ini": b"malformed reload"}
        )
        self.assertIs(retained.observations["rks_software_identity"], identity)
        self.assertNotIn("A" * 64, repr(retained))
        with self.assertRaises(TypeError):
            self.context({"rks_software_identity": b"A" * 64})

    def test_native_fault_restores_resources_and_reads_shared_notification(self):
        from scripts.j2534_2026 import NativeJ2534Error2026
        from scripts.programming_2026_unified import execute_context

        for shared_value, failure in (
            (False, NativePassThruException2026(0x47, "authored", 1)),
            (True, NativePassThruException2026(0x47, "authored", 1)),
            (True, NativeJ2534Error2026(5)),
        ):
            with self.subTest(
                shared_value=shared_value, failure=type(failure).__name__
            ):
                calls = []

                def action(
                    event,
                    remaining,
                    calls=calls,
                    shared_value=shared_value,
                    failure=failure,
                ):
                    calls.append(event)
                    if event["operation"] == "get_timeout":
                        return 3000
                    if event["operation"] == "write_tcp":
                        raise failure
                    if event["operation"] == "get_programming_notification":
                        return shared_value

                runtime = NativeRuntime2026(action, native_cancelled=lambda: False)
                for protocol in (0x8203, 0x8205, 0x8206):
                    runtime.own("logical_disconnect", protocol=protocol)
                runtime.own("stop_sync_periodic")
                result = execute_context(self.context(), runtime)
                self.assertFalse(result["native_return"])
                self.assertEqual(
                    result["native_primary_error"],
                    1 if isinstance(failure, NativeJ2534Error2026) else 0x47,
                )
                if isinstance(failure, NativeJ2534Error2026):
                    self.assertEqual(result["native_passthru_error"], 5)
                self.assertEqual(result["native_outcome"], 2 if shared_value else 1)
                self.assertEqual(
                    result.get("native_comm_phase"), None if shared_value else 1
                )
                operations = [event["operation"] for event in calls]
                self.assertLess(
                    operations.index("stop_sync_periodic"),
                    operations.index("logical_disconnect"),
                )
                self.assertLess(
                    max(
                        i
                        for i, operation in enumerate(operations)
                        if operation == "logical_disconnect"
                    ),
                    operations.index("get_programming_notification"),
                )
                self.assertEqual(runtime.close(), [])


if __name__ == "__main__":
    unittest.main()
