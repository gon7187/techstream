import unittest

from scripts.j2534_2026 import NativeCommunicationAddress
from scripts.native_modules import identify_native_module
from scripts.programming import NativeTransportError
from scripts.programming_2026_common import CommonResponseError, NativeRuntime2026
from scripts.programming_2026_raw import (
    SOFTWARE_INFO,
    SoftwareInfoContext2026,
    decode_software_info2026,
    run_software_info,
)
from tests.private_evidence import read_private_json


class SoftwareInfoTests(unittest.TestCase):
    def context(self, addresses=None, **kwargs):
        return SoftwareInfoContext2026(
            identify_native_module(
                "531c6044f4875a4b9643810ecf36cf5d411cca3a0d52f3661e1bda51758abc25",
                SOFTWARE_INFO,
            ),
            addresses
            if addresses is not None
            else (NativeCommunicationAddress(b"\x07\xe0", b"\x07\xe8"),),
            **kwargs,
        )

    def run_context(
        self,
        replies,
        context=None,
        fault=None,
        cancel=None,
        native_cancel=lambda: False,
    ):
        events, replies = [], iter(replies)
        resources = []
        self.events, self.resources = events, resources

        def action(event, remaining):
            self.assertGreater(remaining, 0)
            events.append(event)
            if fault:
                fault(event)
            name = event["operation"]
            if name == "get_timeout":
                return 100
            if name == "start_flow_control_filter":
                resources.append(5)
                return 5
            if name == "stop_filter":
                resources.remove(event["identifier"])
            if name == "write_messages":
                return 1
            if name == "read_specified_can_message":
                return event["address"] + next(replies)
            return None

        return run_software_info(
            context or self.context(),
            NativeRuntime2026(
                action,
                cancelled=cancel or (lambda: False),
                native_cancelled=native_cancel,
            ),
        )

    def test_native_callback_listing_false_second_observation_and_detail_skip(self):
        for observations, replies, expected, writes in (
            ((True, True), (), True, 0),
            ((True, False), (), False, 0),
            ((False, False, True), (b"\x5a\x88\x00\x01",), True, 1),
            ((False, False, True), (b"\x5a\x88\x00\x00",), True, 1),
            ((False, True), (), False, 1),
        ):
            with self.subTest(observations=observations, replies=replies):
                callback = iter(observations)
                result = self.run_context(
                    replies, native_cancel=lambda callback=callback: next(callback)
                )
                self.assertEqual(result["native_success"], expected)
                self.assertEqual(result["cids"], ())
                self.assertEqual(
                    sum(
                        event["operation"] == "write_messages" for event in self.events
                    ),
                    writes,
                )
                self.assertFalse(self.resources)
                self.assertEqual(list(callback), [])

    def test_native_unknown_exception_preserves_error_fields_and_disconnects(self):
        from scripts.programming_2026_common import NativeException2026

        def fault(event):
            if event["operation"] == "write_messages":
                raise NativeException2026("")

        result = self.run_context((), fault=fault)
        self.assertFalse(result["native_success"])
        self.assertIsNone(result["native_error_code"])
        self.assertIsNone(result["driver_error_code"])
        self.assertEqual(self.events[-1], {"operation": "disconnect"})

    def test_native_getter_requests_and_address_history(self):
        result = self.run_context(
            (
                b"\x5a\x88\0\1\2",
                b"\x5a\x88\1" + b"CAL-ID-ONE       ",
                b"\x5a\x88\2" + b"CAL-ID-TWO       ",
            )
        )
        self.assertEqual(result["cids"], ("CAL-ID-ONE", "CAL-ID-TWO"))
        self.assertEqual(
            (result["native_return"], result["native_success"]), (None, True)
        )
        self.assertEqual(result["query_ids"], (b"\x07\xe0",) * 2)
        writes = [e["data"] for e in self.events if e["operation"] == "write_messages"]
        self.assertEqual(
            writes, [b"\0\0\x07\xe0\x1a\x88" + bytes((v,)) for v in (0, 1, 2)]
        )
        self.assertFalse(self.resources)
        self.assertEqual(self.events[-1]["operation"], "disconnect")

    def test_both_full_data_header_paths_and_native_space_zero_rules(self):
        self.assertEqual(
            decode_software_info2026(b"\0\0\x07\xe8\x5a\x88\1" + b"ABCDEFGHIJKLMNOP"),
            "ABCDEFGHIJKLMNOP",
        )
        self.assertEqual(
            decode_software_info2026(
                b"\0\0\x07\xe8\xaa\x5a\x88\1" + b"ABCDEFGHIJKLMNOP"
            ),
            "ABCDEFGHIJKLMNOP",
        )
        self.assertEqual(decode_software_info2026(b"\0" * 7 + b" " * 16), " ")
        self.assertEqual(
            decode_software_info2026(b"\0" * 7 + b"A  B" + b" " * 12, 3), "A  "
        )
        with self.assertRaises(CommonResponseError):
            decode_software_info2026(b"\0" * 23)

    def test_list_embedded_zero_and_short_detail_are_native_failures(self):
        for replies in ((b"\x5a\x88\0\1\0",), (b"\x5a\x88\0\1", b"\x5a\x88\1short")):
            result = self.run_context(replies)
            self.assertEqual(result["native_error_code"], 3)
            self.assertEqual(result["state"], "get_cid_failed")
            self.assertEqual(
                (result["native_return"], result["native_success"]), (None, False)
            )
            self.assertFalse(self.resources)

    def test_partial_results_retained_on_later_failure(self):
        result = self.run_context(
            (b"\x5a\x88\0\1\2", b"\x5a\x88\1" + b"A" * 16, b"\x5a\x88\2")
        )
        self.assertEqual(result["cids"], ("A" * 16,))
        self.assertEqual(result["native_error_code"], 3)

    def test_cancel_after_filter_acquisition_cleans_filter_and_connection(self):
        cancelled = [False]

        def fault(event):
            if event["operation"] == "start_flow_control_filter":
                cancelled[0] = True

        with self.assertRaises(InterruptedError):
            self.run_context((), fault=fault, cancel=lambda: cancelled[0])
        self.assertFalse(self.resources)
        self.assertEqual(self.events[-1]["operation"], "disconnect")

    def test_partial_write_fails_and_cleans(self):
        def fault(event):
            if event["operation"] == "write_messages":
                raise OSError("authored write failure")

        with self.assertRaises(OSError):
            self.run_context((), fault=fault)
        self.assertFalse(self.resources)
        self.assertEqual(self.events[-1]["operation"], "disconnect")

    def test_bs_override_restored_after_success_malformed_and_cancel(self):
        for mode in ("success", "bad", "cancel", "setter-fault"):
            context = self.context(apgs_parking_assist_monitor=True)
            cancelled = [False]

            def fault(event, mode=mode, cancelled=cancelled):
                if (
                    mode == "cancel"
                    and event["operation"] == "start_flow_control_filter"
                ):
                    cancelled[0] = True
                if mode == "setter-fault" and event.get("parameters") == ((0x1E, 1),):
                    raise OSError("authored partial BS setter")

            if mode in ("cancel", "setter-fault"):
                with self.assertRaises((InterruptedError, OSError)):
                    self.run_context(
                        (), context, fault, lambda cancelled=cancelled: cancelled[0]
                    )
            else:
                self.run_context(
                    (
                        b"\x5a\x88\0\1",
                        b"\x5a\x88\1" + b"A" * (16 if mode == "success" else 1),
                    ),
                    context,
                )
            controls = [
                event["parameters"]
                for event in self.events
                if event["operation"] == "control_io"
            ]
            self.assertEqual(controls, [((0x1E, 1),), ((0x1E, 0),)])
            self.assertEqual(self.events[-1]["operation"], "disconnect")
            self.assertFalse(self.resources)

    def test_native_j2534_exception_preserves_native_and_driver_errors(self):
        from scripts.programming_2026_common import NativeJ2534Exception2026

        def fault(event):
            if event["operation"] == "write_messages":
                raise NativeJ2534Exception2026(16, "authored.cpp", 1)

        result = self.run_context((), fault=fault)
        self.assertEqual(
            (result["native_error_code"], result["driver_error_code"]), (1, 16)
        )
        self.assertFalse(self.resources)


class ImportedGetterIntegrationTests(unittest.TestCase):
    def test_actual_import_parameter_address_and_typed_driver_wire(self):
        from scripts.calibration_2026 import parse_cuw_2026
        from scripts.demo_calibration import table
        from scripts.j2534_2026 import J2534Device2026, NativeMessage
        from scripts.programming_2026_common import bind_native_parameter2026
        from scripts.programming_2026_raw import bind_native_context
        from tests.test_calibration_2026 import cuw
        from tests.test_j2534_2026 import Provider

        text = (
            "[Format]\nVersion=105\n[Vehicle]\nNumberOfNode=1\nKindOfECU=1\nContactType=CAN\n"
            "[Node01]\nNumberOfCalibration=1\nRequiredSpecReproVer=02\nDiagID=0100\n"
            "[CPU11]\nCPUImageName=authored.vbf\nLocationID=0108010000000720\n"
        )
        container = parse_cuw_2026(cuw(text, (bytes(1024),)))
        values = {
            "ParamFileKeySystemProtocolMicon": "1CAN",
            "DLLFileNameForGetCID": SOFTWARE_INFO,
            "GetCANIDFunctionNameForGetCID": "GetCanIDsFromParamForGetCID",
            "CanIDForGetCID": "0100/0108",
            "SoftwareInfoIDByteNum": "9",
            "AlternateCPUType": "2",
        }
        selection = bind_native_parameter2026(
            container,
            {
                "1CAN.ini": table(tuple(values), [tuple(values.values())]),
                "1CAN2.ini": table(
                    tuple(values),
                    [
                        tuple(
                            dict(
                                values, ParamFileKeySystemProtocolMicon="1CAN2"
                            ).values()
                        )
                    ],
                ),
            },
            "get_cid",
            encoded=False,
        )
        context = bind_native_context(
            container, 1, (), selection, SoftwareInfoTests().context().identity, {}, {}
        )
        assert isinstance(context, SoftwareInfoContext2026)
        from scripts.calibration_2026 import native2026_with_cpu_type

        alternate = bind_native_parameter2026(
            container,
            selection.catalog_sources,
            "get_cid",
            encoded=False,
            metadata_state=native2026_with_cpu_type(selection.metadata, 0, "2"),
        )
        alternate_context = bind_native_context(
            container, 1, (), alternate, SoftwareInfoTests().context().identity, {}, {}
        )
        self.assertEqual(alternate_context, context)
        self.assertNotEqual(alternate.metadata, selection.metadata)
        for malformed in (False, True):
            provider = Provider()
            payloads = (
                b"\x5a\x88\0\1",
                b"\x5a\x88\1" + (b"short" if malformed else b"IMPORTED-CAL-ID "),
            )
            provider.reads = [
                batch
                for p in payloads
                for batch in (
                    (NativeMessage(6, b"\0\0\x01\0", rx_status=9),),
                    (NativeMessage(6, b"\0\0\x01\x08" + p),),
                )
            ]
            device = J2534Device2026(
                provider, clock=lambda: 0, background_workers=False
            )
            device.open()
            result = run_software_info(
                context,
                NativeRuntime2026(
                    device.primitive, clock=lambda: 0, native_cancelled=lambda: False
                ),
            )
            self.assertEqual(
                result["state"], "get_cid_failed" if malformed else "cid_read_completed"
            )
            if not malformed:
                self.assertEqual(result["cids"], ("IMPORTED-",))
            writes = [
                event["messages"][0].data
                for event, _ in provider.calls
                if event["operation"] == "passthru_write"
            ]
            self.assertEqual(
                writes, [b"\0\0\x01\0\x1a\x88" + bytes((v,)) for v in (0, 1)]
            )
            self.assertEqual(provider.operations.count("passthru_start_filter"), 2)
            self.assertEqual(provider.operations.count("passthru_stop_filter"), 2)
            self.assertEqual(provider.operations.count("passthru_disconnect"), 1)
            device.close()


class RetryTests(unittest.TestCase):
    def run_retry(self, error=13, b32=False, cancel=False, fault=None):
        from scripts.programming_2026_raw import (
            POWERTRAIN,
            PowerTrainRetryContext2026,
            prepare_powertrain_retry,
        )

        identity = identify_native_module(
            "0a11170ac1b6b14bf387164ada2f5f2f6ab93e084a341affa5794164d79e3a82",
            POWERTRAIN,
        )
        context = PowerTrainRetryContext2026(
            identity,
            NativeCommunicationAddress(b"\x07\xe0", b"\x07\xe8"),
            b32,
            error,
            5,
        )
        replies = iter(
            (
                NativeTransportError(16),
                b"\0\0\x07\xe8junk",
                b"\0\0\x07\xe8\x3c",
                b"\0\0\x07\xe8\x3c",
            )
        )
        self.events = []
        self.cancelled = False

        def action(event, _remaining):
            self.events.append(event)
            if fault:
                fault(event)
            if event["operation"] == "start_flow_control_filter":
                return 2
            if event["operation"] == "write_messages":
                return 1
            if event["operation"] == "read_specified_can_message":
                if cancel:
                    self.cancelled = True
                value = next(replies)
                if isinstance(value, Exception):
                    raise value
                return value
            return None

        return prepare_powertrain_retry(
            context,
            NativeRuntime2026(
                action, clock=lambda: 0, cancelled=lambda: self.cancelled
            ),
        )

    def test_dummy_drain_13_and_15_literal_lengths_and_repeat(self):
        for error, length in ((13, 1024), (15, 256)):
            result = self.run_retry(error)
            self.assertEqual(result["state"], "retry_prepared")
            self.assertEqual(
                (result["native_return"], result["native_success"]), (True, None)
            )
            self.assertEqual(result["attempts"], 2)
            writes = [
                e["data"] for e in self.events if e["operation"] == "write_messages"
            ]
            self.assertEqual(
                writes,
                [b"\0\0\x07\xe0\5", b"\0\0\x07\xe0" + bytes(length), b"\0\0\x07\xe0\5"],
            )
            self.assertEqual(
                self.events[-1], {"operation": "stop_filter", "identifier": 2}
            )

    def test_other_error_is_native20_and_b32_is_wait_only(self):
        result = self.run_retry(7)
        self.assertEqual(result["native_error_code"], 20)
        result = self.run_retry(b32=True)
        self.assertEqual(result["attempts"], 0)
        self.assertEqual(
            [e["milliseconds"] for e in self.events if e["operation"] == "wait"], [5000]
        )

    def test_cancel_cleans_and_does_not_report_ready(self):
        with self.assertRaises(InterruptedError):
            self.run_retry(cancel=True)
        self.assertEqual(self.events[-1], {"operation": "stop_filter", "identifier": 2})

    def test_actual_import_retry_through_typed_driver_timeout_and_partial_write(self):
        from scripts.j2534_2026 import J2534Device2026, NativeMessage, PrimitiveResult
        from scripts.programming_2026_raw import (
            POWERTRAIN,
            bind_powertrain_retry_context,
            prepare_powertrain_retry,
        )
        from tests.test_j2534_2026 import Provider

        write_context = SolarTests().context(module=POWERTRAIN)
        context = bind_powertrain_retry_context(
            write_context.selection.metadata.source_container,
            1,
            (),
            write_context.selection,
            write_context.identity,
            {},
            {"previous_error": 13},
        )
        request, response = context.address.headers()
        for partial in (False, True):
            provider = Provider()
            queue = [
                (NativeMessage(6, request, rx_status=9),),
                PrimitiveResult(status=16),
                (NativeMessage(6, request, rx_status=9),),
                (NativeMessage(6, response + b"junk"),),
                (NativeMessage(6, response + b"\xff"),),
                (NativeMessage(6, request, rx_status=9),),
                (NativeMessage(6, response + b"\x3c"),),
            ]

            def raw(event, remaining, provider=provider, queue=queue, partial=partial):
                name = event["operation"]
                if name == "passthru_read":
                    provider.calls.append((event, remaining))
                    value = queue.pop(0)
                    return (
                        value
                        if isinstance(value, PrimitiveResult)
                        else PrimitiveResult(value=value)
                    )
                if (
                    partial
                    and name == "passthru_write"
                    and len(event["messages"][0].data) == 1028
                ):
                    return PrimitiveResult(value=0)
                return provider(event, remaining)

            device = J2534Device2026(raw, clock=lambda: 0, background_workers=False)
            device.open()
            device.connect(6)
            runtime = NativeRuntime2026(device.primitive, clock=lambda: 0)
            if partial:
                with self.assertRaises(ValueError):
                    prepare_powertrain_retry(context, runtime)
            else:
                result = prepare_powertrain_retry(context, runtime)
                self.assertEqual(
                    (result["state"], result["attempts"]), ("retry_prepared", 2)
                )
                self.assertFalse(queue)
            self.assertEqual(device.filters, [])
            device.disconnect()
            device.close()


class SolarTests(unittest.TestCase):
    def context(self, no_verify=False, module=None, extra_values=None, two_cpu=False):
        from scripts.calibration_2026 import parse_cuw_2026
        from scripts.demo_calibration import table
        from scripts.programming_2026_common import bind_native_parameter2026
        from scripts.programming_2026_raw import SOLAR, bind_solar_context
        from tests.test_calibration_2026 import cuw

        text = (
            "[Format]\nVersion=5\n[Vehicle]\nNumberOfCalibration=1\nKindOfECU=1\nContactType=CAN\n"
            "[Node01]\nNumberOfCalibration=1\nRequiredSpecReproVer=02\nDiagID=0100\n"
            "[CPU01]\nCPUImageName=authored.vbf\nLocationID=0108010000000720\nNumberOfTargets=1\n01_TargetCalibration=OLD\n01_TargetData=12345678\n"
        )
        module = module or SOLAR
        if two_cpu:
            text = text.replace(
                "NumberOfCalibration=1", "NumberOfCalibration=2"
            ).replace("[CPU01]", "[CPU01]\nCPUType=1")
            text += "[CPU02]\nCPUType=2\nCPUImageName=second.vbf\nLocationID=0108010000000720\nNumberOfTargets=1\n01_TargetCalibration=OLD\n01_TargetData=12345678\n"
        container = parse_cuw_2026(cuw(text, (bytes(1024),) * (2 if two_cpu else 1)))
        values = {
            "ParamFileKeySystemProtocolMicon": "1CAN",
            "DLLFileNameForFlashWrite": module,
            "GetCANIDFunctionNameForFlashWrite": "GetCanIDsFromParamForPrepareWrite",
            "CanIDForPrepareWrite": "0100/0108\n0200/0208",
            "BlockSizeInfo": "0:1x1",
            "CPUIDNo": "0",
            "ShrinkFlag": "1",
            "FlagToReceiveRespForFinish": "0"
            if module == "TCUWCanPowerTrainFlashWriter.dll"
            else "1",
            "FlagToNonVerifyProcess": str(int(no_verify)),
        }
        if extra_values:
            values.update(extra_values)
        catalogs = {
            "1CAN.ini": table(tuple(values), [tuple(values.values())]),
            "Parameter.ini": table(
                (
                    "ParamFileKeySystemProtocolMicon",
                    "FlagToReceiveRespForFinish",
                    "FlagToDoIGOFFONAtCPUTypeChange",
                ),
                [("1CAN", "1", "0")],
            ),
        }
        if two_cpu:
            for cpu_type in ("1", "2"):
                row = dict(values, ParamFileKeySystemProtocolMicon="1CAN" + cpu_type)
                catalogs["1CAN" + cpu_type + ".ini"] = table(
                    tuple(row), [tuple(row.values())]
                )
            catalogs["Parameter.ini"] = table(
                (
                    "ParamFileKeySystemProtocolMicon",
                    "FlagToReceiveRespForFinish",
                    "FlagToDoIGOFFONAtCPUTypeChange",
                ),
                [("1CAN1", "0", "0"), ("1CAN2", "1", "1")],
            )
        if values.get("AlternateCPUType"):
            alternate_type = values["AlternateCPUType"]
            alternate = dict(
                values,
                ParamFileKeySystemProtocolMicon="1CAN" + alternate_type,
                ShrinkFlag="1",
                AlternateCPUType="",
            )
            catalogs["1CAN" + alternate_type + ".ini"] = table(
                tuple(alternate), [tuple(alternate.values())]
            )
            catalogs["Parameter.ini"] = table(
                ("ParamFileKeySystemProtocolMicon", "FlagToReceiveRespForFinish"),
                [("1CAN", "0"), ("1CAN" + alternate_type, "1")],
            )
        selection = bind_native_parameter2026(
            container,
            catalogs,
            "write",
            encoded=False,
        )
        from scripts.programming_2026_raw import POWERTRAIN, bind_powertrain_context

        binder = bind_powertrain_context if module == POWERTRAIN else bind_solar_context
        return binder(
            container,
            1,
            (),
            selection,
            identify_native_module(
                "0a11170ac1b6b14bf387164ada2f5f2f6ab93e084a341affa5794164d79e3a82"
                if module == POWERTRAIN
                else "9d14c7bb3fd668e2d6cd53908eddfab0300926f7c41442f8e5e4798137b9e636",
                module,
            ),
            {},
            {},
        )

    def run_solar(self, no_verify=False, fault=None, context=None):
        from scripts.programming_2026_raw import run_solar

        context = context or self.context(no_verify)
        address = b"\0\0\x01\x08"
        ack, status = address + b"\x3c", address + b"\0"
        memory = address + bytes.fromhex("0000000003ff0100") + b"\0"
        replies = [ack, address + b"ID", ack, memory, ack]
        replies += [ack, ack, status, ack]
        replies += [ack, ack, ack, status, ack]
        replies += [ack, ack, status, ack]
        if not no_verify:
            replies += [ack] + [ack, ack, status, ack] * 4
        replies += [ack]
        self.replies = replies
        self.delivered = []
        self.events, self.observations = [], []

        def action(event, remaining):
            self.assertGreater(remaining, 0)
            self.events.append(event)
            if fault:
                fault(event)
            name = event["operation"]
            if name == "start_flow_control_filter":
                return 7
            if name == "get_timeout":
                return 100
            if name == "write_messages":
                return 1
            if name == "read_specified_can_message":
                result = self.replies.pop(0)
                self.delivered.append(result)
                return result
            return None

        return run_solar(
            context,
            NativeRuntime2026(action, clock=lambda: 0),
            notify=lambda *value: self.observations.append(value),
        )

    def test_actual_import_archive_geometry_programming_and_finish_pair(self):
        result = self.run_solar()
        self.assertEqual(result["state"], "write_completed")
        self.assertEqual(
            (result["native_return"], result["native_success"]), (True, None)
        )
        self.assertEqual(result["counts"], (2048,))
        self.assertEqual(result["percentages"], (100,))
        self.assertFalse(self.replies)
        writes = [
            event["data"]
            for event in self.events
            if event["operation"] == "write_messages"
        ]
        self.assertEqual(writes[-1], b"\0\0\x02\0\x80")
        self.assertIn(b"\0\0\x01\0\x26\0\0\0\0", writes)
        self.assertEqual(
            self.events[-1], {"operation": "set_timeout", "milliseconds": 100}
        )

    def test_actual_import_solar_over_typed_j2534_literal_wire(self):
        from scripts.j2534_2026 import J2534Device2026, NativeMessage
        from scripts.programming_2026_raw import run_solar
        from tests.test_j2534_2026 import Provider

        self.run_solar()
        replies = iter(self.delivered)
        expected_writes, batches = [], []
        for event in self.events:
            if event["operation"] == "write_messages":
                expected_writes.append(event["data"])
                batches.append((NativeMessage(6, event["data"][:4], rx_status=9),))
            elif event["operation"] == "read_specified_can_message":
                reply = next(replies)
                if event["frame"] == 1:
                    batches.append((NativeMessage(6, event["address"], rx_status=2),))
                batches.append((NativeMessage(6, reply),))
        for fail_write, two_cpu in (
            (False, False),
            (True, False),
            (False, True),
            (True, True),
        ):
            provider = Provider()
            provider.reads = batches[:]
            if fail_write:
                from scripts.j2534_2026 import PrimitiveResult

                provider.responses["passthru_write"] = PrimitiveResult(status=16)
            device = J2534Device2026(
                provider, clock=lambda: 0, background_workers=False
            )
            device.open()
            device.connect(6)
            result = run_solar(
                self.context(two_cpu=two_cpu),
                NativeRuntime2026(device.primitive, clock=lambda: 0),
            )
            self.assertEqual(
                result["state"], "write_failed" if fail_write else "write_completed"
            )
            if not fail_write:
                writes = [
                    e["messages"][0].data
                    for e, _ in provider.calls
                    if e["operation"] == "passthru_write"
                ]
                self.assertEqual(writes, expected_writes)
                self.assertFalse(provider.reads)
            self.assertEqual(device.filters, [])
            device.disconnect()
            device.close()

    def test_imported_mixed_cpu_next_flag_uses_global_next_cpu_row(self):
        result = self.run_solar(context=self.context(two_cpu=True))
        self.assertTrue(result["native_return"])
        self.assertEqual(result["percentages"], (100, 0))
        self.assertEqual(result["counts"][1], 0)
        self.assertNotIn(("cpu_change_without_ig",), self.observations)

    def test_no_verify_native_total_denominator_and_inverify_retained(self):
        result = self.run_solar(True)
        self.assertEqual((result["counts"], result["percentages"]), ((1024,), (100,)))
        self.assertFalse(self.replies)
        writes = [
            e["data"][4:] for e in self.events if e["operation"] == "write_messages"
        ]
        self.assertIn(b"\x48\0\0\0\0", writes)
        self.assertNotIn(b"\x16\0\0\0\0", writes)

    def test_native_write_fault_resets_arrays_and_restores_timeout(self):
        def fault(event):
            if event["operation"] == "write_messages" and event["data"][4:] == b"\x41":
                raise NativeTransportError(16)

        result = self.run_solar(fault=fault)
        self.assertEqual(result["native_error_code"], 13)
        self.assertEqual(result["driver_error_code"], 16)
        self.assertEqual(result["counts"], (0,))
        self.assertTrue(result["retry_password"])
        self.assertEqual(
            self.events[-1], {"operation": "set_timeout", "milliseconds": 100}
        )


class PowerTrainTests(unittest.TestCase):
    def test_actual_import_shared_writer_blankcheck_and_final_ack(self):
        from scripts.programming_2026_raw import POWERTRAIN, run_powertrain

        helper = SolarTests()
        context = helper.context(module=POWERTRAIN)
        helper.run_solar()
        replies = helper.delivered[:]
        events = []

        def action(event, remaining):
            events.append(event)
            name = event["operation"]
            if name == "get_timeout":
                return 100
            if name == "start_flow_control_filter":
                return 9
            if name == "write_messages":
                return 1
            if name == "read_specified_can_message":
                return replies.pop(0)
            return None

        result = run_powertrain(context, NativeRuntime2026(action, clock=lambda: 0))
        self.assertEqual(
            (result["state"], result["counts"], result["percentages"]),
            ("write_completed", (2048,), (100,)),
        )
        self.assertFalse(replies)
        writes = [
            event["data"] for event in events if event["operation"] == "write_messages"
        ]
        self.assertIn(b"\0\0\x01\0\x36\0\0\0\0", writes)
        self.assertNotIn(b"\0\0\x01\0\x26\0\0\0\0", writes)
        self.assertEqual(writes[-1], b"\0\0\x02\0\x80")
        from scripts.j2534_2026 import J2534Device2026, NativeMessage, PrimitiveResult
        from tests.test_j2534_2026 import Provider

        batches, delivered = [], iter(helper.delivered)
        for event in events:
            if event["operation"] == "write_messages":
                batches.append((NativeMessage(6, event["data"][:4], rx_status=9),))
            elif event["operation"] == "read_specified_can_message":
                if event["frame"] == 1:
                    batches.append((NativeMessage(6, event["address"], rx_status=2),))
                batches.append((NativeMessage(6, next(delivered)),))
        for fail in (False, True):
            provider = Provider()
            provider.reads = batches[:]

            def raw(event, remaining, fail=fail, provider=provider):
                if (
                    fail
                    and event["operation"] == "passthru_write"
                    and event["messages"][0].data[4:] == b"\x41"
                ):
                    return PrimitiveResult(status=16)
                return provider(event, remaining)

            device = J2534Device2026(raw, clock=lambda: 0, background_workers=False)
            device.open()
            device.connect(6)
            result = run_powertrain(
                context,
                NativeRuntime2026(
                    device.primitive, clock=lambda: 0, native_cancelled=lambda: False
                ),
            )
            self.assertEqual(
                result["state"], "write_failed" if fail else "write_completed"
            )
            self.assertEqual(device.filters, [])
            if not fail:
                self.assertFalse(provider.reads)
                self.assertEqual(
                    [
                        event["messages"][0].data
                        for event, _ in provider.calls
                        if event["operation"] == "passthru_write"
                    ],
                    writes,
                )
            device.disconnect()
            device.close()

    def test_powertrain_zero_memory_requeries_and_alternate_load_maps_native10(self):
        from scripts.programming_2026_raw import POWERTRAIN, run_powertrain

        helper = SolarTests()
        helper.run_solar()
        baseline = helper.delivered
        for shrink, alternate, expected in (
            ("1", "", "write_completed"),
            ("0", "", "write_failed"),
            ("0", "2", "write_completed"),
        ):
            context = helper.context(
                module=POWERTRAIN,
                extra_values={
                    "32BHFlag": "1",
                    "ShrinkFlag": shrink,
                    "AlternateCPUType": alternate,
                },
            )
            address = b"\0\0\x01\x08"
            replies = (
                baseline[:2]
                + [address + b"\x3c", address + bytes(9), address + b"\x3c"]
                + baseline[2:]
            )
            events = []

            def action(event, _remaining, replies=replies, events=events):
                events.append(event)
                name = event["operation"]
                if name == "get_timeout":
                    return 100
                if name == "start_flow_control_filter":
                    return 9
                if name == "write_messages":
                    return 1
                if name == "read_specified_can_message":
                    return replies.pop(0)
                return None

            result = run_powertrain(context, NativeRuntime2026(action, clock=lambda: 0))
            self.assertEqual(result["state"], expected)
            if expected == "write_completed":
                if alternate:
                    self.assertEqual(result["cpu_type_updates"], {"0": "2"})
                    self.assertEqual(result["selected_parameter_cpu_type"], "2")
                self.assertEqual(
                    sum(
                        e["operation"] == "write_messages" and e["data"][4:] == b"\x76"
                        for e in events
                    ),
                    2,
                )
                self.assertFalse(replies)
            else:
                self.assertEqual(result["native_error_code"], 10)
            self.assertEqual(
                events[-1], {"operation": "set_timeout", "milliseconds": 100}
            )


class ReproStdTests(unittest.TestCase):
    def context(
        self,
        operation="write",
        *,
        method="00",
        empty_delta=False,
        empty_routine=False,
        raw_fields=None,
        gateway=None,
        can_ids="0100/0108",
        observations=None,
    ):
        from scripts.calibration_2026 import parse_cuw_2026
        from scripts.demo_calibration import table
        from scripts.programming_2026_common import bind_native_parameter2026
        from scripts.programming_2026_raw import (
            REPRO_PREPARE,
            REPRO_WRITE,
            bind_repro_context,
        )
        from tests.test_calibration_2026 import cuw, logical_text

        text = (
            logical_text(209, method=method, routine=empty_routine)
            .replace("NumberOfGateway=1", "NumberOfGateway=0")
            .replace("[Node01]", "[Node01]\nDiagID=0100")
        )
        if raw_fields:
            text = (
                text.replace(
                    "StartAddress=00001000", "StartAddress=" + raw_fields["address"]
                )
                .replace("Length=00000004", "Length=" + raw_fields["length"])
                .replace("CMAC=" + "44" * 64, "CMAC=" + raw_fields["cmac"])
                .replace("[ReproData101]", "[ReproData101]\nCRC=" + raw_fields["crc"])
            )
        if empty_routine:
            text = text.replace(
                "[EraseAndReproRoutine101]\nStartAddress=00002000\nLength=00000004",
                "[EraseAndReproRoutine101]\nStartAddress=00002000\nLength=00000000\nCMAC="
                + "66" * 64,
            )
        if gateway is not None:
            gateway_ids = (gateway,) if isinstance(gateway, str) else gateway
            text = text.replace(
                "NumberOfGateway=0",
                "NumberOfGateway="
                + str(len(gateway_ids))
                + "\n"
                + "\n".join(
                    f"{index:02}_GatewayDiagID={identifier}"
                    for index, identifier in enumerate(gateway_ids, 1)
                ),
            )
        if method == "08":
            text = text.replace("[ReproData101]", "[DeltaReproData101]")
        if empty_delta:
            text = text.replace("Length=00000004", "Length=00000000")
        container = parse_cuw_2026(cuw(text, () if empty_delta else (b"DATA",)))
        name = REPRO_WRITE if operation == "write" else REPRO_PREPARE
        suffix = "FlashWrite" if operation == "write" else "PrepareWrite"
        values = {
            "ParamFileKeySystemProtocolMicon": "P5-Unified03",
            "DLLFileNameFor" + suffix: name,
            "GetCANIDFunctionNameFor" + suffix: "GetCanIDsFromParamForPrepareWrite",
            "CanIDForPrepareWrite": can_ids,
        }
        selection = bind_native_parameter2026(
            container,
            {"P5-Unified03.ini": table(tuple(values), [tuple(values.values())])},
            operation,
            encoded=False,
        )
        hashes = {
            REPRO_WRITE: "23c24339c4ee973a6edd9aa41dbef7d5d1bdbbf4db090cb075ca3369362940a0",
            REPRO_PREPARE: "de0e28b606776768ddbb0f2606200b2da39399df5d524c2dd1779bf294d77bca",
        }
        return bind_repro_context(
            container,
            1,
            (),
            selection,
            identify_native_module(hashes[name], name),
            {"tester_info": bytes(32)} if operation == "write" else {},
            observations or {},
        )

    def run_write(self, fault=None, context=None):
        from scripts.programming_2026_raw import run_repro_write

        context = context or self.context()
        replies = iter(
            (
                b"\x6e\x02\x02",
                b"\x6e\x02\x20",
                b"\x6e\x02\x30",
                b"\x71\x01\xff\0",
                b"\x74\x10\6",
                b"\x76\1",
                b"\x77",
                b"\x71\x01\x10\xf6",
                b"\x51\1",
            )
        )
        self.events = []
        self.delivered = []

        def action(event, remaining):
            self.events.append(event)
            if fault:
                fault(event)
            name = event["operation"]
            if name == "get_timeout":
                return 100
            if name == "get_send_timeout":
                return 500
            if name == "get_system_time":
                return (2026, 10, 2, 20, 12, 0, 0, 0)
            if name == "start_flow_control_filter":
                return 4
            if name == "write_messages":
                return 1
            if name == "read_specified_can_message":
                value = event["address"] + next(replies)
                self.delivered.append(value)
                return value
            return None

        result = run_repro_write(context, NativeRuntime2026(action, clock=lambda: 0))
        return result

    def test_actual_import_logical_write_fingerprint_erase_transfer_verify_reset(self):
        result = self.run_write()
        self.assertEqual(
            (result["state"], result["percentages"]), ("write_completed", ((0, 100),))
        )
        writes = [
            e["data"][4:] for e in self.events if e["operation"] == "write_messages"
        ]
        self.assertEqual(writes[0], b"\x2e\x02\x02" + bytes.fromhex("33" * 16))
        self.assertIn(b"\x34\1\x44" + bytes.fromhex("0000100000000004"), writes)
        self.assertIn(b"\x36\1DATA", writes)
        self.assertEqual(writes[-4], b"\x11\1")
        self.assertEqual(writes[-3:], [b"\x10\x81", b"\xfe\x10\x81", b"\x10\x81"])
        self.assertEqual(
            self.events[-2:],
            [
                {"operation": "stop_filter", "identifier": 4},
                {"operation": "set_history_enabled", "enabled": True},
            ],
        )

    def test_repro_native_fault_resets_node_progress_and_preserves_history_enable(self):
        def fault(event):
            if event["operation"] == "write_messages" and event["data"][4] == 0x36:
                raise NativeTransportError(16)

        result = self.run_write(fault)
        self.assertEqual(
            (
                result["native_return"],
                result["counts"],
                result["percentages"],
                result["error_kind"],
            ),
            (False, ((0, 0),), ((0, 0),), 2),
        )
        self.assertFalse(result["recovery_needed"])
        history = [
            event["enabled"]
            for event in self.events
            if event["operation"] == "set_history_enabled"
        ]
        self.assertEqual(history, [False, True])
        self.assertEqual(self.events[-1], {"operation": "stop_sync_periodic"})

    def test_actual_repro_import_through_typed_j2534_positive_and_transfer_fault(self):
        from scripts.j2534_2026 import J2534Device2026, NativeMessage, PrimitiveResult
        from scripts.programming_2026_raw import run_repro_write
        from tests.test_j2534_2026 import Provider

        self.run_write()
        expected_writes, batches = [], []
        replies = iter(self.delivered)
        for event in self.events:
            if event["operation"] == "write_messages":
                expected_writes.append(event["data"])
                batches.append((NativeMessage(6, event["data"][:4], rx_status=9),))
            elif event["operation"] == "read_specified_can_message":
                batches.append((NativeMessage(6, next(replies)),))
        for fail in (None, "transfer", "cleanup"):
            provider = Provider()
            provider.reads = batches[:]
            provider.responses["get_system_time"] = PrimitiveResult(
                value=(2026, 10, 2, 20, 12, 0, 0, 0)
            )

            def raw(operation, remaining, fail=fail, provider=provider):
                if (
                    fail == "transfer"
                    and operation["operation"] == "passthru_write"
                    and operation["messages"][0].data[4] == 0x36
                ):
                    return PrimitiveResult(status=16)
                if (
                    fail == "cleanup"
                    and operation["operation"] == "passthru_stop_filter"
                ):
                    return PrimitiveResult(status=9)
                return provider(operation, remaining)

            device = J2534Device2026(raw, clock=lambda: 0, background_workers=False)
            device.open()
            device.connect(6)
            result = run_repro_write(
                self.context(), NativeRuntime2026(device.primitive, clock=lambda: 0)
            )
            self.assertEqual(
                result["state"],
                "write_failed" if fail == "transfer" else "write_completed",
            )
            if fail != "transfer":
                self.assertFalse(provider.reads)
                self.assertEqual(
                    [
                        event["messages"][0].data
                        for event, _ in provider.calls
                        if event["operation"] == "passthru_write"
                    ],
                    expected_writes,
                )
            self.assertEqual(result["cleanup_failed"], fail == "cleanup")
            self.assertEqual(bool(device.filters), fail == "cleanup")
            if fail == "cleanup":
                self.assertTrue(result["native_return"])
                device.provider = provider
                for identifier in tuple(device.filters):
                    device.stop_filter(identifier)
            device.disconnect()
            device.close()

    def test_actual_import_zero_and_raw_width_geometry_transfer_and_verify(self):
        from scripts.j2534_2026 import J2534Device2026, NativeMessage, PrimitiveResult
        from scripts.programming_2026_raw import run_repro_write
        from tests.test_j2534_2026 import Provider

        for case in ("zero_whole", "zero_routine", "short", "wide", "short_block"):
            routine = case == "zero_routine"
            with self.subTest(case=case):
                provider = Provider()
                provider.responses["get_system_time"] = PrimitiveResult(
                    value=(2026, 10, 2, 20, 12, 0, 0, 0)
                )

                def raw(operation, remaining, provider=provider, case=case):
                    if operation["operation"] == "passthru_write":
                        data = operation["messages"][0].data
                        payload = data[4:]
                        provider.reads.append(
                            (NativeMessage(6, data[:4], rx_status=9),)
                        )
                        if data[:4] == bytes.fromhex("00000100"):
                            if payload[0] == 0x2E:
                                reply = b"\x6e" + payload[1:3]
                            elif payload[0] == 0x34:
                                reply = (
                                    b"\x74\x20\x06"
                                    if case == "short_block"
                                    else b"\x74\x10\x06"
                                )
                            elif payload[0] == 0x36:
                                reply = b"\x76" + payload[1:2]
                            else:
                                reply = bytes((payload[0] + 0x40,)) + payload[1:4]
                            provider.reads.append(
                                (NativeMessage(6, bytes.fromhex("00000108") + reply),)
                            )
                    return provider(operation, remaining)

                device = J2534Device2026(raw, clock=lambda: 0, background_workers=False)
                device.open()
                device.connect(6)
                context = self.context(
                    method="01" if routine else "00",
                    empty_delta=case == "zero_whole",
                    empty_routine=routine,
                    raw_fields={
                        "address": "1000" if case == "short" else "010203040506",
                        "length": "04",
                        "cmac": "bb",
                        "crc": "aa",
                    }
                    if case in ("short", "wide")
                    else None,
                )
                result = run_repro_write(
                    context, NativeRuntime2026(device.primitive, clock=lambda: 0)
                )
                self.assertTrue(result["native_return"])
                writes = [
                    event["messages"][0].data[4:]
                    for event, _ in provider.calls
                    if event["operation"] == "passthru_write"
                ]
                if case == "short_block":
                    self.assertIn(bytes.fromhex("3401440000100000000004"), writes)
                    self.assertIn(b"\x36\x01DATA", writes)
                    self.assertFalse(device.filters)
                    device.disconnect()
                    device.close()
                    continue
                if case in ("short", "wide"):
                    expected_bounds = bytes.fromhex(
                        "1000000004000000" if case == "short" else "0102030404060000"
                    )
                    self.assertIn(b"\x34\x01\x44" + expected_bounds, writes)
                    self.assertIn(
                        b"\x31\x01\x10\xf6\x44"
                        + expected_bounds
                        + bytes.fromhex("04aa0000000010bb")
                        + bytes(15),
                        writes,
                    )
                    self.assertFalse(device.filters)
                    device.disconnect()
                    device.close()
                    continue
                zero_download = (
                    b"\x34\x01\x44"
                    + (0x2000 if routine else 0x1000).to_bytes(4, "big")
                    + bytes(4)
                )
                index = writes.index(zero_download)
                self.assertEqual(writes[index + 1], b"\x37")
                self.assertTrue(
                    writes[index + 2].startswith(
                        b"\x31\x01\x10\xf5" if routine else b"\x31\x01\x10\xf6"
                    )
                )
                self.assertFalse(
                    any(
                        payload.startswith(b"\x36")
                        for payload in writes[index + 1 : index + 3]
                    )
                )
                self.assertFalse(device.filters)
                device.disconnect()
                device.close()

    def test_dh_dispatch_uses_first_gateway_and_entire_identifier(self):
        for gateway in ("86", ("0001", "0786")):
            with self.subTest(gateway=gateway):
                result = self.run_write(context=self.context(gateway=gateway))
                self.assertTrue(result["native_return"])
                writes = [
                    event["data"]
                    for event in self.events
                    if event["operation"] == "write_messages"
                ]
                self.assertFalse(
                    any(data.startswith(bytes.fromhex("00000786")) for data in writes)
                )

    def test_imported_smc_end_scope_typed_faults_preserve_native_success(self):
        from scripts.j2534_2026 import J2534Device2026, NativeMessage, PrimitiveResult
        from scripts.programming_2026_raw import run_repro_write
        from tests.test_j2534_2026 import Provider

        for fault in (None, b"\x22\x10\x05", b"\x31\x02\xc0\x01\x00"):
            with self.subTest(fault=fault):
                provider = Provider()
                provider.responses["get_system_time"] = PrimitiveResult(
                    value=(2026, 10, 2, 20, 12, 0, 0, 0)
                )

                def raw(operation, remaining, provider=provider, fault=fault):
                    if operation["operation"] == "passthru_write":
                        data = operation["messages"][0].data
                        payload = data[4:]
                        if payload == fault:
                            return PrimitiveResult(status=16)
                        provider.reads.append(
                            (NativeMessage(6, data[:4], rx_status=9),)
                        )
                        if data[:4] == bytes.fromhex("00000100"):
                            if payload[0] == 0x2E:
                                reply = b"\x6e" + payload[1:3]
                            elif payload[0] == 0x34:
                                reply = b"\x74\x10\x06"
                            elif payload[0] == 0x36:
                                reply = b"\x76" + payload[1:2]
                            else:
                                reply = bytes((payload[0] + 0x40,)) + payload[1:4]
                            provider.reads.append(
                                (NativeMessage(6, bytes.fromhex("00000108") + reply),)
                            )
                        elif data[:4] == bytes.fromhex("00000751"):
                            reply = {
                                b"\x10\x01": b"\x50\x01" + bytes(4),
                                b"\x22\x10\x05": b"\x62\x10\x05\x01",
                                b"\x31\x02\xc0\x01\x00": b"\x71\x02\xc0\x01",
                            }[payload]
                            provider.reads.append(
                                (NativeMessage(6, bytes.fromhex("00000761") + reply),)
                            )
                    return provider(operation, remaining)

                device = J2534Device2026(raw, clock=lambda: 0, background_workers=False)
                device.open()
                device.connect(6)
                result = run_repro_write(
                    self.context(gateway="0751"),
                    NativeRuntime2026(
                        device.primitive,
                        clock=lambda: 0,
                        native_cancelled=lambda: False,
                    ),
                )
                self.assertTrue(result["native_return"])
                self.assertFalse(result["cleanup_failed"])
                writes = [
                    event["messages"][0].data[4:]
                    for event, _ in provider.calls
                    if event["operation"] == "passthru_write"
                ]
                if fault != b"\x22\x10\x05":
                    self.assertIn(b"\x22\x10\x05", writes)
                if fault is None:
                    self.assertIn(b"\x31\x02\xc0\x01\x00", writes)
                self.assertFalse(device.filters)
                device.disconnect()
                device.close()

    def test_imported_delta_verification_and_empty_delta_skip_over_typed_driver(self):
        from scripts.j2534_2026 import J2534Device2026, NativeMessage, PrimitiveResult
        from scripts.programming_2026_raw import run_repro_write
        from tests.test_j2534_2026 import Provider

        for empty in (False, True):
            with self.subTest(empty=empty):
                provider = Provider()
                expected = [b"\x6e\x02\x02", b"\x6e\x02\x20", b"\x6e\x02\x30"]
                if not empty:
                    expected += [
                        b"\x74\x10\x06",
                        b"\x76\x01",
                        b"\x77",
                        b"\x71\x01\x10\xf6",
                    ]
                expected += [b"\x51\x01"]
                responses = iter(expected)
                provider.responses["get_system_time"] = PrimitiveResult(
                    value=(2026, 10, 2, 20, 12, 0, 0, 0)
                )

                def raw(operation, remaining, provider=provider, responses=responses):
                    if operation["operation"] == "passthru_write":
                        message = operation["messages"][0]
                        provider.reads.append(
                            (NativeMessage(6, message.data[:4], rx_status=9),)
                        )
                        if message.data[:4] == bytes.fromhex("00000100"):
                            provider.reads.append(
                                (
                                    NativeMessage(
                                        6, bytes.fromhex("00000108") + next(responses)
                                    ),
                                )
                            )
                    return provider(operation, remaining)

                device = J2534Device2026(raw, clock=lambda: 0, background_workers=False)
                device.open()
                device.connect(6)
                result = run_repro_write(
                    self.context(method="08", empty_delta=empty),
                    NativeRuntime2026(device.primitive, clock=lambda: 0),
                )
                self.assertTrue(result["native_return"])
                writes = [
                    event["messages"][0].data[4:]
                    for event, _ in provider.calls
                    if event["operation"] == "passthru_write"
                ]
                self.assertEqual(
                    any(payload.startswith(b"\x34\x21") for payload in writes),
                    not empty,
                )
                self.assertEqual(
                    any(payload.startswith(b"\x31\x01\x10\xf6") for payload in writes),
                    not empty,
                )
                self.assertFalse(
                    any(payload.startswith(b"\x31\x01\xff\x00") for payload in writes)
                )
                self.assertEqual(list(responses), [])
                self.assertFalse(device.filters)
                device.disconnect()
                device.close()


class ReproPrepareTests(unittest.TestCase):
    def run_prepare(
        self,
        fault=None,
        cancelled=lambda: False,
        context=None,
        gateway_node=0,
        private_client=None,
        dh=False,
    ):
        from scripts.programming_2026_common import SecretInfoClient
        from scripts.programming_2026_raw import run_repro_prepare

        context = context or ReproStdTests().context("prepare")
        client = private_client or SecretInfoClient(
            b"authored",
            tuple((n, b"fixture" if n == 0 else b"") for n in range(64)),
            "authored-fixture",
        )
        from unittest.mock import patch

        import scripts.programming_2026_common as common

        # Authored test capability; production constructors reject unissued clients.
        if private_client is None:
            issuer = patch.dict(common._SECRET_INFO_CLIENTS, {id(client): client})
            issuer.start()
            self.addCleanup(issuer.stop)
            client.authorize(b"authored")
        self.events = []
        self.delivered = []
        self.context, self.client = context, client
        last = [b""]

        def action(event, remaining):
            self.events.append(event)
            if fault:
                fault(event)
            name = event["operation"]
            if name == "get_timeout":
                return 100
            if name == "is_sending_sync_periodic":
                return False
            if name == "start_flow_control_filter":
                return 4
            if name == "write_messages":
                last[0] = event["data"]
                return 1
            if name == "read_specified_can_message":
                data = last[0]
                if dh and data[:4] in (
                    bytes.fromhex("00000786"),
                    bytes.fromhex("000006f1"),
                ):
                    request = data[4:]
                    if request.startswith(b"\x27\x02"):
                        payload = b"\x67\x02\x34"
                    else:
                        payload = {
                            b"\x3e\x00": b"\x7e\x00",
                            b"\x10\x5f": b"\x50\x02",
                            b"\x10\x89": b"\x50\x89",
                            b"\x10\x87": b"\x50\x87",
                            b"\x27\x01\x03": b"\x67\x01" + bytes(range(16)) + b"\xaa",
                        }[request]
                elif data.endswith(bytes.fromhex("222103")):
                    payload = bytes.fromhex("6221030000")
                elif data.endswith(b"\x10\2"):
                    payload = b"\x50\2" + bytes(4)
                elif data.endswith(b"\x27\x51"):
                    payload = b"\x67\x51" + bytes(16)
                elif b"\x27\x52" in data:
                    payload = b"\x67\x52\x34"
                elif data.endswith(b"\x27\1"):
                    payload = b"\x67\1" + bytes(16)
                elif b"\x27\2" in data:
                    payload = b"\x67\2"
                else:
                    raise AssertionError("Unexpected native request: " + data.hex())
                value = event["address"] + payload
                self.delivered.append(value)
                return value
            if name == "calculate_central_gateway_key":
                return b"C" * 16
            if name == "decrypt_secret_info":
                self.assertEqual(event["service_auth_key"], bytes.fromhex("11" * 16))
                return b"I" * 16
            if name == "calculate_security_key":
                self.assertEqual(event["seed"], bytes(16))
                return b"K" * 16
            return None

        runtime = NativeRuntime2026(
            action, clock=lambda: 0, native_cancelled=lambda: False, cancelled=cancelled
        )
        dh_gateway = None
        if dh:
            from scripts.programming_2026_dh import DHGateway2026

            dh_gateway = DHGateway2026(
                runtime,
                context.selection,
                identify_native_module(
                    "08fd3e36dfd7b7eab93d96076bedb809664ab8f18148d3589813ddb20164e619",
                    "TCUWDHUtils.dll",
                ),
                client,
            )
        result = run_repro_prepare(
            context,
            runtime,
            secret_info=client,
            gateway_node=gateway_node,
            dh_gateway=dh_gateway,
        )
        self.runtime = runtime
        return result

    def test_actual_import_preparation_broadcast_periodic_session_security_cleanup(
        self,
    ):
        result = self.run_prepare()
        runtime = self.runtime
        self.assertTrue(result["prepared"])
        self.assertEqual(
            (result["native_return"], result["native_success"]), (True, None)
        )
        writes = [
            event["data"]
            for event in self.events
            if event["operation"] == "write_messages"
        ]
        self.assertEqual(writes[0], bytes.fromhex("000007771083"))
        self.assertIn(bytes.fromhex("0000077ffe8582"), writes)
        self.assertIn(bytes.fromhex("18dbefe0288301"), writes)
        self.assertEqual(writes[-1], bytes.fromhex("000001002702") + b"K" * 16)
        self.assertEqual(self.events[-1], {"operation": "stop_filter", "identifier": 4})
        self.assertTrue(runtime.owns_resource("stop_sync_periodic"))
        self.assertEqual(runtime.close(), [])

    def test_preparation_native_fault_and_host_cancel_stop_periodic(self):
        def fault(event):
            if event["operation"] == "write_messages" and event["data"].endswith(
                b"\x10\2"
            ):
                raise NativeTransportError(16)

        result = self.run_prepare(fault)
        self.assertFalse(result["prepared"])
        self.assertEqual(
            (result["native_return"], result["native_success"]), (False, None)
        )
        self.assertEqual(
            (result["native_error_code"], result["driver_error_code"]), (1004, None)
        )
        self.assertFalse(self.runtime.owns_resource("stop_sync_periodic"))
        flag = [False]

        def cancel(event):
            if event["operation"] == "write_messages" and event["data"].endswith(
                b"\x10\2"
            ):
                flag[0] = True

        with self.assertRaises(InterruptedError):
            self.run_prepare(cancel, lambda: flag[0])
        self.assertEqual(self.events[-1], {"operation": "stop_sync_periodic"})

    def test_private_source_dh_gateway_auth_composes_imported_preparation(self):
        from tests.test_programming_2026_dh import dh_aes, native_secret_client

        def fault(event):
            if event["operation"] == "write_messages" and event[
                "data"
            ] == bytes.fromhex("000007a42105"):
                raise NativeTransportError(9)

        result = self.run_prepare(
            fault=fault,
            context=ReproStdTests().context("prepare", gateway="0786"),
            private_client=native_secret_client(),
            dh=True,
        )
        self.assertTrue(result["native_return"])
        self.assertEqual(result["dh_gateway_type"], 1)
        writes = [
            event["data"]
            for event in self.events
            if event["operation"] == "write_messages"
        ]
        self.assertIn(
            bytes.fromhex("000007862702") + dh_aes(1, bytes(range(16))), writes
        )
        self.assertTrue(self.runtime.owns_resource("stop_sync_periodic"))
        self.assertEqual(self.runtime.close(), [])

    def test_imported_central_gateway_native_retry_suppression_is_exact(self):
        from scripts.programming_2026_common import NativePassThruException2026

        for selected, retry, injected, expected in (
            (False, False, False, True),
            (False, True, True, False),
            (True, False, True, False),
            (True, True, True, True),
        ):
            with self.subTest(selected=selected, retry=retry, injected=injected):
                context = ReproStdTests().context(
                    "prepare",
                    gateway="07505F",
                    can_ids="07505f/07585f" if selected else "0100/0108",
                    observations={"native_retry_flag_964": retry},
                )

                def fault(event, injected=injected):
                    if (
                        injected
                        and event["operation"] == "write_messages"
                        and event["data"].endswith(b"\x27\x51")
                    ):
                        raise NativePassThruException2026(23, "authored gateway", 1)

                result = self.run_prepare(fault=fault, context=context, gateway_node=2)
                self.assertEqual(result["native_return"], expected)
                if not expected:
                    self.assertEqual(result["native_error_code"], 23)
                if expected:
                    self.runtime.close()

    def test_unissued_secret_fixture_is_rejected_by_production_boundary(self):
        from scripts.programming_2026_common import SecretInfoClient

        client = SecretInfoClient(
            b"authored", tuple((n, b"fixture") for n in range(64)), "authored"
        )
        with self.assertRaises(PermissionError):
            client.authorize(b"authored")

    def test_actual_import_prepare_over_typed_j2534_and_native_security_primitives(
        self,
    ):
        from scripts.j2534_2026 import J2534Device2026, NativeMessage, PrimitiveResult
        from scripts.programming_2026_raw import run_repro_prepare
        from tests.test_j2534_2026 import Provider

        self.run_prepare()
        replies = iter(self.delivered)
        expected, batches = [], []
        for event in self.events:
            if event["operation"] == "write_messages":
                expected.append(event["data"])
                batches.append((NativeMessage(6, event["data"][:4], rx_status=9),))
            elif event["operation"] == "read_specified_can_message":
                batches.append((NativeMessage(6, next(replies)),))
        self.runtime.close()
        for fail in (False, True):
            provider = Provider()
            provider.reads = batches[:]
            provider.responses["create_mutex"] = PrimitiveResult(value=7)
            provider.responses["local_time_ms"] = PrimitiveResult(value=0)

            def raw(event, remaining, provider=provider, fail=fail):
                if (
                    fail
                    and event["operation"] == "passthru_write"
                    and event["messages"][0].data.endswith(b"\x10\2")
                ):
                    return PrimitiveResult(status=16)
                return provider(event, remaining)

            device = J2534Device2026(raw, clock=lambda: 0, background_workers=False)
            device.open()
            device.connect(6)

            def dispatch(event, remaining, device=device):
                if event["operation"] == "decrypt_secret_info":
                    return b"I" * 16
                if event["operation"] == "calculate_security_key":
                    return b"K" * 16
                return device.primitive(event, remaining)

            runtime = NativeRuntime2026(
                dispatch,
                clock=lambda: 0,
                native_cancelled=lambda: False,
                cleanup_action=device.cleanup_primitive,
            )
            result = run_repro_prepare(self.context, runtime, secret_info=self.client)
            self.assertEqual(result["prepared"], not fail)
            if not fail:
                self.assertEqual(
                    [
                        event["messages"][0].data
                        for event, _ in provider.calls
                        if event["operation"] == "passthru_write"
                    ],
                    expected,
                )
                self.assertFalse(provider.reads)
            self.assertEqual(device.filters, [])
            self.assertEqual(runtime.close(), [])
            device.disconnect()
            device.close()


class NativeExportAllocationTests(unittest.TestCase):
    def test_all_six_exports_match_original_2026_manifest(self):
        from scripts.programming_2026_raw import IMPLEMENTED_EXPORTS

        rows = read_private_json(
            "analysis/evidence/no-car-29/owner-37-2026-exports.json"
        )
        selected = {
            row["name"]: tuple(sorted(row["callable_exports"]))
            for row in rows
            if row["name"] in IMPLEMENTED_EXPORTS
        }
        self.assertEqual(
            selected,
            {
                name: tuple(sorted(exports))
                for name, exports in IMPLEMENTED_EXPORTS.items()
            },
        )
        self.assertEqual((len(selected), sum(map(len, selected.values()))), (5, 6))


class NativeCleanupScopeTests(unittest.TestCase):
    def test_host_failure_identity_survives_cleanup_failure_without_native_outcome(
        self,
    ):
        for family in ("getter", "retry", "solar", "repro_write"):
            with self.subTest(family=family):
                original = OSError("authored primary provider failure")

                def fault(event, original=original):
                    if event["operation"] == "write_messages":
                        raise original
                    if event["operation"] in ("stop_filter", "disconnect"):
                        raise ValueError("authored cleanup contract failure")

                with self.assertRaises(OSError) as caught:
                    if family == "getter":
                        SoftwareInfoTests().run_context((), fault=fault)
                    elif family == "retry":
                        RetryTests().run_retry(fault=fault)
                    elif family == "solar":
                        SolarTests().run_solar(fault=fault)
                    else:
                        ReproStdTests().run_write(fault=fault)
                self.assertIs(caught.exception, original)
                self.assertTrue(
                    any("ValueError" in note for note in original.__notes__)
                )

    def test_native_stopfilter_scope_preserves_retry_solar_and_prepare_bool(self):
        from scripts.programming_2026_common import NativeJ2534Exception2026

        armed = [False]

        def fault(event):
            if event["operation"] == "write_messages" and event["data"].endswith(
                b"\x27\x02" + b"K" * 16
            ):
                armed[0] = True
            if event["operation"] == "stop_filter" and armed[0]:
                raise NativeJ2534Exception2026(9, "authored cleanup", 1)

        for family in ("retry", "solar", "prepare"):
            armed[0] = family != "prepare"
            with self.subTest(family=family):
                if family == "retry":
                    helper = RetryTests()
                    result = helper.run_retry(b32=True, fault=fault)
                elif family == "solar":
                    helper = SolarTests()
                    result = helper.run_solar(fault=fault)
                    self.assertEqual(
                        helper.events[-1],
                        {"operation": "set_timeout", "milliseconds": 100},
                    )
                else:
                    helper = ReproPrepareTests()
                    try:
                        result = helper.run_prepare(fault=fault)
                    finally:
                        helper.doCleanups()
                    self.assertTrue(
                        helper.runtime.owns_resource("stop_filter", identifier=4)
                    )
                self.assertTrue(result["native_return"])
                self.assertTrue(result["cleanup_failed"])
                self.assertEqual(result["cleanup_errors"], ((1, 9),))

    def test_getter_native_bs0_suppression_and_disconnect_outside_eh(self):
        from scripts.programming_2026_common import NativeJ2534Exception2026

        for operation in ("control_io", "disconnect"):
            with self.subTest(operation=operation):
                helper = SoftwareInfoTests()

                def fault(event, operation=operation):
                    if event["operation"] == operation and (
                        operation != "control_io" or event["parameters"] == ((0x1E, 0),)
                    ):
                        raise NativeJ2534Exception2026(9, "authored cleanup", 1)

                arguments = ((b"\x5a\x88\x00\x01", b"\x5a\x88\x01" + b"A" * 16),)
                if operation == "disconnect":
                    with self.assertRaises(NativeJ2534Exception2026):
                        helper.run_context(
                            *arguments,
                            context=helper.context(apgs_parking_assist_monitor=True),
                            fault=fault,
                        )
                else:
                    result = helper.run_context(
                        *arguments,
                        context=helper.context(apgs_parking_assist_monitor=True),
                        fault=fault,
                    )
                    self.assertTrue(result["native_success"])
                    self.assertTrue(result["cleanup_failed"])
                    self.assertEqual(result["cleanup_errors"], ((1, 9),))


if __name__ == "__main__":
    unittest.main()
