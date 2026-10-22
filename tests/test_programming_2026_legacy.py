import unittest
from dataclasses import replace
from typing import cast

from scripts.programming_2026_common import NativeException2026
from scripts.programming_2026_legacy import writing_error_dispose


class WritingErrorDisposeTests(unittest.TestCase):
    def test_native_reset_and_notification_order(self):
        counts, percentages, observed = [12, 34], [56, 78], []
        writing_error_dispose(
            1,
            counts,
            percentages,
            lambda field: observed.append((field, counts[:], percentages[:])),
        )
        self.assertEqual(
            observed,
            [("count", [12, 0], [56, 78]), ("percent", [12, 0], [56, 0])],
        )

    def test_first_callback_fault_stops_second_mutation(self):
        counts, percentages = [12], [56]

        def fail(_field):
            raise OSError("authored callback failure")

        with self.assertRaises(OSError):
            writing_error_dispose(0, counts, percentages, fail)
        self.assertEqual((counts, percentages), ([0], [56]))

    def test_second_callback_fault_propagates_after_both_mutations(self):
        counts, percentages = [12], [56]

        def fail(field):
            if field == "percent":
                raise InterruptedError("authored cancellation from observer")

        with self.assertRaises(InterruptedError):
            writing_error_dispose(0, counts, percentages, fail)
        self.assertEqual((counts, percentages), ([0], [0]))

    def test_malformed_context_rejected_before_mutation_or_callbacks(self):
        for index, counts, percentages in (
            (-1, [1], [2]),
            (True, [1], [2]),
            (1, [1], [2]),
            (0, [1], []),
            (0, [1], [True]),
            (0, [2**32], [2]),
            (0, [1] * 257, [2] * 257),
        ):
            with self.subTest(index=index, size=len(counts)):
                before = counts[:], percentages[:]
                events = []
                with self.assertRaises((TypeError, ValueError)):
                    writing_error_dispose(
                        index, counts, cast(list[int], percentages), events.append
                    )
                self.assertEqual((counts, percentages), before)
                self.assertEqual(events, [])


class P4SecurityTests(unittest.TestCase):
    def context(self, **changes):
        from scripts.calibration_catalog import Address
        from scripts.native_modules import identify_native_module
        from scripts.programming_2026_legacy import P4SecurityPowerTrainContext

        context = P4SecurityPowerTrainContext(
            identity=identify_native_module(
                "106a30d2f5ebf7b931c7088e233fa311d649dcaee1ca3e909c3e1a654b00d02e",
                "TCUWP4CanSecurityPowerTrainPrepareWriter.dll",
            ),
            target_metadata=(Address(b"\x01\x00", b"\x01\x08"),),
            ecu_auth_key=bytes(range(16)),
            service_auth_key=bytes(range(16, 32)),
            seed_wait_ms=2,
            key_wait_ms=3,
            mask_wait_ms=4,
        )
        return replace(context, **changes)

    def run_native(
        self,
        context=None,
        responses=None,
        fault=None,
        cancel=None,
        crypto=None,
        preowned=False,
        exported=False,
    ):
        from scripts.programming_2026_common import NativeRuntime2026
        from scripts.programming_2026_legacy import prepare_p4_security_powertrain

        context = context or self.context()
        clock = [0.0]
        events = []
        replies = iter(
            responses or (b"\x67\x01" + bytes(range(32, 48)), b"\x67\x02", b"\x50")
        )
        resources = []
        self.events, self.resources = events, resources

        def action(event, remaining):
            self.assertGreater(remaining, 0)
            events.append(event)
            if fault is not None:
                fault(event, events)
            operation = event["operation"]
            if operation == "start_flow_control_filter":
                identifier = 9 + len(resources)
                resources.append(identifier)
                return identifier
            if operation == "stop_filter":
                resources.remove(event["identifier"])
            if operation == "get_timeout":
                return 100
            if operation == "write_messages":
                return 1
            if operation == "read_specified_can_message":
                return event["address"] + next(replies)
            if operation == "wait":
                clock[0] += event["milliseconds"] / 1000
            return None

        runtime = NativeRuntime2026(
            action, clock=lambda: clock[0], cancelled=cancel or (lambda: False)
        )
        if preowned:
            runtime.own("disconnect")
            runtime.own("stop_periodic", identifier=7)
        self.runtime = runtime
        provider = crypto or (
            lambda seed, service: (
                self.assertEqual(
                    (seed, service), (bytes(range(32, 48)), bytes(range(16, 32)))
                )
                or bytes(range(48, 64))
            )
        )
        if exported:
            from scripts.programming_2026_legacy import _run_p4_security_powertrain_abi

            result = _run_p4_security_powertrain_abi(context, runtime, provider)
        else:
            result = prepare_p4_security_powertrain(context, runtime, provider)
        return result, events, resources

    def test_export_bool_and_native_exception_outputs(self):
        from scripts.programming import NativeTransportError
        from scripts.programming_2026_common import CommonResponseError

        result, _, _ = self.run_native(exported=True)
        self.assertIs(result["native_return"], True)
        self.assertIsNone(result["native_success"])
        for error, enum, driver, kind in (
            (CommonResponseError(18), 18, None, 1),
            (NativeTransportError(5), 1, 5, 1),
            (NativeException2026("authored native unknown"), None, None, None),
        ):

            def fault(event, _events, error=error):
                if event["operation"] == "write_messages":
                    raise error

            result, _, resources = self.run_native(fault=fault, exported=True)
            self.assertIs(result["native_return"], False)
            self.assertEqual(
                (
                    result["native_error_code"],
                    result["driver_error_code"],
                    result["error_kind"],
                ),
                (enum, driver, kind),
            )
            self.assertEqual(resources, [])
        with self.assertRaises(InterruptedError):
            self.run_native(cancel=lambda: True, exported=True)

    def test_export_host_fault_has_no_invented_native_bool(self):
        for failure in (OSError("host failure"), ValueError("host invalid value")):

            def fault(event, _events, failure=failure):
                if event["operation"] == "write_messages":
                    raise failure

            with self.assertRaises(type(failure)) as caught:
                self.run_native(fault=fault, exported=True)
            self.assertIs(caught.exception, failure)
            self.assertEqual(self.resources, [])

    def test_empty_native_address_vector_obeys_retry_flag_without_io(self):
        for retry in (False, True):
            result, events, resources = self.run_native(
                self.context(target_metadata=(), native_retry_flag_964=retry),
                exported=True,
            )
            self.assertIs(result["native_return"], retry)
            self.assertEqual(result["native_error_code"], None if retry else 17)
            self.assertEqual((events, resources), ([], []))

    def test_literal_native_wire_and_waits(self):
        result, events, resources = self.run_native()
        self.assertEqual(result["state"], "prepare_completed")
        self.assertFalse(result["programming_completed"])
        self.assertEqual(resources, [])
        self.assertEqual(
            [e["data"] for e in events if e["operation"] == "write_messages"],
            [
                b"\0\0\x01\x00\x27\x01" + bytes(range(16)),
                b"\0\0\x01\x00\x27\x02" + bytes(range(48, 64)),
                bytes.fromhex("00000720a027"),
                bytes.fromhex("00000720a027"),
                bytes.fromhex("00000720a027"),
                b"\0\0\x01\x00\x10\x02",
            ],
        )
        self.assertEqual(
            [e["milliseconds"] for e in events if e["operation"] == "wait"],
            [0, 2, 0, 3, 4, 4, 4, 0],
        )

    def test_unavailable_seed_and_explicit_retry_override(self):
        from scripts.programming_2026_common import CommonResponseError

        with self.assertRaises(CommonResponseError) as caught:
            self.run_native(responses=(b"\x7f\x27\x31",))
        self.assertEqual(caught.exception.code, 17)
        self.assertEqual(self.resources, [])
        result, events, resources = self.run_native(
            self.context(native_retry_flag_964=True), responses=(b"\x7f\x27\x31",)
        )
        self.assertTrue(result["native_retry_skip"])
        self.assertEqual(result["skipped_targets"], ((0, 23),))
        self.assertEqual(sum(e["operation"] == "write_messages" for e in events), 1)
        self.assertEqual(resources, [])

    def test_key_nrc35_maps_native1002(self):
        from scripts.programming_2026_common import CommonResponseError

        with self.assertRaises(CommonResponseError) as caught:
            self.run_native(
                responses=(b"\x67\x01" + bytes(range(32, 48)), b"\x7f\x27\x35")
            )
        self.assertEqual(caught.exception.code, 1002)
        self.assertEqual(self.resources, [])

    def test_short_seed_bad_crypto_and_every_primitive_failure_release_filters(self):
        from scripts.programming_2026_common import CommonResponseError

        with self.assertRaises(CommonResponseError) as caught:
            self.run_native(responses=(b"\x67\x01" + bytes(15),))
        self.assertEqual(caught.exception.code, 16)
        with self.assertRaises(ValueError) as caught:
            self.run_native(crypto=lambda _seed, _service: b"bad")
        self.assertEqual(self.resources, [])
        _, baseline, _ = self.run_native()
        for target in range(1, len(baseline) + 1):
            if baseline[target - 1]["operation"] == "stop_filter":
                continue

            def fault(_event, events, target=target):
                if len(events) == target:
                    raise OSError("authored primitive failure")

            with self.subTest(target=target), self.assertRaises(OSError) as caught:
                self.run_native(fault=fault)
            self.assertEqual(self.resources, [])

    def test_cancel_after_acquisition_releases_handle(self):
        cancelled = [False]

        def fault(event, _events):
            if event["operation"] == "start_flow_control_filter":
                cancelled[0] = True

        with self.assertRaises(InterruptedError):
            self.run_native(fault=fault, cancel=lambda: cancelled[0])
        self.assertEqual(self.resources, [])

    def test_cleanup_failure_cannot_return_complete(self):
        def fault(event, _events):
            if event["operation"] == "stop_filter":
                raise OSError("authored release failure")

        with self.assertRaises(OSError):
            self.run_native(fault=fault)

    def test_crypto_fault_never_becomes_unavailable_target(self):
        from scripts.programming import NativeTransportError

        def crypto(_seed, _service):
            raise NativeTransportError(9)

        with self.assertRaises(NativeTransportError):
            self.run_native(self.context(native_retry_flag_964=True), crypto=crypto)

    def test_imported_metadata_and_catalog_drive_bound_addresses_and_keys(self):
        from scripts.calibration_2026 import parse_cuw_2026
        from scripts.demo_calibration import table
        from scripts.programming_2026_common import bind_native_parameter2026
        from scripts.programming_2026_legacy import bind_native_context
        from tests.test_calibration_2026 import cuw

        metadata = (
            "[Format]\nVersion=6\n[Vehicle]\nNumberOfCalibration=1\nKindOfECU=1\nContactType=CAN\n"
            "ECUAuthKey="
            + bytes(range(16)).hex()
            + "\nServiceAuthKey="
            + bytes(range(16, 32)).hex()
            + "\n"
            "[CPU01]\nCPUType=1\nCPUImageName=authored.vbf\nLocationID=0108010000000720\n"
            "NumberOfTargets=1\n01_TargetCalibration=DEMO\n01_TargetData=12345678\n"
        )
        container = parse_cuw_2026(cuw(metadata, (bytes(1024),)))
        values = {
            "ParamFileKeySystemProtocolMicon": "1CAN1",
            "DLLFileNameForPrepareWrite": "TCUWP4CanSecurityPowerTrainPrepareWriter.dll",
            "GetCANIDFunctionNameForPrepareWrite": "GetCanIDsFromParamForPrepareWrite",
            "CanIDForPrepareWrite": "0100/0108",
            "WaitTimeAfterSeedData": "2",
            "WaitTimeAfterSeedKey": "3",
            "WaitTimeAfterDiagnosticMask": "4",
        }
        selection = bind_native_parameter2026(
            container,
            {"1CAN1.ini": table(tuple(values), [tuple(values.values())])},
            "prepare",
            encoded=False,
        )
        bound = bind_native_context(
            container, 1, ("DEMO",), selection, self.context().identity, {}, {}
        )
        from scripts.programming_2026_common import NativeRuntime2026
        from scripts.programming_2026_legacy import run_p4_security_powertrain

        forbidden_io = []
        guard_runtime = NativeRuntime2026(
            lambda event, remaining: forbidden_io.append(event)
        )
        for candidate in (replace(bound, target_metadata=()), self.context()):
            with self.assertRaises(ValueError):
                run_p4_security_powertrain(
                    candidate, guard_runtime, lambda seed, service: bytes(16)
                )
        self.assertEqual(forbidden_io, [])
        forged_values = dict(selection.values)
        forged_values["CanIDForPrepareWrite"] = ("0200/0208",)
        with self.assertRaises(ValueError):
            bind_native_context(
                container,
                1,
                ("DEMO",),
                replace(selection, values=forged_values),
                self.context().identity,
                {},
                {},
            )
        forged_rows = (
            tuple(
                ("0200/0208",) if header == "CanIDForPrepareWrite" else cell
                for header, cell in zip(selection.headers, selection.rows[0])
            ),
        )
        with self.assertRaises(ValueError):
            bind_native_context(
                container,
                1,
                ("DEMO",),
                replace(selection, rows=forged_rows),
                self.context().identity,
                {},
                {},
            )
        from scripts.j2534_2026 import NativeCommunicationAddress

        history_values = {
            **values,
            "GetCANIDFunctionNameForPrepareWrite": "GetCanIDsFromResultOfGetCID",
            "CanIDForGetCID": "0100/0108",
        }
        history_selection = bind_native_parameter2026(
            container,
            {
                "1CAN1.ini": table(
                    tuple(history_values), [tuple(history_values.values())]
                )
            },
            "prepare",
            encoded=False,
        )
        history_bound = bind_native_context(
            container,
            1,
            ("DEMO",),
            history_selection,
            self.context().identity,
            {},
            {
                "previous_addresses": (
                    NativeCommunicationAddress(b"\x01\x00", b"\x01\x08"),
                )
            },
        )
        self.assertEqual(history_bound, bound)
        empty_history_bound = bind_native_context(
            container, 1, ("DEMO",), history_selection, self.context().identity, {}, {}
        )
        self.assertEqual(empty_history_bound.target_metadata, ())
        empty_result, events, _ = self.run_native(empty_history_bound, exported=True)
        self.assertEqual(
            (empty_result["native_return"], empty_result["native_error_code"]),
            (False, 17),
        )
        self.assertEqual(events, [])
        with self.assertRaises(ValueError):
            bind_native_context(
                container,
                1,
                ("DEMO",),
                history_selection,
                self.context().identity,
                {},
                {"previous_addresses": bound.target_metadata},
            )
        self.assertEqual(bound, self.context())
        self.assertNotIn(bytes(range(16)).hex(), repr(bound))
        values["CanIDForPrepareWrite"] = "0100fe/0108fe"
        extended_selection = bind_native_parameter2026(
            container,
            {"1CAN1.ini": table(tuple(values), [tuple(values.values())])},
            "prepare",
            encoded=False,
        )
        extended = bind_native_context(
            container, 1, ("DEMO",), extended_selection, self.context().identity, {}, {}
        )
        self.assertTrue(extended.target_metadata[0].extended)
        self.assertEqual(extended.target_metadata[0].request, bytes.fromhex("0100fe"))
        _, extended_events, _ = self.run_native(context=extended)
        self.assertEqual(
            next(
                e
                for e in extended_events
                if e["operation"] == "start_flow_control_filter"
            )["request_address"],
            bytes.fromhex("00000100fe"),
        )
        self.assertEqual(
            next(e for e in extended_events if e["operation"] == "write_messages")[
                "data"
            ][:5],
            bytes.fromhex("00000100fe"),
        )
        from scripts.j2534_2026 import J2534Device2026, NativeMessage, PrimitiveResult
        from scripts.programming_2026_common import NativeRuntime2026
        from scripts.programming_2026_legacy import run_p4_security_powertrain

        native_reads, native_events = [], []
        answers = iter((b"\x67\x01" + bytes(range(32, 48)), b"\x67\x02", b"\x50"))
        request, response = bytes.fromhex("00000100fe"), bytes.fromhex("00000108fe")

        def provider(event, remaining):
            native_events.append(event)
            name = event["operation"]
            if name == "passthru_write":
                message = event["messages"][0]
                header = (
                    request if message.data.startswith(request) else message.data[:4]
                )
                native_reads.append(
                    PrimitiveResult(value=(NativeMessage(6, header, rx_status=9),))
                )
                if message.data.startswith(request):
                    native_reads.append(
                        PrimitiveResult(
                            value=(NativeMessage(6, response + next(answers)),)
                        )
                    )
                return PrimitiveResult(value=1)
            if name == "passthru_read":
                return native_reads.pop(0)
            if name in ("passthru_open", "passthru_connect", "passthru_start_filter"):
                return PrimitiveResult(value=0)
            return PrimitiveResult()

        device = J2534Device2026(provider, clock=lambda: 0, background_workers=False)
        device.open()
        device.connect(6)
        runtime = NativeRuntime2026(device.primitive, clock=lambda: 0)
        result = run_p4_security_powertrain(
            extended, runtime, lambda seed, service: bytes(16)
        )
        self.assertEqual(result["prepared_targets"], (0,))
        native_filter = next(
            e for e in native_events if e["operation"] == "passthru_start_filter"
        )
        self.assertEqual(
            (
                native_filter["mask"].data,
                native_filter["pattern"].data,
                native_filter["flow_control"].data,
            ),
            (b"\xff" * 5, response, request),
        )
        self.assertEqual(native_filter["pattern"].tx_flags, 0xC0)
        self.assertEqual(device.filters, [])
        self.assertTrue(device.connecting)
        for attachments, observations in (
            ({"ecu_auth_key": bytes(16)}, {}),
            ({}, {"memory_address": 0}),
            ({}, {"stage": "write"}),
            ({}, {"cpu_index": 1}),
        ):
            with self.subTest(observations=observations), self.assertRaises(ValueError):
                bind_native_context(
                    container,
                    1,
                    ("DEMO",),
                    selection,
                    self.context().identity,
                    attachments,
                    observations,
                )

    def test_deadline_and_native_transport_domains(self):
        from scripts.programming import NativeTransportError

        with self.assertRaises(TimeoutError):
            self.run_native(self.context(seed_wait_ms=60000))
        self.assertEqual(self.resources, [])

        def fault(event, _events):
            if event["operation"] == "read_specified_can_message":
                raise NativeTransportError(9)

        result, _events, resources = self.run_native(
            self.context(native_retry_flag_964=True), fault=fault
        )
        self.assertEqual(result["skipped_targets"], ((0, 22),))
        self.assertEqual(resources, [])

        def deadline(event, _events):
            if event["operation"] == "read_specified_can_message":
                raise TimeoutError("authored host deadline")

        with self.assertRaises(TimeoutError):
            self.run_native(self.context(native_retry_flag_964=True), fault=deadline)

    def test_extended_two_target_filter_lifecycle_and_all_releases_after_fault(self):
        from scripts.calibration_catalog import Address

        context = self.context(
            target_metadata=(
                Address(b"\x01\x00", b"\x01\x08"),
                Address(b"\x01\x00\x10", b"\x01\x08\x20", True),
            )
        )
        seed = b"\x67\x01" + bytes(range(32, 48))
        responses = (seed, b"\x67\x02", seed, b"\x67\x02", b"\x50", b"\x50")
        result, events, resources = self.run_native(context, responses=responses)
        self.assertEqual(result["prepared_targets"], (0, 1))
        self.assertEqual(resources, [])
        filters = [e for e in events if e["operation"] == "start_flow_control_filter"]
        self.assertEqual(
            [e["request_address"] for e in filters],
            [b"\0\0\x01\x00", b"\0\0\x01\x00\x10"],
        )
        self.assertEqual(
            [e["identifier"] for e in events if e["operation"] == "stop_filter"],
            [9, 10],
        )

        def fault(event, _events):
            if event["operation"] == "stop_filter" and event["identifier"] == 10:
                raise OSError("authored one-filter release failure")

        with self.assertRaises(OSError):
            self.run_native(context, responses=responses, fault=fault)
        self.assertEqual(
            [e["identifier"] for e in self.events if e["operation"] == "stop_filter"],
            [9, 10],
        )
        self.assertEqual(self.resources, [10])

    def test_exhausted_seed_pending_and_busy_keep_native_unavailable_branch(self):
        for nrc, count in ((0x78, 150), (0x21, 256)):
            with self.subTest(nrc=nrc):
                result, events, resources = self.run_native(
                    self.context(native_retry_flag_964=True),
                    responses=(bytes((0x7F, 0x27, nrc)),) * count,
                )
                self.assertEqual(result["skipped_targets"], ((0, 23),))
                self.assertEqual(resources, [])
                writes = [
                    e["data"] for e in events if e["operation"] == "write_messages"
                ]
                if nrc == 0x78:
                    self.assertEqual(
                        writes,
                        [
                            b"\0\0\x01\x00\x27\x01" + bytes(range(16)),
                            b"\0\0\x01\x00\x3e",
                        ],
                    )
                else:
                    self.assertEqual(len(writes), 256)

    def test_zero_message_count_cannot_complete_diagnostic_mask(self):
        context = self.context()
        _, baseline, _ = self.run_native(context)
        self.assertTrue(
            any(
                e["operation"] == "write_messages"
                and e["data"] == bytes.fromhex("00000720a027")
                for e in baseline
            )
        )
        from scripts.programming_2026_common import NativeRuntime2026, diagnostic_mask

        runtime = NativeRuntime2026(lambda _event, _remaining: 0)
        with self.assertRaises(ValueError):
            diagnostic_mask(runtime, 0)

    def test_malformed_and_unrecognized_contexts_fail_before_provider_calls(self):
        from scripts.calibration_catalog import Address

        for changes in (
            {"target_metadata": (Address(b"\x01\x00", b"\x01\x08"),) * 5},
            {"ecu_auth_key": bytes(15)},
            {"service_auth_key": bytes(17)},
            {"seed_wait_ms": True},
            {"native_retry_flag_964": 1},
            {"identity": replace(self.context().identity, sha256="0" * 64)},
        ):
            with (
                self.subTest(changes=tuple(changes)),
                self.assertRaises((ValueError, LookupError)),
            ):
                self.context(**changes)

    def test_preexisting_device_and_periodic_resources_survive_success_and_fault(self):
        for fail in (False, True):

            def fault(event, fail=fail):
                if fail and event["operation"] == "write_messages":
                    raise OSError("authored preparation fault")

            if fail:
                with self.assertRaises(OSError):
                    self.run_native(
                        fault=lambda event, _events: fault(event), preowned=True
                    )
            else:
                self.run_native(preowned=True)
            self.assertTrue(self.runtime.owns_resource("disconnect"))
            self.assertTrue(self.runtime.owns_resource("stop_periodic", identifier=7))
            self.assertFalse(
                any(
                    e["operation"] in ("disconnect", "stop_periodic")
                    for e in self.events
                )
            )
            self.assertEqual(self.resources, [])

    def test_new2026_node_schema_uses_actual_producer_and_global_auth_overload(self):
        from scripts.calibration_2026 import parse_cuw_2026
        from scripts.demo_calibration import table
        from scripts.programming_2026_common import bind_native_parameter2026
        from scripts.programming_2026_legacy import bind_native_context
        from tests.test_calibration_2026 import cuw

        text = (
            "[Format]\nVersion=105\n[Vehicle]\nNumberOfNode=1\nKindOfECU=1\nContactType=CAN\n"
            "ECUAuthKey="
            + bytes(range(16)).hex()
            + "\nServiceAuthKey="
            + bytes(range(16, 32)).hex()
            + "\n"
            "[Node01]\nNumberOfCalibration=1\nRequiredSpecReproVer=02\nDiagID=0100\n"
            "ECUAuthKey="
            + bytes(16).hex()
            + "\nServiceAuthKey="
            + bytes(16).hex()
            + "\n"
            "[CPU11]\nCPUImageName=authored.vbf\nLocationID=0108010000000720\n"
        )
        container = parse_cuw_2026(cuw(text, (bytes(1024),)))
        values = {
            "ParamFileKeySystemProtocolMicon": "1CAN",
            "DLLFileNameForPrepareWrite": "TCUWP4CanSecurityPowerTrainPrepareWriter.dll",
            "GetCANIDFunctionNameForPrepareWrite": "GetCanIDsFromParamForPrepareWrite",
            "CanIDForPrepareWrite": "0100/0108",
            "WaitTimeAfterSeedData": "2",
            "WaitTimeAfterSeedKey": "3",
            "WaitTimeAfterDiagnosticMask": "4",
        }
        selection = bind_native_parameter2026(
            container,
            {"1CAN.ini": table(tuple(values), [tuple(values.values())])},
            "prepare",
            encoded=False,
        )
        bound = bind_native_context(
            container,
            1,
            ("DEMO",),
            selection,
            self.context().identity,
            {},
            {},
        )
        self.assertEqual(bound, self.context())


class HINOHelpersTests(unittest.TestCase):
    def channel(self, responses=(), fault=None, cancelled=lambda: False):
        from scripts.programming_2026_sil import SILChannel

        reads = iter(responses)
        events = []

        def action(event, remaining):
            self.assertGreater(remaining, 0)
            events.append(event)
            if fault is not None:
                fault(event)
            if event["operation"] == "get_timeout":
                return 100
            if event["operation"] == "write_messages":
                return 1
            if event["operation"] == "read_messages":
                return next(reads)
            if event["operation"] == "ioctl" and event["ioctl"] == 5:
                return {"data": b"", "rx_status": 0}
            return None

        return SILChannel(action, cancelled=cancelled), events

    def test_hino_amt_literal_stop_and_tester_requests(self):
        from scripts.programming_2026_legacy import hino_halt, hino_tester_present_amt

        channel, events = self.channel(
            (bytes.fromhex("81f0197e"), bytes.fromhex("81f019c2"))
        )
        hino_tester_present_amt(channel, 0x19, 0xF0)
        hino_halt(channel, 0x19, 0xF0)
        self.assertEqual(
            [e["data"] for e in events if e["operation"] == "write_messages"],
            [bytes.fromhex("8119f03ec8"), bytes.fromhex("8119f0820c")],
        )

    def test_hino_sil_inner_native_cancel_after_write_keeps_native_buffer(self):
        from scripts.programming_2026_legacy import hino_halt, hino_tester_present_amt

        for helper in (hino_halt, hino_tester_present_amt):
            requested = [False]

            def flip(event, requested=requested):
                if event["operation"] == "write_messages":
                    requested[0] = True

            channel, events = self.channel(fault=flip)
            channel.native_cancelled = lambda requested=requested: requested[0]
            self.assertEqual(helper(channel, 0x19, 0xF0), b"")
            self.assertEqual(sum(e["operation"] == "write_messages" for e in events), 1)
            self.assertFalse(any(e["operation"] == "read_messages" for e in events))
            self.assertEqual(
                events[-1], {"operation": "set_timeout", "milliseconds": 100}
            )

    def test_hino_baud_and_fast_init_use_actual_sil_primitives(self):
        from scripts.programming_2026_legacy import hino_fast_init, hino_set_baud_rate

        channel, events = self.channel()
        hino_set_baud_rate(channel, 57600)
        hino_fast_init(channel, 0x19, 0xF0)
        self.assertEqual(
            events[0], {"operation": "ioctl", "ioctl": 2, "config": ((1, 57600),)}
        )
        self.assertEqual(
            events[1:3],
            [
                {"operation": "ioctl", "ioctl": 2, "config": ((20, 25),)},
                {"operation": "ioctl", "ioctl": 2, "config": ((21, 50),)},
            ],
        )
        self.assertEqual(events[3]["input"], bytes.fromhex("8119f0810b"))

    def test_hino_cid_retains_ansi_spaces_and_nul_semantics(self):
        from scripts.programming_2026_legacy import hino_extract_cid

        self.assertEqual(hino_extract_cid(b"HDR\xffID  \0rest", 3, 8), "\xffID  ")
        for offset, width in ((-1, 1), (0, 0), (1, 3), (True, 1)):
            with self.assertRaises(ValueError):
                hino_extract_cid(b"CID", offset, width)

    def test_hino_native_errors_host_cancel_and_faults_are_visible(self):
        from scripts.programming_2026_common import CommonResponseError
        from scripts.programming_2026_legacy import hino_halt, hino_tester_present_amt

        for helper, code in ((hino_halt, 1007), (hino_tester_present_amt, 1006)):
            channel, _events = self.channel((bytes.fromhex("81f01900"),))
            with self.assertRaises(CommonResponseError) as caught:
                helper(channel, 0x19, 0xF0)
            self.assertEqual(caught.exception.code, code)
            channel, events = self.channel(cancelled=lambda: True)
            with self.assertRaises(InterruptedError):
                helper(channel, 0x19, 0xF0)
            self.assertEqual(events, [])

            def fault(event):
                if event["operation"] == "write_messages":
                    raise OSError("authored HINO primitive failure")

            channel, events = self.channel(fault=fault)
            with self.assertRaises(OSError):
                helper(channel, 0x19, 0xF0)
            self.assertEqual(events[-1]["operation"], "set_timeout")

    def test_hino_can_commands_are_exact_and_require_acknowledged_write(self):
        from scripts.programming_2026_common import NativeRuntime2026
        from scripts.programming_2026_legacy import hino_can_command

        expected = {
            "DiagnosticMaskP4": "00000720a08502",
            "DiagnosticMaskP5": "000007208582",
            "DiagnosticUnMaskP4": "00000720a08501",
            "DiagnosticUnMaskP5": "000007208581",
            "StartCommunicationP4": "00000720a02801",
            "StartCommunicationP5": "00000720288001",
            "StopCommunicationP4": "00000720a02802",
            "StopCommunicationP5": "00000720288101",
        }
        for operation, value in expected.items():
            events = []
            runtime = NativeRuntime2026(
                lambda event, _remaining, events=events: events.append(event) or 1
            )
            hino_can_command(runtime, operation)
            self.assertEqual(
                events,
                [
                    {
                        "operation": "write_messages",
                        "protocol": 6,
                        "tx_flags": 0,
                        "data": bytes.fromhex(value),
                        "count": 1,
                    }
                ],
            )
        with self.assertRaises(ValueError):
            hino_can_command(
                NativeRuntime2026(lambda _event, _remaining: 0), "DiagnosticMaskP4"
            )

    def test_amt_native_cancel_observation_skips_but_host_cancel_remains_exception(
        self,
    ):
        from scripts.programming_2026_legacy import hino_tester_present_amt

        channel, events = self.channel()
        channel.native_cancelled = lambda: True
        self.assertIsNone(hino_tester_present_amt(channel, 0x10, 0xF0))
        self.assertEqual(events, [])

    def test_baud_rate_also_uses_native_can_ioctl_without_a_sil_pointer(self):
        from scripts.programming_2026_common import NativeRuntime2026
        from scripts.programming_2026_legacy import hino_set_baud_rate

        events = []
        runtime = NativeRuntime2026(lambda event, remaining: events.append(event))
        hino_set_baud_rate(runtime, 500000)
        self.assertEqual(
            events,
            [{"operation": "control_io", "ioctl": 2, "parameters": ((1, 500000),)}],
        )


class CommonFlashTests(unittest.TestCase):
    request = bytes.fromhex("00000100")
    response = bytes.fromhex("00000108")

    def channel(self, responses=(), fault=None, cancelled=lambda: False):
        from scripts.programming_2026_common import NativeRuntime2026
        from scripts.programming_2026_legacy import CommonFlash2026

        iterator = iter(responses)
        events = []

        def action(event, remaining):
            self.assertGreater(remaining, 0)
            events.append(event)
            if fault:
                fault(event, len(events))
            if event["operation"] == "read_specified_can_message":
                result = next(iterator)
                if isinstance(result, Exception):
                    raise result
                return result
            if event["operation"] == "start_flow_control_filter":
                return 7
            if event["operation"] == "write_messages":
                return 1
            return None

        return CommonFlash2026(NativeRuntime2026(action, cancelled=cancelled)), events

    def ack(self):
        return self.response + b"\x3c"

    def test_combined_security_has_five_waits_and_one_final_ack(self):
        channel, events = self.channel((self.ack(),))
        nonce, key = bytes(range(16)), bytes(range(16, 32))
        channel.send_nonce_and_seed_key(self.request, self.response, nonce, key, 7)
        writes = [e["data"] for e in events if e["operation"] == "write_messages"]
        self.assertEqual(
            writes,
            [
                self.request + bytes.fromhex("37000102030405"),
                self.request + bytes.fromhex("38060708090a0b"),
                self.request + bytes.fromhex("390c0d0e0f"),
                self.request + bytes.fromhex("3a101112131415"),
                self.request + bytes.fromhex("3b161718191a1b"),
                self.request + bytes.fromhex("3c1c1d1e1f"),
            ],
        )
        self.assertEqual(
            [e["milliseconds"] for e in events if e["operation"] == "wait"], [7] * 5
        )
        self.assertEqual(
            [
                e["frame"]
                for e in events
                if e["operation"] == "read_specified_can_message"
            ],
            [0],
        )

    def test_ack_status_retry_and_transport_domains(self):
        from scripts.programming import NativeTransportError
        from scripts.programming_2026_common import CommonResponseError

        channel, events = self.channel(
            (self.response + b"\x00", self.ack() + b"extra", self.ack())
        )
        self.assertTrue(channel.receive_ack(self.response))
        self.assertEqual(len(events), 3)
        for retries in (False, True):
            channel, events = self.channel(
                tuple(NativeTransportError(9) for _ in range(4))
            )
            with self.assertRaises(CommonResponseError) as caught:
                channel.get_status(self.request, self.response, retries)
            self.assertEqual(caught.exception.code, 4)
            self.assertEqual(
                sum(e["operation"] == "write_messages" for e in events),
                4 if retries else 1,
            )
        channel, events = self.channel((self.ack(), NativeTransportError(9)) * 4)
        with self.assertRaises(NativeTransportError):
            channel.get_status(self.request, self.response)
        self.assertEqual(sum(e["operation"] == "write_messages" for e in events), 4)
        channel, _ = self.channel((NativeTransportError(8),))
        with self.assertRaises(NativeTransportError):
            channel.receive_ack(self.response)

    def test_actual48_address_only_status_uses_zeroed_byte_and_final_ack(self):
        from scripts.j2534_2026 import J2534Device2026, NativeMessage, PrimitiveResult
        from scripts.programming_2026_common import NativeRuntime2026
        from scripts.programming_2026_legacy import CommonFlash2026

        pending, events = [], []

        def provider(event, remaining):
            events.append(event)
            op = event["operation"]
            if op == "passthru_write":
                self.assertEqual(event["messages"][0].data, self.request + b"\x50")
                pending.extend(
                    (
                        NativeMessage(6, self.request, rx_status=9),
                        NativeMessage(6, self.ack()),
                        NativeMessage(6, self.response),
                        NativeMessage(6, self.ack()),
                    )
                )
                return PrimitiveResult(value=1)
            if op == "passthru_read":
                return PrimitiveResult(value=(pending.pop(0),))
            if op in ("passthru_open", "passthru_connect"):
                return PrimitiveResult(value=7)
            return PrimitiveResult()

        device = J2534Device2026(provider, background_workers=False)
        device.open()
        device.connect(6)
        common = CommonFlash2026(NativeRuntime2026(device.primitive))
        self.assertEqual(common.get_status_once(self.request, self.response), 0)
        self.assertEqual(pending, [])
        self.assertEqual(sum(e["operation"] == "passthru_read" for e in events), 4)
        device.close()

    def test_memory_extended_narrow_wide_and_legacy_fallback(self):
        from scripts.programming import NativeTransportError

        for wide, descriptor in (
            (False, bytes.fromhex("0102030405060801")),
            (True, bytes.fromhex("01020304050607080801")),
        ):
            channel, events = self.channel(
                (self.ack(), self.response + descriptor + b"\xff", self.ack())
            )
            memory, extended = channel.get_memory_info(
                self.request, self.response, wide
            )
            self.assertTrue(extended)
            self.assertEqual(memory.block_size_kib, 8)
            self.assertEqual(memory.firmware_version, 1)
            self.assertEqual(
                [
                    e["frame"]
                    for e in events
                    if e["operation"] == "read_specified_can_message"
                ],
                [0, 1, 0],
            )
        channel, events = self.channel(
            (
                NativeTransportError(16),
                self.ack(),
                self.response + bytes.fromhex("0102030405060801"),
                self.ack(),
            )
        )
        memory, extended = channel.get_memory_info(self.request, self.response, True)
        self.assertFalse(extended)
        self.assertEqual(memory.start_address, 0x010203)
        self.assertEqual(
            [e["data"] for e in events if e["operation"] == "write_messages"],
            [self.request + b"\x76", self.request + b"\x75"],
        )

    def test_check_id_literal_frames_timeout_and_extended_finish(self):
        channel, events = self.channel((self.ack(), self.response + b"arbitrary"))
        channel.check_id_with_wait_of_sfs(
            self.request,
            self.response,
            bytes.fromhex("0102030405060708"),
            0x11223344,
            2,
            123,
        )
        self.assertEqual(
            [e["data"] for e in events if e["operation"] == "write_messages"],
            [
                self.request + p
                for p in (
                    b"\0",
                    b"\0",
                    bytes.fromhex("080704030201"),
                    bytes.fromhex("0605"),
                    bytes.fromhex("44332211"),
                    b"\x3c",
                )
            ],
        )
        self.assertEqual(
            [e["milliseconds"] for e in events if e["operation"] == "set_timeout"],
            [123],
        )
        self.assertEqual(
            [
                e["frame"]
                for e in events
                if e["operation"] == "read_specified_can_message"
            ],
            [0, 1],
        )
        channel, events = self.channel()
        channel.finish_reprogramming(self.request + b"\xf1")
        self.assertEqual(
            events,
            [
                {
                    "operation": "write_messages",
                    "data": self.request + b"\xf1\x80",
                    "protocol": 6,
                    "tx_flags": 128,
                    "count": 1,
                }
            ],
        )

    def test_every_security_primitive_fault_and_cancellation_stop_chronology(self):
        channel, baseline = self.channel((self.ack(),))
        channel.send_nonce_and_seed_key(
            self.request, self.response, bytes(16), bytes(16), 0
        )
        for index in range(1, len(baseline) + 1):

            def fail(event, count, index=index):
                if count == index:
                    raise OSError("authored failure")

            channel, events = self.channel((self.ack(),), fault=fail)
            with self.assertRaises(OSError):
                channel.send_nonce_and_seed_key(
                    self.request, self.response, bytes(16), bytes(16), 0
                )
            self.assertEqual(len(events), index)
        channel, events = self.channel((self.ack(),), cancelled=lambda: True)
        with self.assertRaises(InterruptedError):
            channel.send_nonce(self.request, self.response, bytes(16), 0)
        self.assertEqual(events, [])

    def test_block_commands_poll_waits_and_status_error_mapping(self):
        from scripts.demo_calibration import table
        from scripts.programming_2026_common import (
            CommonResponseError,
            NativeParameter2026,
        )

        parameter = NativeParameter2026.from_csv(
            table(("WaitTimeBeforeStatusCheckForBlankCheck",), [("3",)])
        )
        parameter.row_index = 1
        reads = (
            self.ack(),
            self.ack(),
            self.response + b"\x10",
            self.ack(),
            self.ack(),
            self.response + b"\x01",
            self.ack(),
        )
        channel, events = self.channel(reads)
        self.assertFalse(
            channel.check_block(self.request, self.response, parameter, 2, 4, True)
        )
        self.assertEqual(
            [e["data"] for e in events if e["operation"] == "write_messages"],
            [
                self.request + bytes.fromhex("3600010003"),
                self.request + b"\x50",
                self.request + b"\x50",
            ],
        )
        self.assertEqual(
            [e["milliseconds"] for e in events if e["operation"] == "wait"], [3, 3]
        )
        for method in ("erase", "verify"):
            channel, events = self.channel(
                (self.ack(), self.ack(), self.response + b"\x01", self.ack())
            )
            with self.assertRaises(CommonResponseError) as caught:
                if method == "erase":
                    channel.erase_block(self.request, self.response, 2, 4, parameter)
                else:
                    channel.in_verify_block(
                        self.request, self.response, parameter, 2, 4
                    )
            self.assertEqual(caught.exception.code, 12 if method == "erase" else 14)
            self.assertEqual(
                events[0]["data"],
                self.request + (b"\x25\x01" if method == "erase" else b"\x47\x01"),
            )

    def test_write_bytes_observers_see_mutations_and_fault_stops_percent(self):
        channel, events = self.channel()
        counts, percentages, cursor, observed = [0], [0], [0], []

        def notify(field):
            observed.append((field, cursor[:], counts[:], percentages[:]))

        channel.write_bytes(
            self.request, 0, 4, cursor, 2, b"abcdefghi", 8, counts, percentages, notify
        )
        self.assertEqual(events[0]["data"], self.request + b"cdef")
        self.assertEqual(
            observed, [("count", [4], [4], [0]), ("percent", [4], [4], [25])]
        )

        def fault(field):
            raise OSError("authored observer failure")

        with self.assertRaises(OSError):
            channel.write_bytes(
                self.request,
                0,
                2,
                cursor,
                2,
                b"abcdefghi",
                8,
                counts,
                percentages,
                fault,
            )
        self.assertEqual((cursor, counts, percentages), ([6], [6], [25]))

    def test_id_driver_maps7_but_host_cancel_stays_host_cancel(self):
        from scripts.programming import NativeTransportError
        from scripts.programming_2026_legacy import NativeMappedTransportError

        channel, _ = self.channel(
            fault=lambda event, count: (_ for _ in ()).throw(NativeTransportError(8))
        )
        with self.assertRaises(NativeMappedTransportError) as caught:
            channel.check_id_with_wait_of_sfs(
                self.request, self.response, bytes(8), 0, 0
            )
        self.assertEqual(caught.exception.native_error_code, 7)
        self.assertEqual(caught.exception.code, 8)
        channel, events = self.channel(cancelled=lambda: True)
        with self.assertRaises(InterruptedError):
            channel.check_id_with_wait_of_sfs(
                self.request, self.response, bytes(8), 0, 0
            )
        self.assertEqual(events, [])

    def test_write_block_exact_two_chunks_address_marker_and_stage_notifications(self):
        from scripts.demo_calibration import table
        from scripts.programming_2026_common import (
            NativeMemoryInfo,
            NativeParameter2026,
        )

        parameter = NativeParameter2026.from_csv(
            table(
                (
                    "SendDataByteForWriteBlockType",
                    "WaitTimeBeforeStatusCheckForWriteBlock",
                ),
                [("2", "3")],
            )
        )
        parameter.row_index = 1
        per_chunk = (self.ack(), self.ack(), self.response + b"\0", self.ack())
        channel, events = self.channel(
            (self.ack(),) + per_chunk + (self.ack(),) + per_chunk
        )
        image = bytes(range(256))
        counts, percentages, notifications = [0], [0], []
        channel.write_block(
            self.request,
            self.response,
            0,
            3,
            3,
            (0, 0, 256),
            NativeMemoryInfo(0x102030, 0x10212F, 1, 1),
            image,
            256,
            parameter,
            counts,
            percentages,
            lambda field: notifications.append(field),
            notifications.append,
            wait_ms=2,
        )
        writes = [e["data"] for e in events if e["operation"] == "write_messages"]
        self.assertEqual(
            writes,
            [
                self.request + b"\x41",
                self.request + bytes.fromhex("1020301f"),
                self.request + image[:128],
                self.request + b"\x50",
                self.request + b"\x45",
                self.request + image[128:],
                self.request + b"\x50",
            ],
        )
        self.assertEqual(
            notifications, [13, "count", "percent", "count", "percent", 9999]
        )
        self.assertEqual((counts, percentages), ([256], [50]))
        self.assertEqual(
            [e["milliseconds"] for e in events if e["operation"] == "wait"], [2, 3, 3]
        )

    def test_verify_block_and_alternate_wire_and_progress(self):
        from scripts.demo_calibration import table
        from scripts.programming_2026_common import NativeParameter2026

        parameter = NativeParameter2026.from_csv(
            table(("WaitTimeBeforeStatusCheckForVerify",), [("4",)])
        )
        parameter.row_index = 1
        for alternate in (False, True):
            chunks = 2 if alternate else 1
            per_chunk = (self.ack(), self.ack(), self.response + b"\0", self.ack())
            channel, events = self.channel((self.ack(),) + per_chunk * chunks)
            image = bytes(range(256))
            counts, percentages, notifications = [256], [50], []
            arguments = (
                self.request,
                self.response,
                0,
                1,
                1,
                (256,),
                image,
                256,
                parameter,
                counts,
                percentages,
                notifications.append,
            )
            if alternate:
                channel.verify_block2(*arguments)
            else:
                channel.verify_block(*arguments, notifications.append, wide=True)
            writes = [e["data"] for e in events if e["operation"] == "write_messages"]
            self.assertEqual(
                writes[0],
                self.request
                + (
                    bytes.fromhex("1800000000")
                    if alternate
                    else bytes.fromhex("1600000000")
                ),
            )
            self.assertEqual(
                writes[1], self.request + image[: 128 if alternate else 256]
            )
            self.assertEqual((counts, percentages), ([512], [100]))
            self.assertEqual(
                notifications,
                ["count", "percent"] * 2
                if alternate
                else [15, "count", "percent", 9999],
            )

    def test_nonfinal_verify_fault_uses_prior_status_but_wait_fault_propagates(self):
        from scripts.demo_calibration import table
        from scripts.programming import NativeTransportError
        from scripts.programming_2026_common import (
            CommonResponseError,
            NativeParameter2026,
        )
        from scripts.programming_2026_legacy import NativeMappedTransportError

        parameter = NativeParameter2026.from_csv(
            table(("WaitTimeBeforeStatusCheckForVerify",), [("0",)])
        )
        parameter.row_index = 1

        def arguments(channel):
            return (
                self.request,
                self.response,
                0,
                1,
                1,
                (256,),
                bytes(256),
                256,
                parameter,
                [0],
                [0],
                lambda field: None,
            )

        reads = (
            self.ack(),
            self.ack(),
            NativeTransportError(9),
            self.ack(),
            self.ack(),
            self.response + b"\0",
            self.ack(),
        )
        channel, events = self.channel(reads)
        channel.verify_block2(*arguments(channel))
        self.assertEqual(
            sum(
                e["operation"] == "write_messages" and len(e["data"]) == 132
                for e in events
            ),
            2,
        )
        reads = (
            self.ack(),
            self.ack(),
            self.ack(),
            self.response + b"\x10",
            self.ack(),
            NativeTransportError(9),
        )
        channel, events = self.channel(reads)
        with self.assertRaises(CommonResponseError) as caught:
            channel.verify_block2(*arguments(channel))
        self.assertEqual(caught.exception.code, 15)
        self.assertEqual(
            sum(
                e["operation"] == "write_messages" and len(e["data"]) == 132
                for e in events
            ),
            1,
        )

        def fault(event, count):
            if event["operation"] == "wait":
                raise NativeTransportError(8)

        channel, events = self.channel((self.ack(), self.ack()), fault=fault)
        with self.assertRaises(NativeMappedTransportError) as caught:
            channel.verify_block2(*arguments(channel))
        self.assertEqual(
            (caught.exception.native_error_code, caught.exception.code), (15, 8)
        )

    def test_progress_observer_cancel_stops_next_mutation(self):
        cancelled = [False]
        channel, events = self.channel(cancelled=lambda: cancelled[0])
        counts, percentages, cursor = [0], [7], [0]

        def notify(field):
            cancelled[0] = True

        with self.assertRaises(InterruptedError):
            channel.write_bytes(
                self.request, 0, 2, cursor, 0, b"ab", 2, counts, percentages, notify
            )
        self.assertEqual((cursor, counts, percentages), ([2], [2], [7]))
        self.assertEqual(len(events), 1)

    def test_actual48_primary_enum_is_not_a_driver_timeout(self):
        from scripts.j2534_2026 import NativeJ2534Error2026, NativePassThruError2026
        from scripts.programming_2026_legacy import NativeMappedTransportError

        channel, _ = self.channel((NativePassThruError2026(9),))
        with self.assertRaises(NativePassThruError2026) as caught:
            channel.receive_ack(self.response)
        self.assertIsNone(caught.exception.passthru_status)
        channel, _ = self.channel((NativeJ2534Error2026(9),))
        self.assertFalse(channel.receive_ack(self.response))

        def fault(event, count):
            raise NativePassThruError2026(9999)

        channel, _ = self.channel(fault=fault)
        with self.assertRaises(NativePassThruError2026) as caught:
            channel.change_next_cpu(self.request, self.response)
        self.assertEqual(caught.exception.native_error_code, 9999)

        def driver_fault(event, count):
            raise NativeJ2534Error2026(8)

        channel, _ = self.channel(fault=driver_fault)
        with self.assertRaises(NativeMappedTransportError) as mapped:
            channel.change_next_cpu(self.request, self.response)
        self.assertEqual(
            (mapped.exception.native_error_code, mapped.exception.passthru_status),
            (19, 8),
        )

    def test_canonical31_exception_inheritance_and_driver_enum_mapping(self):
        from scripts.programming_2026_common import (
            NativeJ2534Exception2026,
            NativePassThruException2026,
        )

        def fault(event, count):
            raise NativeJ2534Exception2026(8, "authored.cpp", 1)

        channel, _ = self.channel(fault=fault)
        with self.assertRaises(NativeJ2534Exception2026) as caught:
            channel.change_next_cpu(self.request, self.response)
        self.assertEqual(
            (caught.exception.error, caught.exception.j2534_error), (19, 8)
        )
        self.assertEqual(
            (caught.exception.source, caught.exception.line), ("authored.cpp", 1)
        )

        def primary(event, count):
            raise NativePassThruException2026(42, "authored.cpp", 2)

        channel, events = self.channel(fault=primary)
        with self.assertRaises(NativePassThruException2026):
            channel.get_status(self.request, self.response)
        self.assertEqual(len(events), 4)

    def test_finish_probe_owns_only_its_filter_and_preserves_cleanup_failure(self):
        from scripts.j2534_2026 import NativeCommunicationAddress
        from scripts.programming import NativeTransportError

        address = NativeCommunicationAddress(
            bytes.fromhex("0100fe"), bytes.fromhex("0108fe"), True
        )
        response = address.headers()[1] + b"arbitrary"
        channel, events = self.channel((response,))
        channel.runtime.own("disconnect")
        self.assertTrue(channel.is_finish_reprogramming(((address,),)))
        self.assertTrue(channel.runtime.owns_resource("disconnect"))
        self.assertFalse(channel.runtime.owns_resource("stop_filter", identifier=7))
        self.assertEqual(
            next(e for e in events if e["operation"] == "write_messages")["data"],
            address.headers()[0] + b"\x3e",
        )
        self.assertEqual(
            next(e for e in events if e["operation"] == "write_messages")["tx_flags"],
            128,
        )
        for failure in (
            NativeTransportError(8),
            NativeException2026("authored native unknown"),
        ):

            def fault(event, count, failure=failure):
                if event["operation"] == "write_messages":
                    raise failure

            channel, _ = self.channel(fault=fault)
            self.assertFalse(channel.is_finish_reprogramming(((address,),)))

        host_failure = OSError("authored host provider failure")

        def host_fault(event, _count):
            if event["operation"] == "write_messages":
                raise host_failure

        channel, _ = self.channel(fault=host_fault)
        with self.assertRaises(OSError) as caught:
            channel.is_finish_reprogramming(((address,),))
        self.assertIs(caught.exception, host_failure)
        self.assertFalse(channel.runtime.owns_resource("stop_filter", identifier=7))

        def stop_fault(event, count):
            if event["operation"] == "stop_filter":
                raise NativeTransportError(8)

        channel, _ = self.channel((response,), fault=stop_fault)
        with self.assertRaises(NativeTransportError):
            channel.is_finish_reprogramming(((address,),))
        self.assertTrue(channel.runtime.owns_resource("stop_filter", identifier=7))


class HINOCANUtilitiesTests(unittest.TestCase):
    request = bytes.fromhex("00000100")
    response = bytes.fromhex("00000108")

    def channel(self, responses, fault=None, cancelled=lambda: False):
        from scripts.programming_2026_common import NativeRuntime2026
        from scripts.programming_2026_legacy import HINOUtils2026

        replies = iter(responses)
        events, resources = [], []

        def action(event, remaining):
            events.append(event)
            if fault:
                fault(event, len(events))
            operation = event["operation"]
            if operation == "get_timeout":
                return 100
            if operation == "write_messages":
                return 1
            if operation == "read_specified_can_message":
                return event["address"] + next(replies)
            if operation == "start_flow_control_filter":
                resources.append(7)
                return 7
            if operation == "stop_filter":
                resources.remove(event["identifier"])
            return None

        runtime = NativeRuntime2026(action, cancelled=cancelled)
        runtime.own("disconnect")
        return HINOUtils2026(runtime), events, resources

    def test_dss_full_prepare_wire_complement_and_local_cleanup(self):
        channel, events, resources = self.channel(
            (
                bytes.fromhex("5085"),
                bytes.fromhex("67030123abcd"),
                bytes.fromhex("670434"),
            )
        )
        result = channel.prepare_write_dss(self.request, self.response, lambda: False)
        self.assertTrue(result.prepared)
        self.assertEqual(resources, [])
        self.assertTrue(channel.runtime.owns_resource("disconnect"))
        self.assertEqual(
            [
                event["data"]
                for event in events
                if event["operation"] == "write_messages"
            ],
            [
                bytes.fromhex(value)
                for value in (
                    "00000720a08502",
                    "000007208582",
                    "00000720a02802",
                    "00000720288101",
                    "000001001085",
                    "000001002703",
                    "000001002704fedc5432",
                )
            ],
        )
        self.assertEqual(
            [event["milliseconds"] for event in events if event["operation"] == "wait"],
            [1000, 0, 0, 0],
        )

    def test_dss_failure_preserves_native_enum_driver_and_notification_status(self):
        from scripts.programming import NativeTransportError
        from scripts.programming_2026_common import CommonResponseError

        for failure, native, driver in (
            (CommonResponseError(41), 41, None),
            (NativeTransportError(8), 1, 8),
            (NativeException2026("authored native unknown"), 9999, None),
        ):

            def fault(event, count, failure=failure):
                if event["operation"] == "write_messages":
                    raise failure

            channel, events, resources = self.channel((), fault=fault)
            result = channel.prepare_write_dss(
                self.request, self.response, lambda: True
            )
            self.assertEqual(
                (
                    result.prepared,
                    result.native_error_code,
                    result.driver_error_code,
                    result.result_code,
                ),
                (False, native, driver, 2),
            )
            self.assertEqual(resources, [])
        channel, events, resources = self.channel((), cancelled=lambda: True)
        with self.assertRaises(InterruptedError):
            channel.prepare_write_dss(self.request, self.response, lambda: False)
        self.assertEqual(events, [])

    def test_native_observer_fault_after_host_cancel_cannot_become_native_result(self):
        cancelled = [False]
        channel, events, _ = self.channel((), cancelled=lambda: cancelled[0])

        def observe():
            cancelled[0] = True
            raise NativeException2026("authored observer fault")

        channel.runtime.native_cancelled = observe
        with self.assertRaises(InterruptedError):
            channel.tester_present(self.request, self.response)
        self.assertEqual(events, [])

    def test_host_fault_propagates_without_native_result_or_notification(self):
        failure = OSError("authored host provider failure")

        def fault(event, _count):
            if event["operation"] == "write_messages":
                raise failure

        channel, _, resources = self.channel((), fault=fault)
        notifications = []
        with self.assertRaises(OSError) as caught:
            channel.prepare_write_dss(
                self.request, self.response, lambda: not notifications.append(True)
            )
        self.assertIs(caught.exception, failure)
        self.assertEqual((resources, notifications), ([], []))

    def test_transfer_partial_chunk_and_progress_observer_failure(self):
        channel, events, _ = self.channel((b"\x76", b"\x76"))
        counts, percentages, observed = [123], [50], []
        channel.send_data(
            self.request,
            self.response,
            b"abcde",
            3,
            1,
            counts,
            percentages,
            lambda field: observed.append((field, counts[:], percentages[:])),
        )
        self.assertEqual(
            [
                event["data"]
                for event in events
                if event["operation"] == "write_messages"
            ],
            [self.request + b"\x36abc", self.request + b"\x36de"],
        )
        self.assertEqual(
            observed,
            [
                ("count", [3], [50]),
                ("percent", [3], [60]),
                ("count", [5], [60]),
                ("percent", [5], [100]),
            ],
        )
        channel, events, _ = self.channel((b"\x76",))
        counts, percentages = [0], [9]

        def fail(field):
            raise OSError("authored observer failure")

        with self.assertRaises(OSError):
            channel.send_data(
                self.request, self.response, b"abcd", 2, 1, counts, percentages, fail
            )
        self.assertEqual((counts, percentages), ([2], [9]))
        self.assertEqual(
            len([event for event in events if event["operation"] == "write_messages"]),
            1,
        )

    def test_observer_and_notification_cancel_do_not_return_success(self):
        from scripts.programming_2026_common import CommonResponseError

        cancelled = [False]
        channel, _events, resources = self.channel(
            (b"\x76",), cancelled=lambda: cancelled[0]
        )
        counts, percentages = [0], [9]

        def observer(field):
            cancelled[0] = True

        with self.assertRaises(InterruptedError):
            channel.send_data(
                self.request, self.response, b"ab", 2, 1, counts, percentages, observer
            )
        self.assertEqual((counts, percentages), ([2], [9]))
        cancelled[0] = False

        def fault(event, count):
            if event["operation"] == "write_messages":
                raise CommonResponseError(41)

        channel, _events, resources = self.channel(
            (), fault=fault, cancelled=lambda: cancelled[0]
        )

        def notification():
            cancelled[0] = True
            return False

        with self.assertRaises(InterruptedError):
            channel.prepare_write_dss(self.request, self.response, notification)
        self.assertEqual(resources, [])

    def test_copy_assignment_preserve_reference_fields_without_wire(self):
        original, events, _ = self.channel(())
        clone = original.clone()
        self.assertIsNot(clone, original)
        self.assertIs(clone.runtime, original.runtime)
        self.assertIs(clone.diag, original.diag)
        self.assertIs(clone.sil_channel, original.sil_channel)
        other, other_events, _ = self.channel(())
        self.assertIs(other.assign_from(original), other)
        self.assertIs(other.runtime, original.runtime)
        self.assertIs(other.diag, original.diag)
        self.assertEqual((events, other_events), ([], []))

    def test_native_tester_present_observation_skips_can_without_host_cancellation(
        self,
    ):
        channel, events, _ = self.channel(())
        channel.runtime.native_cancelled = lambda: True
        channel.tester_present(self.request, self.response)
        channel.tester_present(self.request, self.response, vcs=True)
        self.assertEqual(events, [])
        channel, events, _ = self.channel((b"\x7e", b"\x7e"))
        channel.runtime.native_cancelled = lambda: False
        channel.tester_present(self.request, self.response)
        channel.tester_present(self.request, self.response, vcs=True)
        self.assertEqual(
            [e["data"] for e in events if e["operation"] == "write_messages"],
            [self.request + b"\x3e", self.request + b"\x3e\x01"],
        )

    def test_dss_host_abort_keeps_primary_when_filter_cleanup_also_fails(self):
        cancelled = [False]

        def fault(event, count):
            if event["operation"] == "write_messages":
                cancelled[0] = True
            if event["operation"] == "stop_filter":
                raise OSError("authored cleanup fault")

        channel, _events, resources = self.channel(
            (), fault=fault, cancelled=lambda: cancelled[0]
        )
        with self.assertRaises(InterruptedError) as caught:
            channel.prepare_write_dss(self.request, self.response, lambda: False)
        self.assertEqual(resources, [7])
        self.assertIn("Native cleanup failure: OSError", caught.exception.__notes__)
        self.assertTrue(channel.runtime.owns_resource("stop_filter", identifier=7))


class CanCID2026Tests(unittest.TestCase):
    def context(self, **changes):
        from scripts.j2534_2026 import NativeCommunicationAddress
        from scripts.native_modules import identify_native_module
        from scripts.programming_2026_legacy import CanCIDContext2026

        result = CanCIDContext2026(
            identify_native_module(
                "3b0527a86cc74a3d1c6c686d39f71a8424cce699871a48c5454f8c315e2a89b6",
                "TCUWCanCIDGetter.dll",
            ),
            (NativeCommunicationAddress(b"\x01\0", b"\x01\x08"),),
            123,
        )
        return replace(result, **changes)

    def run_native(
        self,
        context=None,
        responses=(),
        fault=None,
        cancelled=lambda: False,
        native_cancelled=lambda: False,
        with_controller=False,
    ):
        from scripts.programming_2026_common import NativeRuntime2026
        from scripts.programming_2026_legacy import _run_can_cid_abi

        events, resources = [], []
        replies = iter(responses)

        def action(event, remaining):
            events.append(event)
            if fault:
                fault(event, len(events))
            op = event["operation"]
            if op == "connect":
                resources.append("connection")
            if op == "disconnect":
                resources.remove("connection")
            if op == "start_flow_control_filter":
                resources.append(7)
                return 7
            if op == "stop_filter":
                resources.remove(event["identifier"])
            if op == "write_messages":
                return 1
            if op == "get_timeout":
                return 123
            if op == "read_specified_can_message":
                reply = next(replies)
                if isinstance(reply, Exception):
                    raise reply
                return event["address"] + reply
            return None

        runtime = NativeRuntime2026(
            action, cancelled=cancelled, native_cancelled=native_cancelled
        )
        self.events, self.resources = events, resources
        controller = None
        if with_controller:
            from scripts.native_modules import identify_native_module
            from scripts.programming_2026_common import ControlCommPhase2026

            controller = ControlCommPhase2026(
                identify_native_module(
                    "b2cf3cd681e15f6e53294ad2fafaf460723659853d445b2cfd949b8e9f099012",
                    "TCUWControlCommPhase.dll",
                ),
                runtime,
            )
        self.controller = controller
        return _run_can_cid_abi(
            context or self.context(), runtime, controller=controller
        )

    def test_exact_history_setter_survives_later_host_abort_and_empty_cid_read(self):
        from scripts.j2534_2026 import NativeCommunicationAddress

        context = self.context(
            addresses=self.context().addresses
            + (NativeCommunicationAddress(b"\x02\0", b"\x02\x08"),)
        )

        def fault(event, _count):
            if event["operation"] == "write_messages" and event["data"].startswith(
                b"\0\0\x02\0"
            ):
                raise OSError("authored later ECU host failure")

        with self.assertRaises(OSError):
            self.run_native(
                context,
                responses=(
                    b"\x49\0\x10\0\0\0",
                    b"\x49\x04\x01" + b"DEMO\0".ljust(16, b" "),
                ),
                fault=fault,
                with_controller=True,
            )
        assert self.controller is not None
        self.assertEqual(self.controller.address_history, [context.addresses[0]])
        self.assertEqual(self.resources, [])
        result = self.run_native(
            responses=(b"\x49\0\x10\0\0\0",),
            native_cancelled=lambda: True,
            with_controller=True,
        )
        self.assertTrue(result["native_success"])
        self.assertEqual(result["cids"], ())
        assert self.controller is not None
        self.assertEqual(
            self.controller.address_history, list(self.context().addresses)
        )

    def test_probe_bitmap_cid_frame_history_and_connection_cleanup(self):
        payload = (
            b"\x49\x04\x02"
            + b"DEMO\0".ljust(16, b" ")
            + bytes.fromhex("ff")
            + b" \0".ljust(15, b" ")
        )
        result = self.run_native(responses=(b"\x49\0\x10\0\0\0", payload))
        self.assertEqual(result["state"], "read_completed")
        self.assertEqual(result["cids"], (b"DEMO", b"\xff "))
        self.assertTrue(result["native_success"])
        self.assertEqual(result["history"], self.context().addresses)
        self.assertEqual(result["query_ids"], (b"0100",) * 2)
        self.assertEqual(result["query_cpu_indices"], (0, 0))
        self.assertIsNone(result["native_return"])
        self.assertEqual(
            [
                event["data"]
                for event in self.events
                if event["operation"] == "write_messages"
            ],
            [bytes.fromhex("000001000900"), bytes.fromhex("000001000904")],
        )
        self.assertEqual(self.resources, [])

    def test_probe_absent_bit_and_allowed_timeout_and_bad_frame(self):
        from scripts.programming import NativeTransportError

        for probe in (b"\x49\0\0\0\0\0", NativeTransportError(9)):
            result = self.run_native(responses=(probe,))
            self.assertFalse(result["native_success"])
            self.assertEqual(result["native_error_code"], 3)
            self.assertEqual(self.resources, [])
            result = self.run_native(
                self.context(timeout_allowing_id=b"\x01\0"), responses=(probe,)
            )
            self.assertTrue(result["native_success"])
            self.assertEqual(result["cids"], ())
        result = self.run_native(responses=(b"\x49\0\x30\0\0\0", b"\x49\x04\x01bad"))
        self.assertEqual(
            (result["native_success"], result["native_error_code"]), (False, 3)
        )
        self.assertEqual(self.resources, [])

    def test_extended_parser_header_and_partial_vector_on_second_target_failure(self):
        from scripts.j2534_2026 import NativeCommunicationAddress
        from scripts.programming_2026_legacy import decode_can_cids2026

        self.assertEqual(
            decode_can_cids2026(
                bytes.fromhex("0000010800490401") + b"DEMO".ljust(16, b" ")
            ),
            ("DEMO            ",),
        )
        second = NativeCommunicationAddress(b"\x02\0", b"\x02\x08")
        context = self.context(addresses=self.context().addresses + (second,))
        result = self.run_native(
            context,
            responses=(
                b"\x49\0\x10\0\0\0",
                b"\x49\x04\x01" + b"DEMO\0".ljust(16, b" "),
                b"\x49\0\0\0\0\0",
            ),
        )
        self.assertEqual(result["cids"], (b"DEMO",))
        self.assertEqual(result["state"], "failed")
        self.assertEqual(self.resources, [])

    def test_actual47_metadata31_parameter48_device_full_getter(self):
        from scripts.calibration_2026 import parse_cuw_2026
        from scripts.demo_calibration import table
        from scripts.j2534_2026 import J2534Device2026, NativeMessage, PrimitiveResult
        from scripts.programming_2026_common import (
            NativeRuntime2026,
            bind_native_parameter2026,
        )
        from scripts.programming_2026_legacy import bind_can_cid_context, run_can_cid
        from tests.test_calibration_2026 import cuw

        text = "[Format]\nVersion=6\n[Vehicle]\nKindOfECU=1\nContactType=CAN\nNumberOfCalibration=1\n[CPU01]\nCPUType=1\nCPUImageName=authored.vbf\nLocationID=0108010000000720\n"
        container = parse_cuw_2026(cuw(text))
        values = {
            "ParamFileKeySystemProtocolMicon": "1CAN1",
            "DLLFileNameForGetCID": "TCUWCanCIDGetter.dll",
            "GetCANIDFunctionNameForGetCID": "GetCanIDsFromParamForGetCID",
            "CanIDForGetCID": "0100/0108",
            "ReceiveTimeoutBeforeGetCID": "123",
        }
        binding = bind_native_parameter2026(
            container,
            {"1CAN1.ini": table(tuple(values), [tuple(values.values())])},
            "get_cid",
            encoded=False,
        )
        context = bind_can_cid_context(
            container, 1, (), binding, self.context().identity, {}, {}
        )
        forbidden_io = []
        guard_runtime = NativeRuntime2026(
            lambda event, remaining: forbidden_io.append(event),
            native_cancelled=lambda: False,
        )
        for candidate in (replace(context, receive_timeout_ms=124), self.context()):
            with self.assertRaises(ValueError):
                run_can_cid(candidate, guard_runtime)
        self.assertEqual(forbidden_io, [])
        forged_values = dict(binding.values)
        forged_values["CanIDForGetCID"] = ("0200/0208",)
        with self.assertRaises(ValueError):
            bind_can_cid_context(
                container,
                1,
                (),
                replace(binding, values=forged_values),
                self.context().identity,
                {},
                {},
            )
        self.assertEqual(context, self.context())
        reads, events = [], []
        responses = iter(
            (b"\x49\0\x10\0\0\0", b"\x49\x04\x01" + b"DEMO\0".ljust(16, b" "))
        )

        def provider(event, remaining):
            events.append(event)
            name = event["operation"]
            if name == "passthru_write":
                message = event["messages"][0]
                self.assertEqual((message.protocol_id, message.tx_flags), (6, 0x40))
                reads.extend(
                    (
                        PrimitiveResult(
                            value=(NativeMessage(6, message.data[:4], rx_status=9),)
                        ),
                        PrimitiveResult(
                            value=(
                                NativeMessage(
                                    6, bytes.fromhex("00000108") + next(responses)
                                ),
                            )
                        ),
                    )
                )
                return PrimitiveResult(value=1)
            if name == "passthru_read":
                return reads.pop(0)
            if name in ("passthru_open", "passthru_connect", "passthru_start_filter"):
                return PrimitiveResult(value=0)
            return PrimitiveResult()

        device = J2534Device2026(provider, clock=lambda: 0, background_workers=False)
        runtime = NativeRuntime2026(
            device.primitive, clock=lambda: 0, native_cancelled=lambda: False
        )
        result = run_can_cid(context, runtime)
        self.assertTrue(result["native_success"])
        self.assertEqual(result["cids"], (b"DEMO",))
        self.assertEqual(device.filters, [])
        self.assertFalse(device.connecting)
        self.assertEqual(
            sum(e["operation"] == "passthru_start_filter" for e in events), 2
        )

    def test_native_cancel_skips_only_cid_read_and_foreign_fault_preserves_error_fields(
        self,
    ):
        probe = b"\x49\0\x10\0\0\0"
        result = self.run_native(responses=(probe,), native_cancelled=lambda: True)
        self.assertTrue(result["native_success"])
        self.assertEqual(result["cids"], ())
        self.assertEqual(result["history"], self.context().addresses)
        self.assertEqual(
            sum(e["operation"] == "write_messages" for e in self.events), 1
        )
        self.assertEqual(self.resources, [])

        with self.assertRaises(ValueError):
            self.run_native(native_cancelled=None)
        self.assertEqual(self.events, [])

        def fault(event, count):
            if event["operation"] == "write_messages":
                raise NativeException2026("authored native unknown")

        result = self.run_native(fault=fault)
        self.assertEqual(
            (
                result["native_success"],
                result["native_error_code"],
                result["driver_error_code"],
            ),
            (False, None, None),
        )
        self.assertEqual(self.resources, [])

    def test_host_provider_fault_preserves_exception_and_releases_resources(self):
        failure = OSError("authored host provider failure")

        def fault(event, _count):
            if event["operation"] == "write_messages":
                raise failure

        with self.assertRaises(OSError) as caught:
            self.run_native(fault=fault)
        self.assertIs(caught.exception, failure)
        self.assertEqual(self.resources, [])

    def test_native_cancel_during_response_read_and_cleanup_fault_preserves_host_abort(
        self,
    ):
        values = iter((False, True))
        result = self.run_native(
            responses=(b"\x49\0\x10\0\0\0",), native_cancelled=lambda: next(values)
        )
        self.assertFalse(result["native_success"])
        self.assertEqual(result["history"], ())
        self.assertIsNone(result["native_error_code"])
        self.assertEqual(
            sum(e["operation"] == "write_messages" for e in self.events), 2
        )
        cancelled = [False]

        def fault(event, count):
            if event["operation"] == "write_messages":
                cancelled[0] = True
            if event["operation"] in ("stop_filter", "disconnect"):
                raise OSError("authored cleanup fault")

        with self.assertRaises(InterruptedError) as caught:
            self.run_native(fault=fault, cancelled=lambda: cancelled[0])
        self.assertEqual(len(caught.exception.__notes__), 2)
        self.assertEqual(self.resources, ["connection", 7])


if __name__ == "__main__":
    unittest.main()
