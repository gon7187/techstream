"""Authored CUW→native parameter→typed J2534 positive and failure checks."""

import csv
import io
import unittest
from dataclasses import replace

from scripts.calibration_2026 import (
    native2026_metadata,
    native2026_with_cpu_type,
    parse_cuw_2026,
)
from scripts.j2534_2026 import J2534Device2026, NativeMessage, PrimitiveResult
from scripts.native_modules import identify_native_module
from scripts.programming import NativeTransportError
from scripts.programming_2026_common import (
    CommonResponseError,
    NativeException2026,
    NativeJ2534Exception2026,
    NativePassThruException2026,
    NativeRuntime2026,
    bind_native_parameter2026,
)
from scripts.programming_2026_p5_getters import (
    MIXED,
    MODULE_EXPORTS,
    P5,
    SET_BS,
    bind_native_context,
    decode_p5_cids2026,
    run_native_context,
)
from tests.test_calibration_2026 import cuw

HASHES = {
    MIXED: "2d7f643757b9e0b7209e394962ade0b98154f5b9a733b2898470c4022f358dc2",
    P5: "9a851913a9eef54a5049f47bdd25f091c86ec335046d378f56d8b7f0313b45ef",
    SET_BS: "bf214f86f02560df2348ea3dbe0655d22fe47d88fe7af11810cbad612a163b75",
}


def fixture(module=P5, addresses="0100/0108", *, allow="", cpu_index=0):
    container = parse_cuw_2026(
        cuw(
            "[Format]\nVersion=7\n[Vehicle]\nKindOfECU=8\nContactType=P5\nNumberOfCalibration=2\n"
            "[CPU01]\nCPUType=A\nCPUImageName=authored.vbf\nLocationID=0108010000000000\n"
            "[CPU02]\nCPUType=B\nCPUImageName=authored.vbf\nLocationID=0208020000000000\n",
            (b"authored-A", b"authored-B"),
        )
    )
    values = {
        "DLLFileNameForGetCID": module,
        "GetCANIDFunctionNameForGetCID": "GetCanIDsFromParamForGetCID",
        "CanIDForGetCID": addresses,
        "ReceiveTimeoutBeforeGetCID": "123",
        "RequestCANIDAllowingTimeout": allow,
    }
    catalogs = {}
    for cpu in ("A", "B"):
        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\r\n")
        writer.writerow(("ParamFileKeySystemProtocolMicon", *values))
        writer.writerow(("8P5" + cpu, *values.values()))
        catalogs["8P5" + cpu + ".ini"] = output.getvalue().encode()
    binding = bind_native_parameter2026(
        container, catalogs, "get_cid", encoded=False, cpu_index=cpu_index
    )
    identity = identify_native_module(HASHES[module], module)
    context = bind_native_context(container, 1, (), binding, identity, {}, {})
    return context, container, binding


def p5(*values):
    return (
        b"\x62\xf1\x81"
        + bytes((len(values),))
        + b"".join(v.ljust(16, b"\0") for v in values)
    )


def primitive_runtime(
    replies, *, native_cancelled=lambda: False, fault=None, cancelled=lambda: False
):
    replies = iter(replies)
    events = []

    def action(event, remaining):
        events.append(event)
        if fault:
            fault(event)
        name = event["operation"]
        if name == "start_flow_control_filter":
            return 7
        if name == "get_timeout":
            return 123
        if name == "write_messages":
            return 1
        if name == "read_specified_can_message":
            value = next(replies)
            if isinstance(value, Exception):
                raise value
            return event["address"] + value
        return None

    return NativeRuntime2026(
        action, native_cancelled=native_cancelled, cancelled=cancelled
    ), events


def typed_runtime(
    replies,
    *,
    fault_status=None,
    host_cancel=False,
    cleanup_fault=False,
    pending_first=False,
):
    replies = iter(replies)
    reads, events = [], []

    def provider(event, remaining):
        nonlocal pending_first
        events.append(event)
        name = event["operation"]
        if name == "passthru_write":
            message = event["messages"][0]
            address = message.data[:3] + bytes((message.data[3] + 8,))
            reads.append(
                PrimitiveResult(
                    value=(NativeMessage(6, message.data[:4], rx_status=9),)
                )
            )
            if pending_first:
                reads.append(
                    PrimitiveResult(
                        value=(NativeMessage(6, address + b"\x7f\x22\x78"),)
                    )
                )
                pending_first = False
            reads.append(
                PrimitiveResult(status=fault_status)
                if fault_status is not None
                else PrimitiveResult(value=(NativeMessage(6, address + next(replies)),))
            )
            return PrimitiveResult(value=1)
        if name == "passthru_read":
            return reads.pop(0)
        if name in ("passthru_open", "passthru_connect", "passthru_start_filter"):
            return PrimitiveResult(value=7)
        if name == "passthru_stop_filter" and cleanup_fault:
            raise OSError("Authored filter release failure")
        return PrimitiveResult()

    device = J2534Device2026(provider, clock=lambda: 0, background_workers=False)
    runtime = NativeRuntime2026(
        device.primitive,
        clock=lambda: 0,
        native_cancelled=lambda: False,
        cancelled=lambda: (
            host_cancel and any(e["operation"] == "passthru_write" for e in events)
        ),
    )
    return runtime, device, events


class GetterTests(unittest.TestCase):
    def test_all_exports_authored_import_through_actual_typed_device(self):
        for module in MODULE_EXPORTS:
            with self.subTest(module=module):
                addresses = "0100/0108\n0200/0208" if module == MIXED else "0100/0108"
                context, _, _ = fixture(module, addresses)
                responses = iter(
                    (
                        p5(b"DEMO"),
                        b"\x49\0\x10\0\0\0",
                        b"\x49\x04\x01" + b"SECOND".ljust(16, b"\0"),
                    )
                    if module == MIXED
                    else (p5(b"DEMO"),)
                )
                reads, events = [], []

                def provider(
                    event, remaining, events=events, reads=reads, responses=responses
                ):
                    events.append(event)
                    name = event["operation"]
                    if name == "passthru_write":
                        message = event["messages"][0]
                        request = message.data[2:4]
                        address = b"\0\0" + bytes((request[0], request[1] + 8))
                        reads.extend(
                            (
                                PrimitiveResult(
                                    value=(
                                        NativeMessage(6, message.data[:4], rx_status=9),
                                    )
                                ),
                                PrimitiveResult(
                                    value=(NativeMessage(6, address + next(responses)),)
                                ),
                            )
                        )
                        return PrimitiveResult(value=1)
                    if name == "passthru_read":
                        return reads.pop(0)
                    if name in (
                        "passthru_open",
                        "passthru_connect",
                        "passthru_start_filter",
                    ):
                        return PrimitiveResult(value=7)
                    return PrimitiveResult()

                device = J2534Device2026(
                    provider, clock=lambda: 0, background_workers=False
                )
                runtime = NativeRuntime2026(
                    device.primitive, clock=lambda: 0, native_cancelled=lambda: False
                )
                result = run_native_context(context, runtime)
                self.assertTrue(result["bool_out"])
                self.assertIsNone(result["native_return"])
                self.assertEqual(
                    result["cids"],
                    (b"DEMO", b"SECOND") if module == MIXED else (b"DEMO",),
                )
                self.assertFalse(device.connecting)
                self.assertEqual(device.filters, [])
                self.assertEqual(runtime.close(), [])

    def test_all_exports_typed_native_fault_host_cancel_cleanup_failure(self):
        for module in MODULE_EXPORTS:
            context, _, _ = fixture(
                module, "0100/0108\n0200/0208" if module == MIXED else "0100/0108"
            )
            with self.subTest(module=module):
                rt, device, _ = typed_runtime((), fault_status=9)
                result = run_native_context(context, rt)
                self.assertFalse(result["bool_out"])
                self.assertEqual(result["driver_error_code"], 9)
                self.assertFalse(device.connecting)
                self.assertEqual(device.filters, [])
                rt, device, _ = typed_runtime((p5(b"ONE"),), host_cancel=True)
                with self.assertRaises(InterruptedError):
                    run_native_context(context, rt)
                self.assertFalse(device.connecting)
                self.assertEqual(device.filters, [])
                rt, device, events = typed_runtime((p5(b"ONE"),), cleanup_fault=True)
                with self.assertRaises(OSError):
                    run_native_context(context, rt)
                self.assertTrue(
                    any(e["operation"] == "passthru_disconnect" for e in events)
                )
                self.assertFalse(device.connecting)

    def test_actual31_native_exception_error_fields(self):
        context, _, _ = fixture()
        for exception, native, driver in (
            (NativePassThruException2026(17, "authored", 1), 17, None),
            (NativeJ2534Exception2026(16, "authored", 2), 1, 16),
        ):
            with self.subTest(exception=type(exception).__name__):
                rt, _ = primitive_runtime((exception,))
                result = run_native_context(context, rt)
                self.assertFalse(result["bool_out"])
                self.assertEqual(result["native_error_code"], native)
                self.assertEqual(result["driver_error_code"], driver)

    def test_native_foreign_exception_is9999_only_in_exchange_catchall(self):
        context, _, _ = fixture()
        rt, _ = primitive_runtime(
            (NativeException2026("Authored foreign native exception"),)
        )
        result = run_native_context(context, rt)
        self.assertEqual(result["native_error_code"], 9999)

        def fault(event):
            if event["operation"] == "connect":
                raise NativeException2026("Authored outer native exception")

        rt, _ = primitive_runtime((), fault=fault)
        result = run_native_context(context, rt)
        self.assertFalse(result["bool_out"])
        self.assertIsNone(result["native_error_code"])

        def callback():
            raise NativeException2026("Authored callback exception")

        rt, _ = primitive_runtime((), native_cancelled=callback)
        result = run_native_context(context, rt)
        self.assertFalse(result["bool_out"])
        self.assertIsNone(result["native_error_code"])

    def test_empty_native_p5_vectors_and_bs_restoration(self):
        for module in (P5, SET_BS):
            context, _, _ = fixture(module)
            rt, events = primitive_runtime(())
            result = run_native_context(replace(context, addresses=()), rt)
            self.assertTrue(result["bool_out"])
            self.assertEqual(result["cids"], ())
            self.assertEqual(
                sum(e["operation"] == "control_io" for e in events),
                2 if module == SET_BS else 0,
            )

    def test_mixed_secondary_cancel_preserves_native_success(self):
        context, _, _ = fixture(MIXED, "0100/0108\n0200/0208")
        observations = iter((False, False, True))
        rt, events = primitive_runtime(
            (p5(b"FIRST"),), native_cancelled=lambda: next(observations)
        )
        result = run_native_context(context, rt)
        self.assertTrue(result["bool_out"])
        self.assertEqual(result["cids"], (b"FIRST",))
        self.assertEqual(sum(e["operation"] == "write_messages" for e in events), 1)

    def test_query_associations_cap_at34_while_vector_continues(self):
        context, _, _ = fixture()
        rt, _ = primitive_runtime((p5(*(b"CID" + str(i).encode() for i in range(36))),))
        result = run_native_context(context, rt)
        self.assertEqual(len(result["cids"]), 36)
        self.assertEqual(result["query_ids"], (b"\1\0",) * 34)

    def test_per_receive_native_cancel_immediate_and_after_pending_all_exports(self):
        for module in MODULE_EXPORTS:
            context, _, _ = fixture(
                module, "0100/0108\n0200/0208" if module == MIXED else "0100/0108"
            )
            for pending in (False, True):
                with self.subTest(module=module, pending=pending):
                    callbacks = iter((False, False, True) if pending else (False, True))
                    replies = (b"\x7f\x22\x78",) if pending else ()
                    rt, events = primitive_runtime(
                        replies,
                        native_cancelled=lambda callbacks=callbacks: next(callbacks),
                    )
                    result = run_native_context(context, rt)
                    self.assertFalse(result["bool_out"])
                    self.assertEqual(result["native_error_code"], 9999)
                    self.assertIsNone(result["driver_error_code"])
                    self.assertEqual(
                        sum(
                            e["operation"] == "read_specified_can_message"
                            for e in events
                        ),
                        int(pending),
                    )
                    self.assertEqual(rt.close(), [])
                    self.assertEqual(events[-1]["operation"], "disconnect")

    def test_mixed_support_probe_skips_receive_callback_but_cid_checks_it(self):
        context, _, _ = fixture(MIXED, "0100/0108\n0200/0208")
        callbacks = iter((False, False, False, True))
        rt, events = primitive_runtime(
            (p5(b"FIRST"), b"\x49\0\x10\0\0\0"),
            native_cancelled=lambda: next(callbacks),
        )
        result = run_native_context(context, rt)
        self.assertFalse(result["bool_out"])
        self.assertEqual(result["native_error_code"], 9999)
        self.assertEqual(result["cids"], (b"FIRST",))
        self.assertEqual(
            [e["data"][4:] for e in events if e["operation"] == "write_messages"],
            [b"\x22\xf1\x81", b"\x09\0", b"\x09\4"],
        )
        self.assertEqual(
            sum(e["operation"] == "read_specified_can_message" for e in events), 2
        )
        self.assertEqual(rt.close(), [])

    def test_positive_pending_receive_checks_preserved_all_exports(self):
        for module in MODULE_EXPORTS:
            context, _, _ = fixture(
                module, "0100/0108\n0200/0208" if module == MIXED else "0100/0108"
            )
            replies = (
                b"\x7f\x22\x78",
                p5(b"FIRST"),
                b"\x49\0\x10\0\0\0",
                b"\x49\x04\1" + b"SECOND".ljust(16, b"\0"),
            )
            rt, _ = primitive_runtime(replies)
            result = run_native_context(context, rt)
            self.assertTrue(result["bool_out"])
            self.assertEqual(
                result["cids"],
                (b"FIRST", b"SECOND") if module == MIXED else (b"FIRST",),
            )
            self.assertEqual(rt.close(), [])

    def test_multi_cpu_selection_and_forged_binding(self):
        context, container, binding = fixture(cpu_index=1)
        self.assertEqual(context.binding.metadata.cpu_index, 1)
        self.assertEqual(
            context.binding.cpu_type, "A"
        )  # Native getter selects global CPU0 parameter type.
        values = dict(binding.values)
        values["CanIDForGetCID"] = ("0200/0208",)
        with self.assertRaises(ValueError):
            bind_native_context(
                container,
                1,
                (),
                replace(binding, values=values),
                context.identity,
                {},
                {},
            )
        with self.assertRaises(ValueError):
            bind_native_context(
                container, 1, (), binding, context.identity, {}, {"cpu_index": 0}
            )

    def test_multi_node_getter_uses_global_cpu0_and_node0_protocol(self):
        container = parse_cuw_2026(
            cuw(
                "[Format]\nVersion=105\n[Vehicle]\nKindOfECU=8\nContactType=P5\nNumberOfNode=2\n"
                "[Node01]\nDiagID=01\nProtocol=01\nRequiredSpecReproVer=02\nNumberOfCalibration=1\n"
                "[CPU11]\nCPUType=IGNORED_A\nCPUImageName=first.vbf\n"
                "[Node02]\nDiagID=02\nProtocol=02\nRequiredSpecReproVer=02\nNumberOfCalibration=1\n"
                "[CPU21]\nCPUType=IGNORED_B\nCPUImageName=second.vbf\n",
                (b"first", b"second"),
            )
        )
        state = native2026_metadata(container, node=2)
        state = native2026_with_cpu_type(state, 0, "C")
        state = native2026_with_cpu_type(state, 1, "D")
        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\r\n")
        writer.writerow(
            (
                "ParamFileKeySystemProtocolMicon",
                "DLLFileNameForGetCID",
                "GetCANIDFunctionNameForGetCID",
                "CanIDForGetCID",
            )
        )
        writer.writerow(("8P501C", P5, "GetCanIDsFromParamForGetCID", "0200/0208"))
        binding = bind_native_parameter2026(
            container,
            {"8P501C.ini": output.getvalue().encode()},
            "get_cid",
            node=2,
            metadata_state=state,
            encoded=False,
        )
        context = bind_native_context(
            container, 2, (), binding, identify_native_module(HASHES[P5], P5), {}, {}
        )
        self.assertEqual(context.binding.key, "8P501C")
        self.assertEqual(context.binding.metadata.cpu.index, 1)
        self.assertEqual(context.binding.metadata.cpu_index, 0)
        rt, _ = primitive_runtime((p5(b"NODE2"),))
        self.assertEqual(run_native_context(context, rt)["query_ids"], (b"\2\0",))

    def test_source_validated_runtime_cpu_overrides_preserved(self):
        context, container, binding = fixture(cpu_index=1)
        state = native2026_with_cpu_type(binding.metadata, 0, "C")
        catalogs = dict(binding.catalog_sources)
        catalogs["8P5C.ini"] = catalogs["8P5A.ini"].replace(b"8P5A", b"8P5C")
        selected = bind_native_parameter2026(
            container,
            catalogs,
            "get_cid",
            encoded=False,
            cpu_index=1,
            metadata_state=state,
        )
        result = bind_native_context(
            container, 1, (), selected, context.identity, {}, {}
        )
        self.assertEqual(result.binding.cpu_type, "C")
        self.assertEqual(result.binding.metadata.cpu_index, 1)
        self.assertEqual(result.binding.metadata.cpu_type_overrides[0], "C")

    def test_native_timeout_allowing_id_and_partial_vector(self):
        context, _, _ = fixture(P5, "0100/0108\n0200/0208", allow="0200")
        rt, _ = primitive_runtime((p5(b"ONE"), NativeTransportError(9)))
        result = run_native_context(context, rt)
        self.assertTrue(result["bool_out"])
        self.assertEqual(result["cids"], (b"ONE",))
        context = replace(context, timeout_allowing_id=b"")
        rt, _ = primitive_runtime((p5(b"ONE"), NativeTransportError(16)))
        result = run_native_context(context, rt)
        self.assertFalse(result["bool_out"])
        self.assertEqual(result["cids"], (b"ONE",))
        self.assertEqual(result["driver_error_code"], 16)

    def test_mixed_support_timeout_becomes_native3_not_driver_error(self):
        context, _, _ = fixture(MIXED, "0100/0108\n0200/0208")
        for status in (9, 16, 5):
            rt, _ = primitive_runtime((p5(b"FIRST"), NativeTransportError(status)))
            result = run_native_context(context, rt)
            self.assertFalse(result["bool_out"])
            self.assertEqual(result["native_error_code"], 3 if status in (9, 16) else 1)
            self.assertEqual(
                result["driver_error_code"], None if status in (9, 16) else 5
            )
            self.assertEqual(result["cids"], (b"FIRST",))

    def test_timeout_allowance_cannot_hide_native_filter_release_failure(self):
        context, _, _ = fixture(allow="0100")

        def fault(event):
            if event["operation"] == "stop_filter":
                raise NativeTransportError(9)

        rt, events = primitive_runtime((p5(b"ONE"),), fault=fault)
        with self.assertRaises(OSError):
            run_native_context(context, rt)
        self.assertTrue(any(e["operation"] == "disconnect" for e in events))

    def test_native_cancel_false_result_and_bs_release(self):
        context, _, _ = fixture(SET_BS)
        rt, events = primitive_runtime((), native_cancelled=lambda: True)
        result = run_native_context(context, rt)
        self.assertFalse(result["bool_out"])
        self.assertEqual(result["native_error_code"], 3)
        self.assertEqual(
            [e.get("parameters") for e in events if e["operation"] == "control_io"],
            [((30, 1),), ((30, 0),)],
        )
        self.assertEqual(rt.close(), [])

    def test_pending_and_filtering_native_records(self):
        context, _, _ = fixture()
        rt, _ = primitive_runtime(
            (b"\x7f\x22\x78", p5(b"1234567890#bad", b"!123456789#ok", b"KEEP"))
        )
        result = run_native_context(context, rt)
        self.assertEqual(result["cids"], (b"!123456789#ok", b"KEEP"))
        self.assertTrue(result["bool_out"])

    def test_full_plain_p5_extended_parser_and_bs_fixed_header(self):
        data = b"\0\0\1\x08\0\x62\xf1\x81\1" + b"EXT".ljust(16, b"\0")
        self.assertEqual(decode_p5_cids2026(data), (b"EXT",))
        with self.assertRaises(CommonResponseError):
            decode_p5_cids2026(data, set_bs=True)
        for data in (b"", b"\0" * 8, b"\0" * 24, b"\0" * 7 + b"\x02" + b"X" * 16):
            with self.subTest(length=len(data)), self.assertRaises(CommonResponseError):
                decode_p5_cids2026(data)

    def test_host_fault_and_cancel_at_every_primitive_all_exports(self):
        for module in MODULE_EXPORTS:
            context, _, _ = fixture(
                module, "0100/0108\n0200/0208" if module == MIXED else "0100/0108"
            )
            replies = (
                p5(b"ONE"),
                b"\x49\0\x10\0\0\0",
                b"\x49\x04\1" + b"TWO".ljust(16, b"\0"),
            )
            rt, events = primitive_runtime(replies)
            run_native_context(context, rt)
            for index, event in enumerate(events):
                if event["operation"] in (
                    "stop_filter",
                    "disconnect",
                    "unlock",
                ) or event.get("parameters") == ((30, 0),):
                    continue
                with self.subTest(module=module, index=index):
                    calls = [0]

                    def fault(_event, calls=calls, index=index):
                        n = calls[0]
                        calls[0] += 1
                        if n == index:
                            raise OSError("Authored host fault")

                    rt, _ = primitive_runtime(replies, fault=fault)
                    with self.assertRaises(OSError):
                        run_native_context(context, rt)
                    self.assertEqual(rt.close(), [])
                    rt, es = primitive_runtime(replies)
                    rt.cancelled = lambda es=es, index=index: len(es) > index
                    with self.assertRaises(InterruptedError):
                        run_native_context(context, rt)
                    self.assertEqual(rt.close(), [])


if __name__ == "__main__":
    unittest.main()
