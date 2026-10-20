"""Authored CUW/parameter/driver controls; no OEM material or device access."""

import csv
import io
import struct
import unittest
import zlib
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from scripts.calibration import CalibrationContainer
from scripts.calibration_2026 import parse_cuw_2026
from scripts.native_modules import identify_native_module
from scripts.programming import NativeTransportError
from scripts.programming_2026_common import NativeRuntime2026, bind_parameter2026
from scripts.programming_2026_mmc import (
    bind_native_context,
    mmc_key,
    run_native,
    security_tables,
)
from tests.test_calibration_2026 import cuw, record, srecord

HASHES = {
    "get_cid": (
        "TCUWCanMMCCIDGetter.dll",
        "840e86a5aa708479e5d428a9c1039a687469ce11b49885b190ea976d854ae36d",
    ),
    "prepare": (
        "TCUWCanMMCPrepareWriter.dll",
        "416916da0a1d06d90b5df379b1093fd6206a0127d1ff07d0fd74c7e62c37f4a7",
    ),
    "write": (
        "TCUWCanMMCFlashWriter.dll",
        "39fedbc6a11954300665e9802e4501533550129c8a5cfee71789c0564467f9f8",
    ),
}
TABLES = (
    (tuple(range(18)), tuple(range(256))),
    (tuple(range(18, 36)), tuple(range(256))),
)


def context(stage, *, erase_address="00001000", **observations):
    name, digest = HASHES[stage]
    image = bytes.fromhex("0000100000000004") + b"DATA" + b"\xaa\xbb"
    loader = bytes.fromhex("0000200000000004") + b"LOAD" + b"\xcc\xdd"
    text = (
        "[Format]\nVersion=7\n[Vehicle]\nNumberOfCalibration=1\nContactType=P5-CAN\nKindOfECU=65\n"
        "[CPU01]\nCPUType=282\nCPUImageName=authored.bin\nFlashCodeName=authored.bin\n"
        f"[CPUImage01]\nDataFormatID=11\nNumberOfAreaSettings=1\n01_StartAddress={erase_address}\n01_Length=00000004\n"
        "[FlashCode01]\nDataFormatID=22\nNumberOfAreaSettings=1\n01_StartAddress=00002000\n01_Length=00000004\n"
    )
    container = parse_cuw_2026(
        cuw(
            text,
            (srecord(3, 0x8000, image) + b"\n", srecord(3, 0x9000, loader) + b"\n"),
            count=1,
        )
    )
    assert isinstance(container, CalibrationContainer)
    suffix = {"get_cid": "GetCID", "prepare": "PrepareWrite", "write": "FlashWrite"}[
        stage
    ]
    values = {
        "ParamFileKeySystemProtocolMicon": "65P5-CAN282",
        "DLLFileNameFor" + suffix: name,
        "GetCANIDFunctionNameFor" + suffix: "GetCanIDsFromParamForGetCID"
        if stage == "get_cid"
        else "GetCanIDsFromParamForPrepareWrite",
        "CanIDForGetCID": "07E0/07E8",
        "CanIDForPrepareWrite": "07E0/07E8",
        "ReceiveTimeoutBeforeGetCID": "123",
        "WaitTimeAfterEndOfFlashing": "7",
    }
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(values)
    writer.writerow(values.values())
    selection = bind_parameter2026(
        container,
        {
            "65P5-CAN282.ini": stream.getvalue().encode(),
            "Parameter.ini": b"ParamFileKeySystemProtocolMicon,M16CTypeFlag\r\n65P5-CAN282,0\r\n",
        },
        stage,
        encoded=False,
        node=0,
        cpu_index=0,
    )
    with patch("scripts.programming_2026_mmc.security_tables", return_value=TABLES):
        return bind_native_context(
            container,
            0,
            (),
            selection,
            identify_native_module(digest, name),
            {"prepare_engine": b"authored"} if stage == "prepare" else {},
            observations,
        )


class Replay:
    def __init__(self):
        self.events, self.writes, self.filters = [], [], []
        self.replies = {}
        self.clock = 0.0
        self.local = 86398000
        self.cancel = False
        self.fault: Callable | None = None

    def action(self, event, remaining):
        assert remaining > 0
        self.events.append(event)
        op = event["operation"]
        if self.fault:
            self.fault(event)
        if op == "get_timeout":
            return 123
        if op == "start_flow_control_filter":
            self.filters.append(9)
            return 9
        if op == "stop_filter":
            self.filters.remove(event["identifier"])
        if op == "write_messages":
            self.writes.append(event["data"])
            return 1
        if op == "local_time_ms":
            self.local = (self.local + 1000) % 86400000
            return self.local
        if op == "read_specified_can_message":
            request = self.writes[-1][4:]
            if request in self.replies:
                reply = self.replies[request]
                if isinstance(reply, list):
                    reply = reply.pop(0)
                return event["address"] + reply
            if request.startswith(b"\x34"):
                reply = b"\x74\x20\0\x04"
            elif request.startswith(b"\x36"):
                reply = b"\x76" + request[1:2]
            elif request == b"\x37":
                self.exits = getattr(self, "exits", 0) + 1
                reply = b"\x77" + (b"\xcc\xdd" if self.exits == 1 else b"\xaa\xbb")
            elif request.startswith(b"\x31\x01\x03\x01"):
                reply = b"\x71\x01\x03\x01\x10"
            elif request.startswith(b"\x31\x01\xff\0"):
                reply = b"\x71\x01\xff\0\x10"
            elif request == b"\x31\x01\x03\x04":
                reply = b"\x71\x01\x03\x04\x10\x02"
            elif request == b"\x10\x02":
                reply = b"\x50\x02\0\x32\0\x64"
            elif request == b"\x27\x41":
                reply = b"\x67\x41" + bytes(range(8))
            elif request.startswith(b"\x27\x42"):
                reply = b"\x67\x42"
            elif request == b"\x22\xf1\x11":
                reply = b"\x62\xf1\x11" + b"PRIMARY".ljust(24, b"\0")
            elif request == b"\x22\xf1\x88":
                reply = b"\x62\xf1\x88" + b"SECONDARY".ljust(24, b"\0")
            else:
                raise AssertionError(request.hex())
            return event["address"] + reply

    def runtime(self):
        return NativeRuntime2026(
            self.action, clock=lambda: self.clock, cancelled=lambda: self.cancel
        )


class MMC2026Tests(unittest.TestCase):
    def test_actual_imported_archive_selection_and_full_writer_wire(self):
        ctx, provider = context("write"), Replay()
        notifications = []
        result = run_native(ctx, provider.runtime(), notify=notifications.append)
        self.assertEqual(result["state"], "writer_completed")
        self.assertEqual(
            (result["count"], result["percent"], result["writing"]), (14, 100, False)
        )
        self.assertEqual(provider.filters, [])
        self.assertEqual(
            [x[4:].hex() for x in provider.writes],
            [
                "3422440000200000000004",
                "36014c4f",
                "36024144",
                "37",
                "3101030100002000",
                "3101ff000000100000000004",
                "3411440000100000000004",
                "36014441",
                "36025441",
                "37",
                "31010304",
                "1181",
            ],
        )
        self.assertEqual(provider.writes[-1], bytes.fromhex("000007df1181"))
        self.assertEqual(
            [x["value"] for x in notifications if x["field"] == "writing"],
            [True, False],
        )
        self.assertIn({"operation": "wait", "milliseconds": 7}, provider.events)

    def test_getter_two_native_fixed_width_strings(self):
        p = Replay()
        result = run_native(context("get_cid"), p.runtime())
        self.assertEqual(result["identifier_f111"], "PRIMARY")
        self.assertEqual(result["identifiers"], ["SECONDARY"])
        self.assertEqual(result["state"], "identification_completed")
        self.assertEqual(p.filters, [])
        self.assertEqual(p.events[0], {"operation": "connect", "protocol": 6})

    def test_getter_nrc31_is_failure_not_invented_empty_success(self):
        p = Replay()
        p.replies[b"\x22\xf1\x88"] = b"\x7f\x22\x31"
        result = run_native(context("get_cid"), p.runtime())
        self.assertEqual((result["state"], result["native_error_code"]), ("failed", 3))
        self.assertEqual(result["identifiers"], [])
        self.assertEqual(p.filters, [])

    def test_prepare_burst_midnight_wrap_timing_key_and_periodic_handoff(self):
        p, ctx = Replay(), context("prepare")
        rt = p.runtime()
        with patch("scripts.programming_2026_mmc.security_tables", return_value=TABLES):
            result = run_native(ctx, rt, preparation_state=lambda: 3)
        self.assertEqual(result["state"], "prepare_completed")
        self.assertEqual(result["pending_timeout_ms"], 1000)
        self.assertEqual(p.writes[:3], [bytes.fromhex("000007e01082")] * 3)
        self.assertEqual(
            p.writes[-1],
            bytes.fromhex("000007e02742") + mmc_key(bytes(range(8)), *TABLES[0]),
        )
        self.assertTrue(rt.owns_resource("stop_sync_periodic"))
        self.assertEqual(p.filters, [])
        self.assertEqual(rt.close(), [])

    def test_declined_prepare_has_no_filter_or_authorization(self):
        p = Replay()
        result = run_native(
            context("prepare"), p.runtime(), preparation_state=lambda: 2
        )
        self.assertEqual(result["state"], "prepare_declined")
        self.assertEqual(p.events, [])

    def test_write_failures_reset_progress_keep_native_writing_phase(self):
        for request, expected_status in (
            (b"\x34\x22\x44\0\0\x20\0\0\0\0\x04", 1),
            (b"\x31\x01\xff\0\0\0\x10\0\0\0\0\x04", 2),
        ):
            with self.subTest(request=request):
                p = Replay()
                p.replies[request] = b"\x7f" + request[:1] + b"\x22"
                result = run_native(context("write"), p.runtime())
                self.assertEqual(result["state"], "failed")
                self.assertEqual(result["failure_status"], expected_status)
                self.assertEqual((result["count"], result["percent"]), (0, 0))
                self.assertEqual(p.filters, [])

    def test_cancellation_after_filter_acquisition_releases_filter(self):
        p = Replay()

        def fault(event):
            if event["operation"] == "start_flow_control_filter":
                p.cancel = True

        p.fault = fault
        with self.assertRaises(InterruptedError):
            run_native(context("write"), p.runtime())
        self.assertEqual(p.filters, [])

    def test_prepare_fault_stops_periodic_and_filter(self):
        p, ctx = Replay(), context("prepare")
        p.replies[b"\x27\x41"] = b"\x67\x41short"
        rt = p.runtime()
        result = run_native(ctx, rt, preparation_state=lambda: 3)
        self.assertEqual(result["state"], "failed")
        self.assertEqual(p.filters, [])
        self.assertFalse(rt.owns_resource("stop_sync_periodic"))

    def test_cleanup_fault_cannot_report_success(self):
        p = Replay()

        def fault(event):
            if event["operation"] == "stop_filter":
                raise NativeTransportError(7)

        p.fault = fault
        result = run_native(context("get_cid"), p.runtime())
        self.assertEqual(result["state"], "cleanup_failed")

    def test_malformed_transfer_maximum_fails_bounded(self):
        p = Replay()
        p.replies[bytes.fromhex("3422440000200000000004")] = b"\x74\x20\0\x02"
        with self.assertRaises(ValueError):
            run_native(context("write"), p.runtime())
        self.assertEqual(len(p.writes), 1)

    def test_source_and_selection_spoofing_rejected(self):
        ctx = context("write")
        with self.assertRaises(ValueError):
            replace(
                ctx,
                identity=identify_native_module(
                    HASHES["get_cid"][1], HASHES["get_cid"][0]
                ),
            )
        for raw in (b"", b"MZ" + bytes(100), bytes(100)):
            with self.assertRaises((ValueError, LookupError)):
                security_tables(raw)

    def test_actual48_typed_driver_getter_and_complete_writer(self):
        from tests.test_programming_2026_vendor import TypedDriver

        getter = TypedDriver(
            {
                b"\x22\xf1\x11": [b"\x62\xf1\x11" + b"ONE".ljust(24, b"\0")],
                b"\x22\xf1\x88": [b"\x62\xf1\x88" + b"TWO".ljust(24, b"\0")],
            }
        )
        getter.device.disconnect()
        result = run_native(context("get_cid"), getter.runtime())
        self.assertEqual(result["identifiers"], ["TWO"])
        self.assertEqual(result["state"], "identification_completed")
        replies = {
            bytes.fromhex("3422440000200000000004"): [b"\x74\x20\0\x04"],
            bytes.fromhex("3411440000100000000004"): [b"\x74\x20\0\x04"],
            bytes.fromhex("36014c4f"): [b"\x76\x01"],
            bytes.fromhex("36024144"): [b"\x76\x02"],
            bytes.fromhex("36014441"): [b"\x76\x01"],
            bytes.fromhex("36025441"): [b"\x76\x02"],
            b"\x37": [b"\x77\xcc\xdd", b"\x77\xaa\xbb"],
            bytes.fromhex("3101030100002000"): [bytes.fromhex("7101030110")],
            bytes.fromhex("3101ff000000100000000004"): [bytes.fromhex("7101ff0010")],
            bytes.fromhex("31010304"): [bytes.fromhex("710103041002")],
        }
        writer = TypedDriver(replies)
        result = run_native(context("write"), writer.runtime())
        self.assertEqual(result["state"], "writer_completed")
        self.assertEqual(result["percent"], 100)
        self.assertIn("passthru_stop_filter", [e["operation"] for e in writer.events])
        writer.device.close()
        getter.device.close()

    def test_actual48_prepare_periodic_handoff_and_typed_driver_fault(self):
        from scripts.j2534_2026 import PrimitiveResult
        from tests.test_programming_2026_vendor import TypedDriver

        class WallTimeDriver(TypedDriver):
            def __call__(self, event, remaining):
                if event["operation"] == "local_time_ms":
                    self.events.append(event)
                    self.now += 1
                    return PrimitiveResult(value=int(self.now * 1000) % 86400000)
                return super().__call__(event, remaining)

        seed = bytes(range(8))
        request = b"\x27\x42" + mmc_key(seed, *TABLES[0])
        driver = WallTimeDriver(
            {
                b"\x10\x02": [bytes.fromhex("500200320064")],
                b"\x27\x41": [b"\x67\x41" + seed],
                request: [b"\x67\x42"],
            }
        )
        rt = driver.runtime()
        with patch("scripts.programming_2026_mmc.security_tables", return_value=TABLES):
            result = run_native(context("prepare"), rt, preparation_state=lambda: 3)
        self.assertEqual(result["state"], "prepare_completed")
        self.assertIsNotNone(driver.device.sync)
        self.assertEqual(rt.close(), [])
        self.assertIsNone(driver.device.sync)
        driver.device.close()
        failing = TypedDriver({}, fault="passthru_start_filter")
        result = run_native(context("write"), failing.runtime())
        self.assertEqual(result["state"], "failed")
        self.assertEqual(
            (result["native_error_code"], result["driver_error_code"]), (1, 9)
        )
        failing.device.close()

    def test_pending_response_uses_shared31_runtime_without_resend(self):
        p = Replay()
        p.replies[b"\x22\xf1\x11"] = [
            b"\x7f\x22\x78",
            b"\x62\xf1\x11" + b"ONE".ljust(24, b"\0"),
        ]
        result = run_native(context("get_cid"), p.runtime())
        self.assertEqual(result["state"], "identification_completed")
        self.assertEqual(len(p.writes), 2)

    def test_prepare_other_kind_selects_second_native_key_table(self):
        p, ctx = Replay(), context("prepare")
        metadata = replace(
            ctx.selection.metadata,
            vehicle={**ctx.selection.metadata.vehicle, "kindofecu": "66"},
        )
        with patch("scripts.programming_2026_mmc.security_tables", return_value=TABLES):
            ctx = replace(ctx, selection=replace(ctx.selection, metadata=metadata))
            result = run_native(ctx, p.runtime(), preparation_state=lambda: 3)
        self.assertEqual(result["state"], "prepare_completed")
        self.assertEqual(
            p.writes[-1][4:], b"\x27\x42" + mmc_key(bytes(range(8)), *TABLES[1])
        )

    def test_native_entry_write_faults_retry_and_do_not_skip_authorization(self):
        p, ctx = Replay(), context("prepare")
        states = iter((1, 3, 3))

        def fault(event):
            if event["operation"] == "write_messages" and event["data"].endswith(
                b"\x10\x82"
            ):
                raise NativeTransportError(9)

        p.fault = fault
        with patch("scripts.programming_2026_mmc.security_tables", return_value=TABLES):
            result = run_native(
                ctx, p.runtime(), preparation_state=lambda: next(states)
            )
        self.assertEqual(result["state"], "prepare_completed")
        self.assertTrue(p.writes[-1][4:].startswith(b"\x27\x42"))

    def test_native_typed_exception_status_fields(self):
        from scripts.programming_2026_common import (
            NativeJ2534Exception2026,
            NativePassThruException2026,
        )

        for error, expected in (
            (NativeJ2534Exception2026(9, "authored", 1), (1, 9)),
            (NativePassThruException2026(34, "authored", 2), (34, 0)),
        ):
            p = Replay()

            def fault(event, error=error):
                if event["operation"] == "read_specified_can_message":
                    raise error

            p.fault = fault
            result = run_native(context("write"), p.runtime())
            self.assertEqual(
                (result["native_error_code"], result["driver_error_code"]), expected
            )
            self.assertEqual(p.filters, [])

    def test_image_sequence_wrap_and_negotiated_width(self):
        from scripts.programming_vendor import VendorSegment

        ctx = replace(
            context("write"),
            loader=(),
            image=(VendorSegment(0x1000, bytes(257), b"\xaa\xbb"),),
            erase_areas=(),
        )
        p = Replay()
        p.replies[bytes.fromhex("3411440000100000000101")] = b"\x74\x20\0\x03"
        p.replies[b"\x37"] = b"\x77\xaa\xbb"
        result = run_native(ctx, p.runtime())
        self.assertEqual(result["state"], "writer_completed")
        data = [frame[4:] for frame in p.writes if frame[4:5] == b"\x36"]
        self.assertEqual([x[1] for x in data[-3:]], [255, 0, 1])
        self.assertEqual((result["count"], result["percent"]), (267, 100))

    def test_getter_disconnects_after_filter_without_invented_completion_observer(self):
        p, seen = Replay(), []
        result = run_native(context("get_cid"), p.runtime(), notify=seen.append)
        self.assertEqual(seen, [])
        operations = [e["operation"] for e in p.events]
        self.assertLess(operations.index("stop_filter"), operations.index("disconnect"))
        self.assertEqual(result["state"], "identification_completed")
        self.assertIsNone(result["native_return"])
        self.assertIs(result["native_success"], True)

    def test_source_getter_abort_observation_skips_each_query_without_host_cancel(self):
        p = Replay()
        states = iter((True, False))
        runtime = NativeRuntime2026(
            p.action, clock=lambda: p.clock, native_cancelled=lambda: next(states)
        )
        result = run_native(context("get_cid"), runtime)
        self.assertEqual(result["identifier_f111"], "")
        self.assertEqual(result["identifiers"], ["SECONDARY"])
        self.assertEqual([frame[4:] for frame in p.writes], [b"\x22\xf1\x88"])
        self.assertEqual(result["state"], "identification_completed")

    def test_native_catchall_preserves_getter_writer_fields_and_prepare_assigns9999(
        self,
    ):
        from scripts.programming_2026_common import NativeException2026

        for stage in ("get_cid", "write", "prepare"):
            p, ctx = Replay(), context(stage, native_error_kind=55)

            def fault(event):
                if event["operation"] == "read_specified_can_message":
                    raise NativeException2026("authored")

            p.fault = fault
            if stage == "write":
                with self.assertRaises(NativeException2026):
                    run_native(ctx, p.runtime())
                self.assertEqual(p.filters, [])
                continue
            result = run_native(ctx, p.runtime(), preparation_state=lambda: 3)
            self.assertEqual(result["state"], "failed")
            self.assertEqual(
                result["native_error_code"], 9999 if stage == "prepare" else 55
            )
            if stage == "prepare":
                self.assertEqual(result["failure_status"], 1)
            else:
                self.assertNotIn("failure_status", result)
            self.assertEqual(p.filters, [])

    def test_catchall_after_image_preserves_progress_and_prior_driver_status(self):
        from scripts.programming_2026_common import (
            NativeException2026,
            NativePassThruException2026,
        )

        for error, expected in (
            (NativeException2026("authored"), 55),
            (NativePassThruException2026(70, "authored", 1), 70),
        ):
            p = Replay()

            def fault(event, error=error, p=p):
                if event["operation"] == "read_specified_can_message" and p.writes[-1][
                    4:
                ] == bytes.fromhex("31010304"):
                    raise error

            p.fault = fault
            if isinstance(error, NativeException2026) and not isinstance(
                error, NativePassThruException2026
            ):
                with self.assertRaises(NativeException2026):
                    run_native(
                        context(
                            "write", native_error_kind=55, native_driver_error_code=77
                        ),
                        p.runtime(),
                    )
                self.assertEqual(p.filters, [])
                continue
            result = run_native(
                context("write", native_error_kind=55, native_driver_error_code=77),
                p.runtime(),
            )
            self.assertEqual(result["native_error_code"], expected)
            self.assertEqual(result["driver_error_code"], 77)
            self.assertEqual(
                (result["count"], result["percent"]),
                (0, 0) if expected == 70 else (14, 100),
            )

    def test_host_deadline_after_write_releases_filter_and_periodic(self):
        p = Replay()

        def fault(event):
            if event["operation"] == "write_messages":
                p.clock = 31

        p.fault = fault
        rt = p.runtime()
        with self.assertRaises(TimeoutError):
            run_native(context("write"), rt)
        self.assertEqual(p.filters, [])
        self.assertFalse(rt.owns_resource("stop_sync_periodic"))
        self.assertIn("stop_sync_periodic", [e["operation"] for e in p.events])

    def test_declared_malformed_native_erase_header_rejected_before_io(self):
        with self.assertRaises(ValueError):
            context("write", erase_address="not-hex")

    def test_canonical_native_bool_export_and_pointer_out_parameter(self):
        for stage in ("get_cid", "prepare", "write"):
            p, ctx = Replay(), context(stage)
            with patch(
                "scripts.programming_2026_mmc.security_tables", return_value=TABLES
            ):
                result = run_native(ctx, p.runtime(), preparation_state=lambda: 3)
            self.assertIs(result["native_return"], None if stage == "get_cid" else True)
            self.assertIs(
                result["native_success"], True if stage == "get_cid" else None
            )
        p = Replay()
        p.replies[b"\x22\xf1\x88"] = b"\x7f\x22\x31"
        result = run_native(context("get_cid"), p.runtime())
        self.assertIsNone(result["native_return"])
        self.assertIs(result["native_success"], False)

    def test_native_bool_tracks_writer_success_instruction_before_observer_fault(self):
        p = Replay()

        def observer(event):
            if event == {"field": "writing", "value": False}:
                from scripts.programming_2026_common import NativePassThruException2026

                raise NativePassThruException2026(70, "authored", 1)

        result = run_native(context("write"), p.runtime(), notify=observer)
        self.assertEqual(result["state"], "failed")
        self.assertIs(result["native_return"], True)
        self.assertIsNone(result["native_success"])

    def test_getter_disconnect_failure_leaves_native_out_parameter_unknown(self):
        p = Replay()

        def fault(event):
            if event["operation"] == "disconnect":
                raise NativeTransportError(9)

        p.fault = fault
        result = run_native(context("get_cid"), p.runtime())
        self.assertEqual(result["state"], "cleanup_failed")
        self.assertIsNone(result["native_success"])
        self.assertIsNone(result["native_return"])
        self.assertEqual(p.filters, [])

    def test_getter_filter_cleanup_catch_preserves_bool_then_disconnects(self):
        for query_failed in (False, True):
            p = Replay()
            if query_failed:
                p.replies[b"\x22\xf1\x88"] = b"\x7f\x22\x31"

            def fault(event):
                if event["operation"] == "stop_filter":
                    raise NativeTransportError(9)

            p.fault = fault
            result = run_native(context("get_cid"), p.runtime())
            self.assertEqual(result["state"], "cleanup_failed")
            self.assertIs(result["native_success"], not query_failed)
            self.assertIsNone(result["native_return"])
            self.assertEqual(p.events[-1]["operation"], "disconnect")

    def test_filter_cleanup_preserves_prepare_and_writer_native_bool(self):
        for stage in ("prepare", "write"):
            p = Replay()

            def fault(event):
                if event["operation"] == "stop_filter":
                    raise NativeTransportError(9)

            p.fault = fault
            with patch(
                "scripts.programming_2026_mmc.security_tables", return_value=TABLES
            ):
                result = run_native(
                    context(stage), p.runtime(), preparation_state=lambda: 3
                )
            self.assertEqual(result["state"], "cleanup_failed")
            self.assertIs(result["native_return"], True)

    def test_prepare_entry_observer_fault_propagates_outside_native_handler(self):
        from scripts.programming_2026_common import NativeException2026

        p = Replay()
        error = NativeException2026("authored entry observation")

        def observer():
            raise error

        with self.assertRaises(NativeException2026) as caught:
            run_native(context("prepare"), p.runtime(), preparation_state=observer)
        self.assertIs(caught.exception, error)
        self.assertEqual(p.filters, [])

    def test_host_provider_fault_propagates_without_native_result(self):
        for stage in ("get_cid", "prepare", "write"):
            p = Replay()
            error = OSError("authored host fault")

            def fault(event, error=error):
                if event["operation"] == "write_messages":
                    raise error

            p.fault = fault
            with self.assertRaises(OSError) as caught:
                run_native(context(stage), p.runtime(), preparation_state=lambda: 3)
            self.assertIs(caught.exception, error)
            self.assertEqual(p.filters, [])

    def test_writer_final_stop_sync_fault_propagates_after_filter_attempt(self):
        p = Replay()
        count = 0

        def fault(event):
            nonlocal count
            if event["operation"] == "stop_sync_periodic":
                count += 1
                if count == 2:
                    raise NativeTransportError(9)

        p.fault = fault
        with self.assertRaises(NativeTransportError):
            run_native(context("write"), p.runtime())
        self.assertEqual(p.filters, [])

    def _hardware_fixture(self):
        from scripts.cuw_2026 import CUWEngine2026, identity_2026
        from scripts.programming_2026_common import (
            ControlCommPhase2026,
            NativeGeneralParameters2026,
        )

        folder = Path("runtime/no-car-21/recovered")
        if not (folder / "CUW.dll").is_file():
            self.skipTest("Optional authenticated CUW2026 static image unavailable")
        ctx, provider = context("get_cid"), Replay()
        container = ctx.selection.metadata.source_container
        body = record(container.attached.header, container.attached.data)
        body += container.declared_count.to_bytes(container.count_width, "big")
        body += b"".join(record(r.header, r.data) for r in container.records)
        raw = (
            b"\0CALIBRATION\0"
            + bytes((container.version,))
            + bytes(4)
            + struct.pack(">I", 22 + len(body))
            + body
        )
        raw = raw[:14] + struct.pack(">I", zlib.crc32(raw[18:])) + raw[18:]
        runtime = NativeRuntime2026(
            provider.action,
            clock=lambda: provider.clock,
            local_milliseconds_of_day=lambda: 1000,
        )
        controller = ControlCommPhase2026(
            identity_2026(
                (folder / "TCUWControlCommPhase.dll").read_bytes(),
                "TCUWControlCommPhase.dll",
            ),
            runtime,
        )
        engine = CUWEngine2026(
            (folder / "CUW.dll").read_bytes(),
            general_parameters=NativeGeneralParameters2026.from_binding(ctx.selection),
        )
        engine.configure(struct.pack("<IIddII", 64, 0, 1.0, 1.0, 0, 0))
        engine.load_cuw(raw)
        self.addCleanup(engine.close)
        return ctx, provider, runtime, controller, engine

    def test_actual_getter_hardware_assignment_precedes_second_query_and_survives_faults(
        self,
    ):
        for case in ("positive", "second_native_fault", "second_host_fault", "empty"):
            with self.subTest(case=case):
                ctx, p, rt, controller, engine = self._hardware_fixture()
                hardware = b"" if case == "empty" else b"HW123"
                p.replies[b"\x22\xf1\x11"] = b"\x62\xf1\x11" + hardware.ljust(24, b"\0")
                if case == "second_native_fault":
                    p.replies[b"\x22\xf1\x88"] = b"\x7f\x22\x31"
                observed = []
                host_error = OSError("authored second-query host failure")

                def fault(
                    event,
                    observed=observed,
                    engine=engine,
                    case=case,
                    p=p,
                    host_error=host_error,
                ):
                    if (
                        event["operation"] == "write_messages"
                        and event["data"][4:] == b"\x22\xf1\x88"
                    ):
                        observed.append(engine._working_hardware)
                        self.assertEqual(engine.received_hardware, b"PRIOR")
                    if (
                        case == "second_host_fault"
                        and event["operation"] == "read_specified_can_message"
                        and p.writes[-1][4:] == b"\x22\xf1\x88"
                    ):
                        raise host_error

                p.fault = fault
                with engine.controller_execution(controller, 0):
                    engine._import_identifier_context()
                    engine.apply_mmc_getter_hardware(ctx.identity, b"PRIOR")
                    engine.commit_received_identifiers((), controller=controller)
                    engine._import_identifier_context()
                    if case == "empty":
                        engine.apply_mmc_getter_hardware(ctx.identity, b"OLD")
                    if case == "second_host_fault":
                        with self.assertRaises(OSError) as caught:
                            run_native(ctx, rt, engine=engine)
                        self.assertIs(caught.exception, host_error)
                        values = ()
                    else:
                        result = run_native(ctx, rt, engine=engine)
                        self.assertIs(
                            result["native_success"], case != "second_native_fault"
                        )
                        values = tuple(
                            value.encode("latin1")
                            for value in result.get("identifiers", ())
                        )
                    self.assertEqual(observed, [hardware])
                    self.assertEqual(engine._working_hardware, hardware)
                    self.assertEqual(engine.received_hardware, b"PRIOR")
                    # Isolated5a050 handoff; host-abort public reception does not commit.
                    engine.commit_received_identifiers(values, controller=controller)
                    self.assertEqual(engine.received_hardware, hardware)
                    self.assertEqual(p.filters, [])

    def test_actual_getter_engine_owner_and_phase_guards_precede_io(self):
        ctx, p, rt, controller, engine = self._hardware_fixture()
        with self.assertRaises(ValueError):
            run_native(ctx, rt, engine=engine)
        self.assertEqual(p.events, [])
        with engine.controller_execution(controller, 1):
            engine._import_identifier_context()
            with self.assertRaises(ValueError):
                run_native(ctx, rt, engine=engine)
        self.assertEqual(p.events, [])
        with engine.controller_execution(controller, 0):
            engine._import_identifier_context()
            other_source = context("get_cid", erase_address="00001001")
            with self.assertRaises(ValueError):
                run_native(other_source, rt, engine=engine)
            with self.assertRaises(TypeError):
                run_native(
                    context("prepare"), rt, engine=engine, preparation_state=lambda: 3
                )
        self.assertEqual(p.events, [])

    def test_feistel_overflow_matches_independent_word_reference(self):
        p = tuple(0xFFFFFFF0 + i % 16 for i in range(18))
        s = tuple((i * 0x1234567) & 0xFFFFFFFF for i in range(256))
        left, right = 0xFFFFFFFF, 0xFEFDFCFB
        for key in p[:16]:
            old = left ^ key
            a, b, c, d = old.to_bytes(4, "big")
            left, right = (((s[a] + s[b]) % 2**32 ^ s[c]) + s[d]) % 2**32 ^ right, old
        expected = (right ^ p[17]).to_bytes(4, "big") + (left ^ p[16]).to_bytes(
            4, "big"
        )
        self.assertEqual(mmc_key(bytes.fromhex("fffffffffefdfcfb"), p, s), expected)


if __name__ == "__main__":
    unittest.main()
