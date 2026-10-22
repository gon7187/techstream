"""Authored CUW/CAN controls; no OEM payloads, services or devices."""

import csv
import io
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

from scripts.calibration import CalibrationContainer
from scripts.calibration_2026 import (
    native2026_metadata,
    native2026_with_cpu_type,
    parse_cuw_2026,
)
from scripts.j2534_2026 import J2534Device2026, NativeMessage, PrimitiveResult
from scripts.native_modules import identify_native_module
from scripts.programming_2026_common import (
    CommonResponseError,
    NativeJ2534Exception2026,
    NativePassThruException2026,
    NativeRuntime2026,
    bind_parameter2026,
)
from scripts.programming_2026_vendor import (
    SBRUtils2026,
    VendorCAN2026,
    bind_native_context,
    bind_sbr_utility,
    execute_sbr_utility,
    hino_key,
    native2026_write_address_groups,
    prepare_sbr,
    run_native,
    sbr_cipher_function,
    sbr_des_key,
    sbr_secret_type,
)
from tests.test_calibration_2026 import cuw

HASHES = {
    "TCUWCanHINOCIDGetter.dll": "886ebfb75afb3d27261bffcbc6a7710bb18774a25676fe830af17119cfb986e1",
    "TCUWCanHINOCIDGetterForDSS.dll": "63dadd220e393193c9ba778832359fb683a112d42aca3e669b294c5129e58176",
    "TCUWCanHINOCIDGetterForVCS.dll": "c02c1c93eead20fb6906df2381ca617e39ca8c4a992a74faee0cc8b84271f337",
    "TCUWCanHINOFlashWriter.dll": "9b24ea208b16ae1e1589f0466801c82497e132556abf62deecf1c90fafde944f",
    "TCUWCanHINOFlashWriterForDSS.dll": "0b2ece1752970d238b6d17dfa93774c1b13f2a1402fef08a0190a7dd6f988646",
    "TCUWCanHINOFlashWriterForVCS.dll": "8562da7c17e1e1483c947fdcaf306402ddf1e559ee60634a781e43cd988f9439",
    "TCUWCanHINOPrepareWriter.dll": "88b2d8d20d3555a12b6a8c1329454679194d202428c4f7da0266129c1b9b6bbc",
    "TCUWCanHINOPrepareWriterForDSS.dll": "0aade7e4f7d3300aa4e1112b484ade67309505936abd4058ee05e04a670f84e9",
    "TCUWCanHINOPrepareWriterForVCS.dll": "bde2e2e5ce85c1a7792005be35b67d1aae2ee68e7b7a8fd750803d0f41a5162f",
    "TCUWCanSBRFlashWriter.dll": "e2e7befc06dcea0de8e7dc73861e38bf92448015a2e9ba09609c6e02417c4436",
    "TCUWCanSBRPrepareWriter.dll": "c406e73100b7568e8d369b899981b65d0c1ce98cd02eec08b59ff6f9bf90ceaa",
    "TCUWCanSBRSoftwareIDGetter.dll": "db6700be64514f8a156cd3133b79c6902b3662ce87f1916da992e3ef5f338b97",
}


def context(
    name,
    *,
    cpu_count=1,
    cpu_index=0,
    cpu_type="282",
    cpu_type_second="282",
    contact_type="P5-CAN",
    native_observations=None,
    **parameters,
):
    stage = (
        "get_cid"
        if "Getter" in name
        else "prepare"
        if "PrepareWriter" in name
        else "write"
    )
    sbr = "SBR" in name
    text = (
        f"[Format]\nVersion={9 if sbr else 7}\n[Vehicle]\nNumberOfCalibration=1\n"
        f"ContactType={contact_type}\nKindOfECU=106\n[CPU01]\nCPUType={cpu_type}\n"
        + (
            "NumberOfFiles=1\n[File1001]\nALFID=44\nEraseBlock=1\nDownloadAddress=00001000\nDownloadMemsize=00000004\n"
            if sbr
            else "CPUImageName=authored.bin\nFlashCodeName=authored.bin\n"
        )
    )
    if sbr and cpu_count == 2:
        text = text.replace("NumberOfCalibration=1", "NumberOfCalibration=2")
        text += f"[CPU02]\nCPUType={cpu_type_second}\nNumberOfFiles=1\n[File2001]\nALFID=44\nEraseBlock=1\nDownloadAddress=00002000\nDownloadMemsize=00000004\n"
    if sbr:
        container = parse_cuw_2026(cuw(text, (b"DATA",) * cpu_count))
    else:
        from tests.test_calibration_2026 import srecord

        container = parse_cuw_2026(
            cuw(
                text,
                (
                    srecord(3, 0x1000, b"DATA") + b"\n",
                    srecord(3, 0x2000, b"LOAD") + b"\n",
                ),
                count=1,
            )
        )
    if not isinstance(container, CalibrationContainer):
        raise TypeError("Authored vendor fixture must remain a CUW container")
    suffix = {"get_cid": "GetCID", "prepare": "PrepareWrite", "write": "FlashWrite"}[
        stage
    ]
    values = {
        "ParamFileKeySystemProtocolMicon": f"106{contact_type}{cpu_type}",
        "DLLFileNameFor" + suffix: name,
        "GetCANIDFunctionNameFor" + suffix: "GetCanIDsFromParamForGetCID"
        if stage == "get_cid"
        else "GetCanIDsFromParamForPrepareWrite",
        "CanIDForGetCID": "07E0/07E8",
        "CanIDForPrepareWrite": "07E0/07E8" + ("\n07E1/07E9" if cpu_count == 2 else ""),
        "ReceiveTimeoutBeforeGetCID": "100",
        "SBLStartAddressSize": "00002000\n00000004",
        "DATAStartAddressSize": "00001000\n00000004",
        "SoftwareInfoROMIDByteNum": "5",
        "FlagToSupportGetCID": "1",
        "CpuLoopBetweenPrepareAndWriteFlag": "1",
        **parameters,
    }
    table = io.StringIO()
    writer = csv.writer(table)
    writer.writerow(values)
    writer.writerow(values.values())
    catalogs = {f"106{contact_type}{cpu_type}.ini": table.getvalue().encode()}
    if cpu_count == 2 and cpu_type_second != "282":
        second_values = {
            **values,
            "ParamFileKeySystemProtocolMicon": "106" + contact_type + cpu_type_second,
            "CanIDForPrepareWrite": "07E1/07E9",
            "FlagToWaitAfterFuncReq": "1",
        }
        second_table = io.StringIO()
        second_writer = csv.writer(second_table)
        second_writer.writerow(second_values)
        second_writer.writerow(second_values.values())
        catalogs["106" + contact_type + cpu_type_second + ".ini"] = (
            second_table.getvalue().encode()
        )
    selection = bind_parameter2026(
        container,
        catalogs,
        stage,
        encoded=False,
        node=0,
        cpu_index=cpu_index,
    )
    identity = identify_native_module(HASHES[name], name)
    return bind_native_context(
        container,
        0,
        (),
        selection,
        identity,
        {},
        {
            "cpu_index": cpu_index,
            "native_pending_timeout_ms": 5000,
            **(native_observations or {}),
        },
    )


class Replay:
    def __init__(self, replies=(), *, fail=None, cancel=None):
        self.replies = iter(replies)
        self.events = []
        self.now = 0.0
        self.filters = []
        self.fail = fail
        self.cancel = cancel
        self.cancelled = False
        self.timeout = 100

    def __call__(self, event, remaining):
        if remaining <= 0:
            raise AssertionError("Expired callback")
        self.events.append(event)
        op = event["operation"]
        if self.cancel == op:
            self.cancelled = True
        if self.fail == op:
            raise OSError("Authored primitive fault")
        if op == "start_flow_control_filter":
            identifier = len(self.filters) + 10
            self.filters.append(identifier)
            return identifier
        if op == "stop_filter":
            self.filters.remove(event["identifier"])
        if op == "get_timeout":
            return self.timeout
        if op == "set_timeout":
            self.timeout = event["milliseconds"]
        if op == "get_protocol_id":
            return 6
        if op == "write_messages":
            return 1
        if op == "read_specified_can_message":
            return event["address"] + next(self.replies)
        if op == "wait":
            self.now += event["milliseconds"] / 1000
        return None

    def runtime(self, **kwargs):
        return NativeRuntime2026(
            self,
            clock=lambda: self.now,
            cancelled=lambda: self.cancelled,
            native_cancelled=lambda: False,
            timeout=60,
            **kwargs,
        )

    @property
    def writes(self):
        return [
            item["data"]
            for item in self.events
            if item["operation"] == "write_messages"
        ]


class GetterTests(unittest.TestCase):
    def test_dss_prequery_and_literal_fixed_field(self):
        ctx = context("TCUWCanHINOCIDGetterForDSS.dll")
        p = Replay((b"\x7e", b"\x5a\x88\x01ABC\0" + b"x" * 12))
        runtime = p.runtime()
        self.assertEqual(run_native(ctx, runtime)["identifiers"], (b"ABC",))
        self.assertEqual(
            p.writes, [bytes.fromhex("000007e03e"), bytes.fromhex("000007e01a8801")]
        )
        self.assertFalse(runtime._resources)

    def test_vcs_two_tester_requests_before_query(self):
        p = Replay((b"\x7e", b"\x7e", b"\x5a\x03ABCDEFGHIJKLM"))
        result = run_native(context("TCUWCanHINOCIDGetterForVCS.dll"), p.runtime())
        self.assertEqual(result["identifiers"], (b"ABCDEFGHIJKLM",))
        self.assertEqual([v[4:] for v in p.writes], [b"\x3e", b"\x3e\x01", b"\x1a"])

    def test_hino_phase5_and_sbr_binary(self):
        p = Replay((b"\x7e\0", b"\x62\xf1\x88ABCDEFGHIJKL"))
        self.assertEqual(
            run_native(context("TCUWCanHINOCIDGetter.dll"), p.runtime())["identifiers"],
            (b"ABCDEFGHIJKL",),
        )
        p = Replay((b"\x62\xf1\x82\x01\x02\x03\x04\x05",))
        ctx = context("TCUWCanSBRSoftwareIDGetter.dll", FlagToSupportGetCID="0")
        self.assertEqual(run_native(ctx, p.runtime())["identifiers"], ("0102030405",))
        self.assertEqual(p.events[2], {"operation": "wait", "milliseconds": 10000})

    def test_malformed_response_and_cleanup_fault_are_failures(self):
        for fail in (None, "stop_filter"):
            p = Replay((b"\x7e", b"\x5a\x88\x01short"), fail=fail)
            result = run_native(context("TCUWCanHINOCIDGetterForDSS.dll"), p.runtime())
            self.assertEqual(result["state"], "failed")
            self.assertEqual(result["native_error_code"], 3)
            self.assertTrue(any(e["operation"] == "disconnect" for e in p.events))

    def test_cancel_after_filter_acquisition_releases_it(self):
        p = Replay(cancel="start_flow_control_filter")
        runtime = p.runtime()
        with self.assertRaises(InterruptedError):
            run_native(context("TCUWCanHINOCIDGetterForDSS.dll"), runtime)
        self.assertEqual(p.filters, [])
        self.assertFalse(runtime._resources)
        self.assertEqual(p.writes, [])

    def test_no_legacy_identity_or_parameter_mutation(self):
        ctx = context("TCUWCanHINOCIDGetter.dll")
        old = replace(ctx.identity, cuw_build="18")
        with self.assertRaises(ValueError):
            replace(ctx, identity=old)
        with self.assertRaises(ValueError):
            run_native(ctx, Replay().runtime(), entrypoint="PrepareRetry")

    def test_actual48_typed_driver_composition(self):
        responses = [b"\x7e", b"\x5a\x88\x01ABCDEFGHIJKLMNOP"]
        pending = []
        events = []

        def primitive(event, remaining):
            events.append(event)
            op = event["operation"]
            if op == "passthru_write":
                for message in event["messages"]:
                    pending.append((NativeMessage(6, message.data[:4], rx_status=9),))
                    if message.data[4:] in (b"\x3e", b"\x1a\x88\x01"):
                        pending.append(
                            (
                                NativeMessage(
                                    6, bytes.fromhex("000007e8") + responses.pop(0)
                                ),
                            )
                        )
                return PrimitiveResult(value=event["count"])
            if op == "passthru_read":
                return PrimitiveResult(value=pending.pop(0) if pending else ())
            if op in ("passthru_open", "passthru_connect", "passthru_start_filter"):
                return PrimitiveResult(value=0)
            return PrimitiveResult()

        device = J2534Device2026(primitive, clock=lambda: 0, background_workers=False)
        result = run_native(
            context("TCUWCanHINOCIDGetterForDSS.dll"),
            NativeRuntime2026(
                device.primitive, clock=lambda: 0, native_cancelled=lambda: False
            ),
        )
        self.assertEqual(result["identifiers"], (b"ABCDEFGHIJKLMNOP",))
        self.assertIsNone(device.channel_id)
        self.assertTrue(any(e["operation"] == "passthru_stop_filter" for e in events))


class HinoTests(unittest.TestCase):
    def test_native_seed_arithmetic_including_unsigned_underflow(self):
        self.assertEqual(hino_key(bytes(range(12))), bytes(range(255, 243, -1)))
        self.assertEqual(hino_key(bytes.fromhex("0023ffde"), dcu=True), b"\xff" * 4)
        self.assertEqual(
            hino_key(bytes.fromhex("00230001"), dcu=True), bytes.fromhex("ffdcffff")
        )
        with self.assertRaises(ValueError):
            hino_key(bytes(4))

    def test_prepare_session_timing_and_local_seed_transform(self):
        p = Replay(
            (b"\x50\x02\x01\x23\x00\x64", b"\x67\x01\x00\x23\x00\x01", b"\x67\x02")
        )
        result = run_native(context("TCUWCanHINOPrepareWriter.dll"), p.runtime())
        self.assertEqual(result["state"], "prepare_completed")
        self.assertIn(bytes.fromhex("000007e02702ffdcffff"), p.writes)
        self.assertTrue(
            any(
                e == {"operation": "set_timeout", "milliseconds": 291} for e in p.events
            )
        )
        self.assertEqual(p.filters, [])

    def test_writer_phase5_progress_and_complete_chronology(self):
        replies = (
            b"\x74\x10\x06",
            b"\x76\x01",
            b"\x77",
            b"\x71\x01\x10\xff\0",
            b"\x71\x01\x10\xfd\0",
            b"\x74\x10\x06",
            b"\x76\x01",
            b"\x77",
            b"\x71\x01\x10\xfe\0",
            b"\x71\x01\x10\xfc\0",
            b"\x51\x01",
        )
        p, notifications = Replay(replies), []
        result = run_native(
            context("TCUWCanHINOFlashWriter.dll"),
            p.runtime(),
            notify=lambda k, v: notifications.append((k, v)),
        )
        self.assertEqual(result["transferred"], 4)
        self.assertEqual(
            notifications,
            [("writing", 1), ("count", 4), ("percent", 100), ("writing", 0)],
        )
        self.assertEqual(p.writes[0], bytes.fromhex("000007e03400440000200000000004"))
        self.assertEqual(p.writes[1][4:], b"\x36\x01LOAD")
        self.assertEqual(p.filters, [])

    def test_vcs_reset_has_subfunction_and_dss_size_byte_slices(self):
        ctx = context(
            "TCUWCanHINOFlashWriterForDSS.dll",
            SBLStartAddressSize="12345678\n90ABCDEF",
            DATAStartAddressSize="11223344\n55667788",
        )
        p = Replay(
            (
                b"\x7f\x34\x11",
                b"\x71\xa0\0",
                b"\x74",
                b"\x76",
                b"\x77",
                b"\x71\xa3\0",
                b"\x51",
            )
        )
        run_native(ctx, p.runtime())
        self.assertEqual(p.writes[0][4:], bytes.fromhex("34123456789000"))
        self.assertEqual(p.writes[2][4:], bytes.fromhex("34112233556600"))
        ctx = context("TCUWCanHINOFlashWriterForVCS.dll")
        p = Replay(
            (
                b"\x7f\x34\x11",
                b"\x71\x01",
                b"\x74\x02",
                b"\x76",
                b"\x77",
                b"\x71\x02",
                b"\x71\x03",
                b"\x51",
            )
        )
        run_native(ctx, p.runtime())
        self.assertIn(bytes.fromhex("000007e01101"), p.writes)

    def test_failure_or_late_callback_never_programs_next_stage(self):
        p = Replay((b"\x74\x10\x02",))
        result = run_native(context("TCUWCanHINOFlashWriter.dll"), p.runtime())
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["native_error_code"], 26)
        self.assertEqual(len(p.writes), 1)
        p = Replay(cancel="write_messages")
        with self.assertRaises(InterruptedError):
            run_native(context("TCUWCanHINOFlashWriter.dll"), p.runtime())
        self.assertEqual(p.filters, [])


class SBRControlPublicationTests(unittest.TestCase):
    def test_replaced_active_export_scope_fails_before_scratch_publication(self):
        from tests.test_programming_replay import make_authentic_sbr_replay_fixture

        engine, controller, session, _driver, runtime, actions, _key = (
            make_authentic_sbr_replay_fixture(self)
        )
        rows = session.trace.rows
        if type(rows) is not list:
            raise TypeError("Mutable stale-scope trace rows required")
        transfer_index = next(
            index
            for index, row in enumerate(rows)
            if row["request"].get("operation") == "passthru_write"
            and row["request"]["messages"][0]["data"]["value"].startswith(
                "000007e03601"
            )
        )
        response_index = next(
            index
            for index, row in enumerate(rows[transfer_index + 1 :], transfer_index + 1)
            if row["request"].get("operation") == "passthru_read"
            and row["result"]["value"]["value"]["value"][0]["value"]["data"][
                "value"
            ].startswith("000007e87601")
        )
        stop_filter_index = next(
            index
            for index, row in enumerate(rows[response_index + 1 :], response_index + 1)
            if row["request"].get("operation") == "passthru_stop_filter"
        )
        tester_index = next(
            index
            for index, row in enumerate(rows[response_index + 1 :], response_index + 1)
            if row["request"].get("operation") == "passthru_write"
            and row["request"]["messages"][0]["data"]["value"].endswith("3e80")
        )
        next_wire_index = next(
            index
            for index, row in enumerate(rows[tester_index + 1 :], tester_index + 1)
            if row["request"].get("operation") == "passthru_write"
        )
        stop_filter = rows[stop_filter_index]
        final_clock_index = next(
            index
            for index, row in enumerate(
                rows[stop_filter_index + 1 :], stop_filter_index + 1
            )
            if row["request"].get("operation") == "get_local_milliseconds_of_day"
        )
        final_clock = rows[final_clock_index]
        rows[next_wire_index:stop_filter_index] = []
        current_stop_filter_index = next(
            index for index, row in enumerate(rows) if row is stop_filter
        )
        rows[current_stop_filter_index + 1 :] = [final_clock]

        trace_capture = runtime.action.__self__.consume
        recorded_action = trace_capture.recorded_consume

        def replace_scope_after_transfer(kind, event, remaining=None):
            result = recorded_action(kind, event, remaining)
            if event.get("operation") == "passthru_write" and event["messages"][
                0
            ].data.startswith(bytes.fromhex("000007e03601")):
                runtime._device_calls.control_export = (
                    engine,
                    controller,
                    object(),
                )
            return result

        trace_capture.recorded_consume = replace_scope_after_transfer
        with engine.controller_execution(controller, 1):
            session._bind_control_prelude2026(engine, controller, controller.runtime)
            engine.worker._control_count_scratch2026[0] = 7
            engine.worker._control_percent_scratch2026[0] = 41
            device = engine.engine_runtime_device()
            device.open()
            device.connect(6)
            with self.assertRaisesRegex(ValueError, "scope expired or was replaced"):
                controller.execute(engine, session)
            control = controller.native_control_context2026(engine)
            scratch = (control.count_scratch[0], control.percentage_scratch[0])
            published = (
                engine.dh_state._transferred_bytes[0],
                engine.dh_state._progress[0],
            )

        self.assertEqual(scratch, (7, 41))
        self.assertEqual(published, (0, 0))
        self.assertEqual(actions, [])

    def test_padded_transfer_uses_logical_total_and_actual_wire_bytes(self):
        import tests.test_calibration_2026 as calibration_tests
        import tests.test_programming_2026_vendor as vendor_tests
        from tests.test_programming_replay import make_authentic_sbr_replay_fixture

        original_cuw = calibration_tests.cuw
        original_context = vendor_tests.context

        def logical_seven_cuw(text, records, **kwargs):
            return original_cuw(
                text.replace("DownloadMemsize=00000008", "DownloadMemsize=00000007"),
                records,
                **kwargs,
            )

        def padded_context(*args, **kwargs):
            kwargs["FlagToDataBlockPadding"] = "1"
            return original_context(*args, **kwargs)

        original_driver = vendor_tests.TypedDriver.__call__

        def padded_file_replies(driver, event, remaining):
            if event["operation"] == "passthru_write":
                for message in event["messages"]:
                    request = message.data[4:]
                    if request.startswith(b"\x34\x04"):
                        driver.replies[request] = [b"\x74\x20\x00\x0a"]
                    elif request.startswith(b"\x31\x01\xff\x00"):
                        driver.replies[request] = [b"\x71\x01\xff\x00"]
                    elif request.startswith(b"\x31\x01\xff\x01"):
                        driver.replies[request] = [b"\x71\x01\xff\x01\x01"]
            return original_driver(driver, event, remaining)

        with (
            patch.object(calibration_tests, "cuw", logical_seven_cuw),
            patch.object(vendor_tests, "context", padded_context),
            patch.object(vendor_tests.TypedDriver, "__call__", padded_file_replies),
        ):
            engine, controller, session, _driver, _runtime, actions, _key = (
                make_authentic_sbr_replay_fixture(self, data=b"12345678")
            )
        with engine.controller_execution(controller, 1):
            session._bind_control_prelude2026(engine, controller, controller.runtime)
            device = engine.engine_runtime_device()
            device.open()
            device.connect(6)
            result = controller.execute(engine, session)
            control = controller.native_control_context2026(engine)
            scratch = (control.count_scratch, control.percentage_scratch)
            published = (
                engine.dh_state._transferred_bytes,
                engine.dh_state._progress,
                engine.worker._previous_percentages2026,
            )

        self.assertTrue(result["native_return"])
        self.assertEqual(
            tuple(
                (a["operation"], a.get("transferred_bytes", a.get("progress")))
                for a in actions
            ),
            (
                ("notify_progress_count", 0),
                ("notify_progress_percent", 57),
                ("notify_progress_count", 4),
                ("notify_progress_percent", 114),
            ),
        )
        self.assertEqual(scratch, ((8,) + (0,) * 15, (114,) + (0,) * 15))
        self.assertEqual(
            published,
            ((4,) + (0,) * 15, (114,) + (0,) * 15, (57,) + (0,) * 15),
        )

    def test_double_1_of_49_arithmetic_uses_source_truncation(self):
        from tests.test_programming_replay import make_authentic_sbr_replay_fixture

        engine, controller, session, _driver, _runtime, actions, _key = (
            make_authentic_sbr_replay_fixture(
                self,
                data=bytes(range(49)),
                block_response=bytes.fromhex("74200007"),
            )
        )
        with engine.controller_execution(controller, 1):
            session._bind_control_prelude2026(engine, controller, controller.runtime)
            device = engine.engine_runtime_device()
            device.open()
            device.connect(6)
            result = controller.execute(engine, session)
            control = controller.native_control_context2026(engine)
            scratch = (control.count_scratch, control.percentage_scratch)
            published = (
                engine.dh_state._transferred_bytes,
                engine.dh_state._progress,
                engine.worker._previous_percentages2026,
            )

        count_actions = tuple(
            action["transferred_bytes"]
            for action in actions
            if action["operation"] == "notify_progress_count"
        )
        self.assertTrue(result["native_return"])
        self.assertEqual(count_actions[:2], (0, 0))
        self.assertEqual(len(count_actions), 49)
        self.assertEqual(
            scratch,
            ((49,) + (0,) * 15, (100,) + (0,) * 15),
        )
        self.assertEqual(
            published,
            (
                (48,) + (0,) * 15,
                (100,) + (0,) * 15,
                (97,) + (0,) * 15,
            ),
        )

    def test_live_complete_scratch_skips_without_final_progress_flush(self):
        from tests.test_programming_replay import make_authentic_sbr_replay_fixture

        engine, controller, session, _driver, _runtime, actions, _key = (
            make_authentic_sbr_replay_fixture(self)
        )
        rows = session.trace.rows
        if type(rows) is not list:
            raise TypeError("Mutable skip trace rows required")
        mode_on_index = next(
            index
            for index, row in enumerate(rows)
            if row["request"].get("operation") == "set_communication_log_mode"
            and row["request"].get("mode") == 2
        )
        mode_off_index = next(
            index
            for index, row in enumerate(rows[mode_on_index + 1 :], mode_on_index + 1)
            if row["request"].get("operation") == "set_communication_log_mode"
            and row["request"].get("mode") == 0
        )
        final_clock_index = next(
            index
            for index, row in enumerate(rows[mode_off_index + 1 :], mode_off_index + 1)
            if row["request"].get("operation") == "get_local_milliseconds_of_day"
        )
        mode_off, final_clock = rows[mode_off_index], rows[final_clock_index]
        rows[mode_on_index + 1 : mode_off_index] = [mode_off, final_clock]
        with engine.controller_execution(controller, 1):
            session._bind_control_prelude2026(engine, controller, controller.runtime)
            engine.worker._control_count_scratch2026[0] = 4
            engine.worker._control_percent_scratch2026[0] = 100
            device = engine.engine_runtime_device()
            device.open()
            device.connect(6)
            result = controller.execute(engine, session)
            control = controller.native_control_context2026(engine)
            scratch = (control.count_scratch[0], control.percentage_scratch[0])
            published = (
                engine.dh_state._transferred_bytes[0],
                engine.dh_state._progress[0],
            )

        self.assertTrue(result["native_return"])
        self.assertTrue(
            any(report.get("native_skipped_completed") for report in result["exports"])
        )
        self.assertEqual(scratch, (4, 100))
        self.assertEqual(published, (0, 0))
        self.assertEqual(actions, [])

    def test_reset_count_observer_fault_stops_before_percent_reset(self):
        from tests.test_programming_replay import make_authentic_sbr_replay_fixture

        engine, controller, session, _driver, runtime, actions, _key = (
            make_authentic_sbr_replay_fixture(self)
        )
        rows = session.trace.rows
        if type(rows) is not list:
            raise TypeError("Mutable reset-fault trace rows required")
        write_index = next(
            index
            for index, row in enumerate(rows)
            if row["request"].get("operation") == "passthru_write"
            and row["request"]["messages"][0]["data"]["value"].startswith(
                "000007e03601"
            )
        )
        response_index = next(
            index
            for index, row in enumerate(rows[write_index + 1 :], write_index + 1)
            if row["request"].get("operation") == "passthru_read"
            and row["result"]["value"]["value"]["value"][0]["value"]["data"][
                "value"
            ].startswith("000007e87601")
        )
        rows[response_index]["result"]["value"]["value"]["value"][0]["value"]["data"][
            "value"
        ] = "000007e87f3611"
        stop_filter_index = next(
            index
            for index, row in enumerate(rows[response_index + 1 :], response_index + 1)
            if row["request"].get("operation") == "passthru_stop_filter"
        )
        stop_filter = rows[stop_filter_index]
        final_clock_index = next(
            index
            for index, row in enumerate(
                rows[stop_filter_index + 1 :], stop_filter_index + 1
            )
            if row["request"].get("operation") == "get_local_milliseconds_of_day"
        )
        final_clock = rows[final_clock_index]
        rows[response_index + 1 : stop_filter_index] = []
        current_stop_filter_index = next(
            index for index, row in enumerate(rows) if row is stop_filter
        )
        rows[current_stop_filter_index + 1 :] = [final_clock]

        fault = OSError("reset count observer fault")
        trace_capture = runtime.action.__self__.consume
        recorded_action = trace_capture.recorded_consume

        def fail_after_count(kind, event, remaining=None):
            result = recorded_action(kind, event, remaining)
            if event.get("operation") == "notify_progress_count":
                raise fault
            return result

        trace_capture.recorded_consume = fail_after_count
        with engine.controller_execution(controller, 1):
            session._bind_control_prelude2026(engine, controller, controller.runtime)
            control = controller.native_control_context2026(engine)
            engine.worker._control_count_scratch2026[0] = 7
            engine.worker._control_percent_scratch2026[0] = 41
            device = engine.engine_runtime_device()
            device.open()
            device.connect(6)
            with self.assertRaises(OSError) as caught:
                controller.execute(engine, session)
            scratch = (control.count_scratch[0], control.percentage_scratch[0])
            published = (
                engine.dh_state._transferred_bytes[0],
                engine.dh_state._progress[0],
                engine.worker._previous_percentages2026,
            )

        self.assertIs(caught.exception, fault)
        self.assertEqual(scratch, (0, 41))
        self.assertEqual(published, (0, 0, ()))
        self.assertEqual(
            tuple(action["operation"] for action in actions),
            ("notify_progress_count",),
        )

    def test_typed_transfer_failure_resets_count_then_percent(self):
        from tests.test_programming_replay import make_authentic_sbr_replay_fixture

        engine, controller, session, _driver, _runtime, actions, _key = (
            make_authentic_sbr_replay_fixture(self)
        )
        rows = session.trace.rows
        if type(rows) is not list:
            raise TypeError("Mutable typed-failure trace rows required")
        write_index = next(
            index
            for index, row in enumerate(rows)
            if row["request"].get("operation") == "passthru_write"
            and row["request"]["messages"][0]["data"]["value"].startswith(
                "000007e03601"
            )
        )
        response_index = next(
            index
            for index, row in enumerate(rows[write_index + 1 :], write_index + 1)
            if row["request"].get("operation") == "passthru_read"
            and row["result"]["value"]["value"]["value"][0]["value"]["data"][
                "value"
            ].startswith("000007e87601")
        )
        response = rows[response_index]
        response["result"]["value"]["value"]["value"][0]["value"]["data"]["value"] = (
            "000007e87f3611"
        )
        stop_filter_index = next(
            index
            for index, row in enumerate(rows[response_index + 1 :], response_index + 1)
            if row["request"].get("operation") == "passthru_stop_filter"
        )
        stop_filter = rows[stop_filter_index]
        log_off_index = next(
            index
            for index, row in enumerate(rows[response_index + 1 :], response_index + 1)
            if row["request"].get("operation") == "set_communication_log_mode"
            and row["request"].get("mode") == 0
        )
        final_clock_index = next(
            index
            for index, row in enumerate(rows[log_off_index + 1 :], log_off_index + 1)
            if row["request"].get("operation") == "get_local_milliseconds_of_day"
        )
        final_clock = rows[final_clock_index]
        rows[response_index + 1 : stop_filter_index] = []
        current_stop_filter_index = next(
            index for index, row in enumerate(rows) if row is stop_filter
        )
        rows[current_stop_filter_index + 1 :] = [final_clock]
        reports = []
        original_call = controller._control_call2026
        boundary = OSError("stop after observing the returned family report")

        def stop_after_family_report(*args, **kwargs):
            report = original_call(*args, **kwargs)
            if args[3] == "StartFlashWrite":
                reports.append(report)
                raise boundary
            return report

        with engine.controller_execution(controller, 1):
            session._bind_control_prelude2026(engine, controller, controller.runtime)
            device = engine.engine_runtime_device()
            device.open()
            device.connect(6)
            with (
                patch.object(
                    controller,
                    "_control_call2026",
                    side_effect=stop_after_family_report,
                ),
                self.assertRaises(OSError) as caught,
            ):
                controller.execute(engine, session)
            control = controller.native_control_context2026(engine)
            scratch = (control.count_scratch[0], control.percentage_scratch[0])

        self.assertIs(caught.exception, boundary)
        self.assertEqual(len(reports), 1)
        self.assertFalse(reports[0]["native_return"])
        self.assertEqual(
            tuple(
                (
                    action["operation"],
                    action.get("transferred_bytes", action.get("progress")),
                )
                for action in actions
            ),
            (("notify_progress_count", 0), ("notify_progress_percent", 0)),
        )
        self.assertEqual(scratch, (0, 0))

    def test_host_faults_preserve_each_count_percent_publication_boundary(self):
        from tests.test_programming_replay import make_authentic_sbr_replay_fixture

        for fault_operation in (
            "notify_progress_count",
            "notify_progress_percent",
        ):
            with self.subTest(operation=fault_operation):
                engine, controller, session, _driver, runtime, actions, _key = (
                    make_authentic_sbr_replay_fixture(self, data=b"DATA1234")
                )
                fault = OSError("observer fault")
                chronology = []
                trace_capture = runtime.action.__self__.consume
                recorded_action = trace_capture.recorded_consume
                original_runtime_call = runtime.call

                def record_source_call(
                    operation,
                    *,
                    chronology=chronology,
                    original_runtime_call=original_runtime_call,
                    **kwargs,
                ):
                    if operation in (
                        "notify_progress_count",
                        "notify_progress_percent",
                    ):
                        chronology.append(("callback", operation))
                    return original_runtime_call(operation, **kwargs)

                def record_actual_wire_then_fault(
                    kind,
                    event,
                    remaining=None,
                    *,
                    chronology=chronology,
                ):
                    if kind == "action" and event.get("operation") == "passthru_write":
                        for message in event["messages"]:
                            payload = message.data[4:]
                            if payload.startswith(b"\x36"):
                                chronology.append(("block", payload))
                            elif payload == b"\x3e\x80":
                                chronology.append(("tester", payload))
                    return fail_after_publication(kind, event, remaining)

                def fail_after_publication(
                    kind,
                    event,
                    remaining=None,
                    action=recorded_action,
                    operation=fault_operation,
                    failure=fault,
                ):
                    result = action(kind, event, remaining)
                    if event.get("operation") == operation:
                        raise failure
                    return result

                runtime.call = record_source_call
                trace_capture.recorded_consume = record_actual_wire_then_fault
                with engine.controller_execution(controller, 1):
                    session._bind_control_prelude2026(
                        engine, controller, controller.runtime
                    )
                    device = engine.engine_runtime_device()
                    device.open()
                    device.connect(6)
                    with self.assertRaises(OSError) as caught:
                        try:
                            controller.execute(engine, session)
                        except OSError:
                            rows = session.trace.rows
                            if type(rows) is not list:
                                raise TypeError("Mutable fault-trace rows required")
                            final_clock_index = next(
                                index
                                for index in range(len(rows) - 1, -1, -1)
                                if rows[index]["request"].get("operation")
                                == "get_local_milliseconds_of_day"
                            )
                            rows.insert(
                                session.trace.position,
                                rows.pop(final_clock_index),
                            )
                            raise
                    control = controller.native_control_context2026(engine)
                    scratch = (control.count_scratch, control.percentage_scratch)
                    published = (
                        engine.dh_state._transferred_bytes,
                        engine.dh_state._progress,
                        engine.worker._previous_percentages2026,
                    )

                self.assertIs(caught.exception, fault)
                block_index = next(
                    index
                    for index, item in enumerate(chronology)
                    if item[0] == "block" and item[1][1] == 1
                )
                tester_index = next(
                    index
                    for index, item in enumerate(chronology)
                    if index > block_index and item[0] == "tester"
                )
                count_index = next(
                    index
                    for index, item in enumerate(chronology)
                    if item == ("callback", "notify_progress_count")
                )
                self.assertLess(block_index, tester_index)
                self.assertLess(tester_index, count_index)
                if fault_operation == "notify_progress_count":
                    self.assertEqual(scratch[0][0], 0)
                    self.assertEqual(scratch[1][0], 0)
                    self.assertEqual(published[0][0], 0)
                    self.assertEqual(published[1][0], 0)
                    self.assertEqual(
                        tuple(item["operation"] for item in actions),
                        ("notify_progress_count",),
                    )
                else:
                    self.assertEqual(scratch[0][0], 4)
                    self.assertEqual(scratch[1][0], 50)
                    self.assertEqual(published[0][0], 0)
                    self.assertEqual(published[1][0], 50)
                    self.assertEqual(published[2][0], 0)
                    self.assertEqual(
                        tuple(item["operation"] for item in actions),
                        ("notify_progress_count", "notify_progress_percent"),
                    )

    def test_scoped_two_cpu_loop_uses_issued_entry_and_keeps_count_lag(self):
        import copy

        from scripts.calibration_2026 import native2026_global_cpu_index
        from tests.test_programming_replay import make_authentic_sbr_replay_fixture

        (
            capture_engine,
            capture_controller,
            capture_session,
            _driver,
            _runtime,
            capture_actions,
            _key,
        ) = make_authentic_sbr_replay_fixture(self, data=b"DATA1234", cpu_count=2)
        entry_targets = []
        entry_globals = []
        scoped_callback_indices = []

        def execute(engine, controller, session):
            original_call = controller._control_call2026
            original_runtime_call = controller.runtime.call

            def capture_progress_scope(operation, **kwargs):
                if operation in ("notify_progress_count", "notify_progress_percent"):
                    active = controller.runtime._device_calls.control_export
                    scoped_callback_indices.append(
                        (active[2].entry_cpu_index, kwargs["cpu_index"])
                    )
                return original_runtime_call(operation, **kwargs)

            def capture_entry(*args, **kwargs):
                target = args[2]
                if args[3] == "StartFlashWrite":
                    entry_targets.append(target.entry_cpu_index)
                    entry_globals.append(
                        native2026_global_cpu_index(target.binding.metadata)
                    )
                return original_call(*args, **kwargs)

            controller._control_call2026 = capture_entry
            controller.runtime.call = capture_progress_scope
            with engine.controller_execution(controller, 1):
                session._bind_control_prelude2026(
                    engine, controller, controller.runtime
                )
                engine.worker._control_count_scratch2026[0:3] = [2, 6, 9]
                engine.worker._control_percent_scratch2026[0:3] = [37, 25, 11]
                device = engine.engine_runtime_device()
                device.open()
                device.connect(6)
                result = controller.execute(engine, session)
                control = controller.native_control_context2026(engine)
                scratch = (control.count_scratch, control.percentage_scratch)
                published = (
                    engine.dh_state._transferred_bytes,
                    engine.dh_state._progress,
                    engine.worker._previous_percentages2026,
                )
            return result, scratch, published

        capture_result, _scratch, _published = execute(
            capture_engine, capture_controller, capture_session
        )
        self.assertTrue(capture_result["native_return"])
        self.assertEqual(
            capture_session.trace.position, len(capture_session.trace.rows)
        )
        captured_actions = tuple(copy.deepcopy(capture_actions))
        frozen_events = tuple(copy.deepcopy(capture_session.trace.rows))

        engine, controller, session, _driver, _runtime, actions, _key = (
            make_authentic_sbr_replay_fixture(
                self,
                data=b"DATA1234",
                cpu_count=2,
                events_override=frozen_events,
                capture_progress=False,
            )
        )
        result, scratch, published = execute(engine, controller, session)

        self.assertEqual(actions, [])
        self.assertTrue(result["native_return"])
        self.assertEqual(session.trace.position, len(frozen_events))
        self.assertEqual(
            tuple(
                event["request"]
                for event in frozen_events
                if event.get("request", {}).get("operation")
                in ("notify_progress_count", "notify_progress_percent")
            ),
            captured_actions,
        )
        self.assertEqual(entry_targets, [0, 1, 0, 1])
        self.assertEqual(entry_globals, [0, 1, 0, 1])
        self.assertEqual(
            scoped_callback_indices,
            [
                *((0, 0),) * 4,
                *((0, 1),) * 4,
                *((0, 0),) * 4,
                *((0, 1),) * 4,
            ],
        )
        self.assertEqual(actions, [])
        writes = [
            event["request"]["messages"][0]["data"]["value"]
            for event in frozen_events
            if event.get("request", {}).get("operation") == "passthru_write"
            and event["request"]["messages"][0]["data"]["value"].startswith(
                ("000007e036", "000007e136")
            )
        ]
        self.assertEqual(
            [value[:20] for value in writes],
            [
                "000007e0360100001000",
                "000007e0360200001004",
                "000007e1360100002000",
                "000007e1360200002004",
            ],
        )
        self.assertEqual(
            tuple(
                (
                    action["operation"],
                    action["cpu_index"],
                    action.get("transferred_bytes", action.get("progress")),
                )
                for action in captured_actions
            ),
            (
                ("notify_progress_count", 0, 2),
                ("notify_progress_percent", 0, 50),
                ("notify_progress_count", 0, 4),
                ("notify_progress_percent", 0, 100),
                ("notify_progress_count", 1, 6),
                ("notify_progress_percent", 1, 50),
                ("notify_progress_count", 1, 4),
                ("notify_progress_percent", 1, 100),
            ),
        )
        self.assertEqual(
            scratch,
            ((8, 8, 9) + (0,) * 13, (100, 100, 11) + (0,) * 13),
        )
        self.assertEqual(
            published,
            (
                (8, 4, 9) + (0,) * 13,
                (100, 100, 11) + (0,) * 13,
                (100, 50, 11) + (0,) * 13,
            ),
        )

        import csv
        import io
        from unittest.mock import patch

        import tests.test_calibration_2026 as calibration_tests
        import tests.test_programming_2026_common as common_tests
        import tests.test_programming_replay as replay_tests
        from scripts.calibration import decode_cuw_text
        from tests.test_cuw_engine_worker import encoded_table

        original_cuw = calibration_tests.cuw
        original_factory = common_tests.make_raw_control_fixture2026
        for loop_flag in (1, 0):
            with self.subTest(future_cpu_loop_flag=loop_flag):
                invalid_sources = []

                def remember_invalid_cpu(
                    text,
                    records,
                    *,
                    _invalid_sources=invalid_sources,
                    **kwargs,
                ):
                    if "[File2001]\nALFID=44" in text:
                        _invalid_sources[:] = [
                            original_cuw(
                                text.replace(
                                    "[File2001]\nALFID=44",
                                    "[File2001]\nALFID=00",
                                ),
                                records,
                                **kwargs,
                            )
                        ]
                    return original_cuw(text, records, **kwargs)

                def issue_invalid_future_source(
                    *args,
                    _invalid_sources=invalid_sources,
                    _loop_flag=loop_flag,
                    **kwargs,
                ):
                    self.assertTrue(_invalid_sources)
                    kwargs["source"] = _invalid_sources[0]
                    catalog = dict(kwargs["catalog"])
                    for name, payload in catalog.items():
                        rows = list(
                            csv.reader(io.StringIO(decode_cuw_text(payload).decode()))
                        )
                        if "CpuLoopBetweenPrepareAndWriteFlag" not in rows[0]:
                            continue
                        column = rows[0].index("CpuLoopBetweenPrepareAndWriteFlag")
                        for row in rows[1:]:
                            row[column] = str(_loop_flag)
                        catalog[name] = encoded_table(
                            tuple(rows[0]), tuple(tuple(row) for row in rows[1:])
                        )
                    kwargs["catalog"] = catalog
                    return original_factory(*args, **kwargs)

                with (
                    patch.object(calibration_tests, "cuw", remember_invalid_cpu),
                    patch.object(
                        common_tests,
                        "make_raw_control_fixture2026",
                        issue_invalid_future_source,
                    ),
                ):
                    lazy_engine, lazy_controller, lazy_session, *_ = (
                        replay_tests.make_authentic_sbr_replay_fixture(
                            self, data=b"DATA1234", cpu_count=2
                        )
                    )
                with lazy_engine.controller_execution(lazy_controller, 1):
                    lazy_session._bind_control_prelude2026(
                        lazy_engine, lazy_controller, lazy_controller.runtime
                    )
                    device = lazy_engine.engine_runtime_device()
                    device.open()
                    device.connect(6)
                    if loop_flag:
                        result = lazy_controller.execute(lazy_engine, lazy_session)
                        self.assertTrue(result["native_return"])
                    else:
                        with self.assertRaisesRegex(
                            ValueError, "SBR file requires explicit segment"
                        ):
                            lazy_controller.execute(lazy_engine, lazy_session)
                    consumed = lazy_session.trace.rows[: lazy_session.trace.position]
                block_writes = [
                    event["request"]["messages"][0]["data"]["value"]
                    for event in consumed
                    if event["request"].get("operation") == "passthru_write"
                    and event["request"]["messages"][0]["data"]["value"].startswith(
                        "000007e036"
                    )
                ]
                self.assertEqual(len(block_writes), 2)
                self.assertTrue(all("0000100" in value for value in block_writes))

    def test_actual_prepare_read_publishes_before_later_auth_fault(self):
        for central, cpu_type, response, expected in (
            (False, "282", b"\x62\xf1\0\xe0\xa2\0", 0xE0),
            (True, "283", b"\x62\xf1\0\xe0\xa2\0", 0xA2),
        ):
            with self.subTest(central=central):
                ctx = context(
                    "TCUWCanSBRPrepareWriter.dll",
                    cpu_type=cpu_type,
                    FlagToCentralGateway="1" if central else "0",
                )
                replay = Replay((response,))
                runtime = replay.runtime()

                class Worker:
                    def _bind_sbr_ssm_producer2026(self, utility, target):
                        self.utility, self.target = utility, target
                        self.published = []

                    def publish_sbr_ssm2026(self, utility):
                        if utility is not self.utility:
                            raise AssertionError("Different SBR utility published")
                        self.published.append(utility.ssm)

                worker = Worker()
                engine = SimpleNamespace(worker=worker)
                target = object()
                controller = SimpleNamespace(runtime=runtime)
                runtime._device_calls.control_export = (engine, controller, target)
                fault = OSError("later authorization fault")
                replay.replies = iter((response, b"\x67\x01\x01" + bytes(3)))

                def reject_key(*_args, failure=fault):
                    raise failure

                with (
                    patch.object(SBRUtils2026, "extended_session"),
                    patch.object(SBRUtils2026, "collate_gateway"),
                    patch.object(SBRUtils2026, "central_gateway_routine"),
                    patch.object(SBRUtils2026, "diagnostic_mask"),
                    patch.object(SBRUtils2026, "stop_communication"),
                    patch.object(SBRUtils2026, "wait_after"),
                    self.assertRaisesRegex(OSError, "later authorization fault"),
                ):
                    prepare_sbr(
                        ctx,
                        runtime,
                        key_provider=reject_key,
                        gateway_key_provider=lambda _: bytes(256),
                    )
                self.assertEqual(worker.published, [expected])
                self.assertIs(worker.utility.context, ctx)

    def test_standalone_utility_keeps_ssm_local(self):
        ctx = context("TCUWCanSBRPrepareWriter.dll")
        replay = Replay((b"\x62\xf1\0\x12\x34\0",))
        utility = SBRUtils2026(VendorCAN2026(replay.runtime(), ctx.addresses[0]))
        utility.read_ssm()
        self.assertEqual(utility.ssm, 0x12)
        self.assertFalse(utility._control_ssm_issued)


class SBRTests(unittest.TestCase):
    def test_secret_selection_and_cipher_round_boundaries(self):
        self.assertEqual(sbr_secret_type("282", 0xE0), 4)
        self.assertEqual(sbr_secret_type("294", 0x16), 16)
        with self.assertRaises(CommonResponseError):
            sbr_secret_type("001", 0)
        table = bytes(range(16)) * 2
        self.assertEqual(sbr_cipher_function(0, 0, table), 0)
        self.assertEqual(sbr_des_key(bytes(4), bytes(32), table), bytes(4))
        with self.assertRaises(ValueError):
            sbr_cipher_function(0, 0, bytes(31))

    def test_functional_wait_flags_preserve_native_order(self):
        ctx = context("TCUWCanSBRPrepareWriter.dll")
        for flag, waits in ((False, [120, 100]), (True, [150, 60, 120, 100, 60])):
            p = Replay()
            utility = SBRUtils2026(
                VendorCAN2026(p.runtime(), ctx.addresses[0]), wait_after_function=flag
            )
            utility.diagnostic_mask()
            utility.stop_communication()
            self.assertEqual(
                [e["milliseconds"] for e in p.events if e["operation"] == "wait"], waits
            )
            self.assertEqual(
                [d[4:] for d in p.writes],
                [b"\x85\x02", b"\x3e\x80", b"\x28\x03\x01", b"\x3e\x80"],
            )

    def test_sbr_writer_native_address_counter_and_periodic_cleanup(self):
        p = Replay(
            (
                b"\x71\x01\xff\0",
                b"\x74\x20\x00\x0a",
                b"\x76\x01",
                b"\x77",
                b"\x71\x01\xff\x01\x01",
            )
        )
        runtime = p.runtime()
        result = run_native(context("TCUWCanSBRFlashWriter.dll"), runtime)
        self.assertEqual(result["transferred"], 4)
        self.assertIn(bytes.fromhex("000007e0360100001000") + b"DATA", p.writes)
        self.assertFalse(runtime._resources)
        self.assertEqual(
            sum(e["operation"] == "start_sync_periodic" for e in p.events), 2
        )


class TypedDriver:
    def __init__(self, replies, *, fault=None):
        self.replies = {request: list(values) for request, values in replies.items()}
        self.pending = []
        self.events = []
        self.fault = fault
        self.now = 0.0
        self.device = J2534Device2026(
            self, clock=lambda: self.now, background_workers=False
        )
        self.device.open()
        self.device.connect(6)

    def __call__(self, event, remaining):
        self.events.append(event)
        op = event["operation"]
        if self.fault == op:
            return PrimitiveResult(status=9)
        if op == "passthru_write":
            for message in event["messages"]:
                self.pending.append((NativeMessage(6, message.data[:4], rx_status=9),))
                request = message.data[4:]
                if request in self.replies:
                    answer = self.replies[request].pop(0)
                    response_id = (
                        int.from_bytes(message.data[:4], "big") + 8
                    ).to_bytes(4, "big")
                    self.pending.append((NativeMessage(6, response_id + answer),))
            return PrimitiveResult(value=event["count"])
        if op == "passthru_read":
            return PrimitiveResult(value=self.pending.pop(0) if self.pending else ())
        if op in (
            "passthru_open",
            "passthru_connect",
            "passthru_start_filter",
            "create_mutex",
        ):
            return PrimitiveResult(value=7)
        if op == "local_time_ms":
            return PrimitiveResult(value=int(self.now * 1000))
        if op == "wait":
            self.now += event["milliseconds"] / 1000
        return PrimitiveResult()

    def runtime(self):
        return NativeRuntime2026(
            self.device.primitive,
            clock=lambda: self.now,
            timeout=60,
            native_cancelled=lambda: False,
        )

    @property
    def payloads(self):
        return [
            m.data[4:]
            for e in self.events
            if e["operation"] == "passthru_write"
            for m in e["messages"]
        ]


class NativeCompositionTests(unittest.TestCase):
    def test_sbr_prepare_actual48_gateway_zero_seed_and_session(self):
        p = TypedDriver(
            {
                b"\x27\x33": [b"\x67\x33" + bytes(range(16))],
                b"\x27\x34" + bytes(256): [b"\x67\x34"],
                b"\x31\x01\x02\0": [b"\x71\x01\x02\0"],
                b"\x31\x01\x02\x01": [b"\x71\x01\x02\x01"],
                b"\x22\xf1\0": [b"\x62\xf1\0\xe0\0\0"],
                b"\x27\x01": [b"\x67\x01" + bytes(4)],
                b"\x10\x02": [b"\x50\x02"],
            }
        )
        called = []
        runtime = p.runtime()
        result = run_native(
            context("TCUWCanSBRPrepareWriter.dll"),
            runtime,
            key_provider=lambda *args: called.append(args),
            gateway_key_provider=lambda seed: bytes(256),
        )
        self.assertEqual(result["state"], "prepare_completed")
        self.assertEqual(called, [])
        self.assertIsNone(p.device.sync)
        self.assertEqual(p.device.filters, [])
        self.assertFalse(runtime._resources)
        self.assertIn(b"\x10\x63", p.payloads)
        self.assertIn(b"\x28\x03\x01", p.payloads)

    def test_sbr_writer_actual48_periodic_mutex_cleanup(self):
        area = bytes.fromhex("440000100000000004")
        p = TypedDriver(
            {
                b"\x31\x01\xff\0" + area: [b"\x71\x01\xff\0"],
                b"\x34\x04" + area: [b"\x74\x20\0\x0a"],
                bytes.fromhex("360100001000") + b"DATA": [b"\x76\x01"],
                b"\x37": [b"\x77"],
                b"\x31\x01\xff\x01" + area: [b"\x71\x01\xff\x01\x01"],
            }
        )
        runtime = p.runtime()
        self.assertEqual(
            run_native(context("TCUWCanSBRFlashWriter.dll"), runtime)["state"],
            "writer_completed",
        )
        self.assertIsNone(p.device.sync)
        self.assertFalse(runtime._resources)
        self.assertEqual(sum(e["operation"] == "close_handle" for e in p.events), 2)

    def test_sbr_internal_two_cpu_loop_uses_each_native_address(self):
        replies = (
            b"\x71\x01\xff\0",
            b"\x74\x20\0\x0a",
            b"\x76\x01",
            b"\x77",
            b"\x71\x01\xff\x01\x01",
        ) * 2
        p = Replay(replies)
        notifications = []
        ctx = context(
            "TCUWCanSBRFlashWriter.dll",
            cpu_count=2,
            cpu_type_second="283",
            CpuLoopBetweenPrepareAndWriteFlag="0",
        )
        runtime = p.runtime()
        result = run_native(
            ctx, runtime, notify=lambda k, v: notifications.append((k, v))
        )
        self.assertEqual(result["transferred"], 8)
        self.assertEqual(result["next_cpu_index"], 2)
        self.assertEqual(ctx.selection.metadata.cpus[1].values["cputype"], "283")
        self.assertIn(("next_cpu", 1), notifications)
        self.assertFalse(
            any(e["operation"] == "wait" and e["milliseconds"] for e in p.events)
        )
        writes = [v for v in p.writes if v[4:6] == b"\x36\x01"]
        self.assertEqual(
            [v[:4] for v in writes],
            [bytes.fromhex("000007e0"), bytes.fromhex("000007e1")],
        )
        self.assertFalse(runtime._resources)

    def test_hino_dss_shared_actual37_helper_and_prepare_retry(self):
        for name, export in (
            ("TCUWCanHINOPrepareWriterForDSS.dll", None),
            ("TCUWCanHINOFlashWriterForDSS.dll", "PrepareRetry"),
        ):
            p = Replay((b"\x50\x85", b"\x67\x03\x01\x02\x03\x04", b"\x67\x04\x34"))
            result = run_native(context(name), p.runtime(), entrypoint=export)
            self.assertEqual(result["state"], "prepare_completed")
            self.assertIn(bytes.fromhex("000007e02704fefdfcfb"), p.writes)
            self.assertEqual(p.filters, [])

    def test_vcs_native_three_attempt_retry_and_malformed_no_retry(self):
        p = Replay(
            (
                b"\x7f\x10\x11",
                b"\x7f\x10\x11",
                b"\x50",
                b"\x67\x01" + bytes(12),
                b"\x67\x02",
            )
        )
        result = run_native(context("TCUWCanHINOPrepareWriterForVCS.dll"), p.runtime())
        self.assertEqual(result["state"], "prepare_completed")
        self.assertEqual(sum(v[4:] == b"\x10\x02" for v in p.writes), 3)
        p = Replay((b"wrong",))
        result = run_native(context("TCUWCanHINOPrepareWriterForVCS.dll"), p.runtime())
        self.assertEqual(result["state"], "failed")
        self.assertEqual(sum(v[4:] == b"\x10\x02" for v in p.writes), 1)

    def test_context_archive_target_and_selected_row_mutations_fail_before_io(self):
        ctx = context("TCUWCanHINOFlashWriter.dll")
        for changed in (
            replace(ctx, image_size=5),
            replace(ctx, addresses=ctx.addresses[::-1] + ctx.addresses),
            replace(ctx, selection=replace(ctx.selection, source_sha256="0" * 64)),
        ):
            p = Replay()
            with self.assertRaises(ValueError):
                run_native(changed, p.runtime())
            self.assertEqual(p.events, [])


class AllSBRExportsTests(unittest.TestCase):
    def test_every_exact18_callable_export_executes(self):
        identity = identify_native_module(
            "44d2a46a951652937d3a3524b18ffba37cc58af2128677f5b8b89b4e537e5638",
            "TCUWSBRUtils.dll",
        )
        cases = {
            "constructor": ((), {}),
            "CalcCipherFuncF": (
                (),
                {"value": 0x1234, "key": 0x5678},
            ),
            "CalcSeedKey": (
                (),
                {
                    "seed": bytes(16),
                    "key_provider": lambda kind, seed, aes, encrypt: bytes(16),
                },
            ),
            "CalcSeedKeyForDES": (
                (),
                {
                    "seed": bytes(4),
                    "key": bytes(32),
                    "substitution": bytes(range(16)) * 2,
                },
            ),
            "CollateSeedKey": (
                (b"\x62\xf1\0\xe0\0\0", b"\x67\x01" + bytes(4)),
                {"key_provider": lambda *args: bytes(4)},
            ),
            "CollateSeedKeyForCentralGW": (
                (b"\x67\x33" + bytes(16), b"\x67\x34"),
                {"key_provider": lambda seed: bytes(256)},
            ),
            "DiagnosticMask": ((), {}),
            "ExtendedDiagnosticSessionControl": ((), {}),
            "GetSecretInfoType": ((), {}),
            "ProgrammingSessionControl": ((b"\x50\x02",), {}),
            "ProgrammingSessionControlForMaster": ((b"\x50\x02",), {}),
            "ReadSSMID": ((b"\x62\xf1\0\xe0\0\0",), {}),
            "RoutineControlForCentralGW": ((b"\x71\x01\x02\0",), {"mode": 0}),
            "SendTesterPresent": ((), {}),
            "StartSyncPeriodicMsg": ((), {}),
            "StopCommunication": ((), {}),
            "UnitStatusCheck": ((b"\x62\x10\x1c\x01",), {}),
            "WaitAfterFuncReq": ((), {"milliseconds": 60}),
        }
        visited = set()
        for export in identity.callable_exports:
            name = (
                "constructor"
                if export.startswith("??0")
                else export.split("@", 1)[0][1:]
            )
            with self.subTest(export=name):
                replies, kwargs = cases[name]
                p = Replay(replies)
                runtime = p.runtime()
                utility = bind_sbr_utility(
                    identity,
                    context("TCUWCanSBRPrepareWriter.dll", cpu_count=2),
                    runtime,
                )
                utility.ssm = 0xE0
                utility.substitution = bytes(range(16)) * 2
                execute_sbr_utility(utility, export, **kwargs)
                if name == "StartSyncPeriodicMsg":
                    utility.stop_periodic()
                self.assertFalse(runtime._resources)
                # Replay establishes authored request/reply pairing; execute the
                # same exact export again through the concrete typed48 device.
                wire_replies = {}
                answers = iter(replies)
                request = b""
                for event in p.events:
                    if event["operation"] == "write_messages":
                        request = event["data"][4:]
                    elif event["operation"] == "read_specified_can_message":
                        wire_replies.setdefault(request, []).append(next(answers))
                driver = TypedDriver(wire_replies)
                actual_runtime = driver.runtime()
                actual = bind_sbr_utility(
                    identity,
                    context("TCUWCanSBRPrepareWriter.dll", cpu_count=2),
                    actual_runtime,
                )
                actual.ssm = 0xE0
                actual.substitution = bytes(range(16)) * 2
                execute_sbr_utility(actual, export, **kwargs)
                if name == "StartSyncPeriodicMsg":
                    actual.stop_periodic()
                self.assertFalse(actual_runtime._resources)
                self.assertEqual(driver.device.filters, [])
                self.assertIsNone(driver.device.sync)
                driver.device.close()
                visited.add(name)
        self.assertEqual(visited, set(cases))
        self.assertEqual(len(visited), 18)

    def test_nonzero_crypto_selects_native_secret_type_and_flags(self):
        ctx = context(
            "TCUWCanSBRPrepareWriter.dll",
            cpu_count=2,
            cpu_index=1,
            FlagToEncryptLogicForAES="1",
            FlagToCalcKeyLogicForEncrypt="1",
        )
        p = Replay(
            (
                b"\x62\xf1\0\xe0\0\0",
                b"\x67\x01" + bytes(range(16)),
                b"\x67\x02",
                b"\x50\x02",
            )
        )
        observed = []

        def crypto(kind, seed, aes, encrypt):
            observed.append((kind, seed, aes, encrypt))
            return b"x" * 16

        result = run_native(
            ctx,
            p.runtime(),
            key_provider=crypto,
            gateway_key_provider=lambda _: bytes(256),
        )
        self.assertEqual(result["state"], "prepare_completed")
        self.assertEqual(observed, [(4, bytes(range(16)), True, True)])
        self.assertIn(bytes.fromhex("000007e02702") + b"x" * 16, p.writes)

    def test_dss_failure_returns_literal_native_error_and_notification_status(self):
        ctx = context(
            "TCUWCanHINOPrepareWriterForDSS.dll",
            native_observations={"native_writing": True},
        )
        p = Replay((b"\x50\x85", b"\x67\x03\x01\x02\x03\x04", b"\x7f\x27\x35"))
        result = run_native(ctx, p.runtime())
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["native_error_code"], 17)
        self.assertEqual(result["native_result_code"], 2)
        self.assertEqual(p.filters, [])

    def test_sbr_padding_underflow_rejected_and_periodics_released(self):
        ctx = context("TCUWCanSBRFlashWriter.dll", FlagToDataBlockPadding="1")
        p = Replay((b"\x71\x01\xff\0", b"\x74\x20\0\x0b"))
        runtime = p.runtime()
        with self.assertRaisesRegex(ValueError, "beyond imported archive"):
            run_native(ctx, runtime)
        self.assertFalse(runtime._resources)
        self.assertFalse(any(v[4:5] == b"\x36" for v in p.writes))


class NativeFaultAndStateTests(unittest.TestCase):
    def test_sbr_completed_cpu_resume_skips_wire_and_filter(self):
        ctx = context(
            "TCUWCanSBRFlashWriter.dll",
            native_observations={"native_counts": (4,), "native_percentages": (100,)},
        )
        p = Replay()
        result = run_native(ctx, p.runtime())
        self.assertTrue(result["native_skipped_completed"])
        self.assertEqual(result["next_cpu_index"], 0)
        self.assertEqual(p.events, [{"operation": "set_timeout", "milliseconds": 5000}])

    def test_writer_failure_preserves_native_stage_and_reset_callbacks(self):
        p = Replay((b"\x7f\x34\x11", b"\x71\xa0\0", b"\x7f\x34\x22"))
        events = []
        result = run_native(
            context("TCUWCanHINOFlashWriterForDSS.dll"),
            p.runtime(),
            notify=lambda k, v: events.append((k, v)),
        )
        self.assertEqual(
            (
                result["state"],
                result["native_error_code"],
                result["native_result_code"],
            ),
            ("failed", 26, 2),
        )
        self.assertEqual(events, [("writing", 1), ("count", 0), ("percent", 0)])
        self.assertEqual(p.filters, [])

    def test_native_ordinary_loader_nrc31_is_skipped(self):
        p = Replay(
            (
                b"\x7f\x34\x31",
                b"\x71\x01\x10\xfd\0",
                b"\x74\x10\x06",
                b"\x76\x01",
                b"\x77",
                b"\x71\x01\x10\xfe\0",
                b"\x71\x01\x10\xfc\0",
                b"\x51\x01",
            )
        )
        result = run_native(context("TCUWCanHINOFlashWriter.dll"), p.runtime())
        self.assertEqual(result["state"], "writer_completed")
        self.assertFalse(any(v[4:] == bytes.fromhex("310110ff") for v in p.writes))

    def test_sbr_retry_short_branch_only_gateway_and_native_periodics(self):
        p = Replay(
            (
                b"\x67\x33" + bytes(16),
                b"\x67\x34",
                b"\x71\x01\x02\0",
                b"\x71\x01\x02\x01",
            )
        )
        runtime = p.runtime()
        result = run_native(
            context("TCUWCanSBRFlashWriter.dll"),
            runtime,
            entrypoint="PrepareRetry",
            key_provider=lambda *args: self.fail(
                "No main authorization in native short branch"
            ),
            gateway_key_provider=lambda seed: bytes(256),
        )
        self.assertEqual(result["native_branch"], "retry_gateway_only")
        self.assertFalse(any(v[4:] == b"\x27\x01" for v in p.writes))
        self.assertFalse(runtime._resources)

    def test_deadline_during_native_wait_and_after_successful_write(self):
        p = Replay()
        runtime = NativeRuntime2026(p, timeout=0.5, clock=lambda: p.now)
        with self.assertRaises(TimeoutError):
            run_native(
                context("TCUWCanSBRPrepareWriter.dll"),
                runtime,
                key_provider=lambda *args: bytes(4),
                gateway_key_provider=lambda _: bytes(256),
            )
        self.assertFalse(p.writes)
        p = Replay()

        def action(event, remaining):
            result = p(event, remaining)
            if event["operation"] == "write_messages":
                p.now = 100
            return result

        runtime = NativeRuntime2026(action, clock=lambda: p.now)
        with self.assertRaises(TimeoutError):
            run_native(context("TCUWCanHINOFlashWriter.dll"), runtime)
        self.assertEqual(p.filters, [])
        self.assertFalse(runtime._resources)

    def test_native_sbr_missing_width_uses_zero_minimum_and_actual_five_byte_groups(
        self,
    ):
        p = Replay((b"\x62\xf1\x82",))
        ctx = context(
            "TCUWCanSBRSoftwareIDGetter.dll",
            FlagToSupportGetCID="0",
            SoftwareInfoROMIDByteNum="",
        )
        self.assertEqual(run_native(ctx, p.runtime())["identifiers"], ("0000000000",))

    def test_hino_writer_rejects_absent_shared_timing_before_io(self):
        with self.assertRaisesRegex(ValueError, r"context\+98c"):
            context(
                "TCUWCanHINOFlashWriter.dll",
                native_observations={"native_pending_timeout_ms": None},
            )
        p = Replay(
            (b"\x50\x02\x01\x23\x00\x64", b"\x67\x01\x00\x23\x00\x01", b"\x67\x02")
        )
        result = run_native(context("TCUWCanHINOPrepareWriter.dll"), p.runtime())
        self.assertEqual(result["native_pending_timeout_ms"], 1000)
        ctx = context(
            "TCUWCanHINOFlashWriter.dll",
            native_observations={
                "native_pending_timeout_ms": result["native_pending_timeout_ms"]
            },
        )
        self.assertEqual(ctx.native_pending_timeout_ms, 1000)

    def test_exported_substitution_data_is_shared_between_bound_utilities(self):
        identity = identify_native_module(
            "44d2a46a951652937d3a3524b18ffba37cc58af2128677f5b8b89b4e537e5638",
            "TCUWSBRUtils.dll",
        )
        ctx = context("TCUWCanSBRPrepareWriter.dll")
        one = bind_sbr_utility(identity, ctx, Replay().runtime())
        two = bind_sbr_utility(identity, ctx, Replay().runtime())
        previous = one.substitution
        try:
            one.substitution = bytes(range(16)) * 2
            self.assertEqual(two.substitution, one.substitution)
            export = next(
                e
                for e in identity.callable_exports
                if e.startswith("?CalcCipherFuncF@")
            )
            self.assertEqual(
                execute_sbr_utility(two, export, value=0x1234, key=0x5678),
                sbr_cipher_function(0x1234, 0x5678, one.substitution),
            )
        finally:
            one.substitution = previous


class FullHinoTypedCompositionTests(unittest.TestCase):
    def test_ordinary_prepare_negotiated_shared_context_then_complete_writer(self):
        p = TypedDriver(
            {
                bytes.fromhex("1002"): [bytes.fromhex("500201230064")],
                bytes.fromhex("2701"): [bytes.fromhex("670100230001")],
                bytes.fromhex("2702ffdcffff"): [bytes.fromhex("6702")],
                bytes.fromhex("3400440000200000000004"): [bytes.fromhex("741006")],
                b"\x36\x01LOAD": [b"\x76\x01"],
                bytes.fromhex("310110ff"): [bytes.fromhex("710110ff00")],
                bytes.fromhex("310110fd"): [bytes.fromhex("710110fd00")],
                bytes.fromhex("3400440000100000000004"): [bytes.fromhex("741006")],
                b"\x36\x01DATA": [b"\x76\x01"],
                b"\x37": [b"\x77", b"\x77"],
                bytes.fromhex("310110fe"): [bytes.fromhex("710110fe00")],
                bytes.fromhex("310110fc"): [bytes.fromhex("710110fc00")],
                bytes.fromhex("1101"): [bytes.fromhex("5101")],
            }
        )
        runtime = p.runtime()
        prepared = run_native(context("TCUWCanHINOPrepareWriter.dll"), runtime)
        self.assertEqual(prepared["native_pending_timeout_ms"], 1000)
        self.assertEqual(p.device.timeout, 291)
        ctx = context(
            "TCUWCanHINOFlashWriter.dll",
            native_observations={
                "native_pending_timeout_ms": prepared["native_pending_timeout_ms"]
            },
        )
        observed = []
        result = run_native(ctx, runtime, notify=lambda k, v: observed.append((k, v)))
        self.assertEqual(result["state"], "writer_completed")
        self.assertEqual(
            observed, [("writing", 1), ("count", 4), ("percent", 100), ("writing", 0)]
        )
        self.assertEqual(p.device.filters, [])
        self.assertFalse(runtime._resources)
        self.assertEqual(p.device.timeout, 291)

    def test_dss_full_loader_and_image_writer_through_actual48(self):
        p = TypedDriver(
            {
                bytes.fromhex("34000020000000"): [b"\x74"],
                b"\x36LOAD": [b"\x76"],
                b"\x37": [b"\x77", b"\x77"],
                bytes.fromhex("31a2"): [bytes.fromhex("71a200")],
                bytes.fromhex("31a0"): [bytes.fromhex("71a000")],
                bytes.fromhex("34000010000000"): [b"\x74"],
                b"\x36DATA": [b"\x76"],
                bytes.fromhex("31a3"): [bytes.fromhex("71a300")],
                b"\x11": [b"\x51"],
            }
        )
        runtime = p.runtime()
        result = run_native(context("TCUWCanHINOFlashWriterForDSS.dll"), runtime)
        self.assertEqual(result["state"], "writer_completed")
        self.assertEqual(result["transferred"], 4)
        self.assertEqual(p.device.filters, [])
        self.assertFalse(runtime._resources)

    def test_vcs_full_loader_image_and_reset_through_actual48(self):
        p = TypedDriver(
            {
                bytes.fromhex("34010000200000000004"): [bytes.fromhex("7401")],
                b"\x36LOAD": [b"\x76"],
                b"\x37": [b"\x77", b"\x77"],
                bytes.fromhex("3105"): [bytes.fromhex("7105")],
                bytes.fromhex("3101"): [bytes.fromhex("7101")],
                bytes.fromhex("34020000100000000004"): [bytes.fromhex("7402")],
                b"\x36DATA": [b"\x76"],
                bytes.fromhex("3102"): [bytes.fromhex("7102")],
                bytes.fromhex("3103"): [bytes.fromhex("7103")],
                bytes.fromhex("1101"): [b"\x51"],
            }
        )
        runtime = p.runtime()
        result = run_native(context("TCUWCanHINOFlashWriterForVCS.dll"), runtime)
        self.assertEqual(result["state"], "writer_completed")
        self.assertEqual(p.device.filters, [])
        self.assertFalse(runtime._resources)
        self.assertEqual(
            p.payloads[-2:], [bytes.fromhex("a02801"), bytes.fromhex("a08501")]
        )


class NativeGetterCancellationTests(unittest.TestCase):
    def test_callback12_true_skips_functions_instead_of_host_cancellation(self):
        for name, identifiers in (
            ("TCUWCanHINOCIDGetterForDSS.dll", (b"",)),
            ("TCUWCanHINOCIDGetterForVCS.dll", (b"",)),
            ("TCUWCanHINOCIDGetter.dll", (b"",)),
            ("TCUWCanSBRSoftwareIDGetter.dll", ()),
        ):
            with self.subTest(name=name):
                p = Replay()
                runtime = NativeRuntime2026(
                    p, clock=lambda p=p: p.now, native_cancelled=lambda: True
                )
                result = run_native(context(name), runtime)
                self.assertEqual(result["state"], "read_completed")
                self.assertEqual(result["identifiers"], identifiers)
                self.assertEqual(p.writes, [])
                self.assertFalse(runtime._resources)

    def test_callback12_observed_separately_for_tester_and_query(self):
        observed = iter((False, True))
        p = Replay((b"\x7e",))
        runtime = NativeRuntime2026(
            p, clock=lambda: p.now, native_cancelled=lambda: next(observed)
        )
        result = run_native(context("TCUWCanHINOCIDGetterForDSS.dll"), runtime)
        self.assertEqual(result["identifiers"], (b"",))
        self.assertEqual(p.writes, [bytes.fromhex("000007e03e")])

    def test_missing_callback_observation_fails_before_any_primitive(self):
        p = Replay()
        with self.assertRaisesRegex(ValueError, "callback12"):
            run_native(context("TCUWCanHINOCIDGetter.dll"), NativeRuntime2026(p))
        self.assertEqual(p.events, [])

    def test_native_hino_p4_retains_two_five_second_query_delays(self):
        p = Replay((b"\x7e", b"\x5a\x03A B C D E F G"))
        result = run_native(
            context("TCUWCanHINOCIDGetter.dll", contact_type="P4-CAN"), p.runtime()
        )
        self.assertEqual(result["identifiers"], (b"ABCDEFG",))
        self.assertEqual([v[4:] for v in p.writes], [b"\x3e\x01", b"\x1a\x81"])
        self.assertEqual(
            [e["milliseconds"] for e in p.events if e["operation"] == "wait"],
            [5000, 5000],
        )


class NativeErrorTaxonomyTests(unittest.TestCase):
    def test_base_driver_and_read_errors_preserve_actual_fields(self):
        from scripts.j2534_2026 import NativePassThruError2026, NativeReadError2026

        for error, expected in (
            (NativePassThruError2026(2), (2, None)),
            (NativeReadError2026(9, (), native_error_code=9999), (9999, None)),
            (NativePassThruException2026(26, "authored.cpp", 12), (26, None)),
        ):
            with self.subTest(error=type(error).__name__):
                p = Replay()

                def fault(event, remaining, error=error, p=p):
                    if event["operation"] == "write_messages":
                        raise error
                    return p(event, remaining)

                result = run_native(
                    context("TCUWCanHINOCIDGetterForDSS.dll"),
                    NativeRuntime2026(
                        fault, clock=lambda p=p: p.now, native_cancelled=lambda: False
                    ),
                )
                self.assertEqual(
                    (result["native_error_code"], result["driver_error_code"]), expected
                )
                self.assertIs(result["native_success"], False)
                self.assertIsNone(result["native_return"])

    def test_vcs_retry_uses_canonical_driver_status_not_base_enum(self):
        for driver_exception in (False, True):
            p = Replay((b"\x50", b"\x67\x01" + bytes(12), b"\x67\x02"))
            attempts = []

            def action(
                event,
                remaining,
                p=p,
                driver_exception=driver_exception,
                attempts=attempts,
            ):
                if (
                    event["operation"] == "write_messages"
                    and event["data"][4:] == b"\x10\x02"
                ):
                    attempts.append(1)
                    if not driver_exception or len(attempts) < 3:
                        exception = (
                            NativeJ2534Exception2026
                            if driver_exception
                            else NativePassThruException2026
                        )
                        raise exception(9, "authored.cpp", 1)
                return p(event, remaining)

            result = run_native(
                context("TCUWCanHINOPrepareWriterForVCS.dll"),
                NativeRuntime2026(action, clock=lambda p=p: p.now),
            )
            self.assertEqual(len(attempts), 3 if driver_exception else 1)
            self.assertEqual(
                result["state"], "prepare_completed" if driver_exception else "failed"
            )
            if not driver_exception:
                self.assertEqual(
                    (result["native_error_code"], result["driver_error_code"]),
                    (9, None),
                )

    def test_cleanup_only_host_fault_preserves_original_exception_identity(self):
        for operation in ("disconnect", "stop_sync_periodic_message"):
            marker = OSError("Authored cleanup failure")
            p = (
                Replay((b"\x7e", b"\x5a\x88\x01" + b"A" * 16))
                if operation == "disconnect"
                else Replay((b"\x50\x02",))
            )

            def action(event, remaining, p=p, marker=marker, operation=operation):
                if event["operation"] == operation:
                    raise marker
                return p(event, remaining)

            runtime = NativeRuntime2026(
                action, clock=lambda p=p: p.now, native_cancelled=lambda: False
            )
            with self.assertRaises(OSError) as raised:
                if operation == "disconnect":
                    run_native(context("TCUWCanHINOCIDGetterForDSS.dll"), runtime)
                else:
                    channel = VendorCAN2026(
                        runtime,
                        context("TCUWCanSBRPrepareWriter.dll").addresses[0],
                        phase5=True,
                    )
                    SBRUtils2026(channel).programming_session()
            self.assertIs(raised.exception, marker)
            if operation == "stop_sync_periodic_message":
                self.assertEqual(p.timeout, 100)

    def test_actual_bool_return_and_pointer_success_are_separate(self):
        p = Replay((b"\x7e", b"\x5a\x88\x01" + b"A" * 16))
        result = run_native(context("TCUWCanHINOCIDGetterForDSS.dll"), p.runtime())
        self.assertIs(result["native_success"], True)
        self.assertIsNone(result["native_return"])
        p = Replay((b"\x7f\x34\x22",))
        result = run_native(context("TCUWCanHINOFlashWriterForDSS.dll"), p.runtime())
        self.assertIs(result["native_success"], False)
        self.assertIs(result["native_return"], False)


class GlobalWriterAddressTests(unittest.TestCase):
    def test_two_nodes_and_mutated_cpu_type_use_global_own_rows(self):
        text = "[Format]\nVersion=101\n[Vehicle]\nKindOfECU=106\nContactType=P4-CAN\nNumberOfNode=2\n"
        for node, cpu in ((1, "282"), (2, "283")):
            text += (
                f"[Node{node:02}]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\nDiagID=070{node}\n"
                f"[CPU{node}1]\nCPUType={cpu}\nCPUImageName=authored.vbf\n"
                f"LocationID=NODE{node}\n"
            )
        container = parse_cuw_2026(cuw(text, (b"FIRST", b"SECOND")))
        for changed in (False, True):
            with self.subTest(changed=changed):
                state = native2026_metadata(container, node=2)
                if changed:
                    state = native2026_with_cpu_type(state, 0, "284")
                catalogs = {}
                for cpu, address in (
                    *((("284", "07E0/07E8"),) if changed else ()),
                    ("", "07E1/07E9"),
                ):
                    key = "106P4-CAN" + cpu
                    values = {
                        "ParamFileKeySystemProtocolMicon": key,
                        "DLLFileNameForFlashWrite": "TCUWCanHINOFlashWriter.dll",
                        "GetCANIDFunctionNameForFlashWrite": "GetCanIDsFromParamForGetCID",
                        "CanIDForGetCID": address,
                    }
                    table = io.StringIO()
                    writer = csv.writer(table)
                    writer.writerow(values)
                    writer.writerow(values.values())
                    catalogs[key + ".ini"] = table.getvalue().encode()
                selection = bind_parameter2026(
                    container,
                    catalogs,
                    "write",
                    node=2,
                    cpu_index=0,
                    encoded=False,
                    metadata_state=state,
                )
                history = []
                groups = native2026_write_address_groups(
                    container, selection, history=history
                )
                self.assertEqual(len(groups), 2)
                self.assertEqual(
                    [group[0].record() for group in groups],
                    [
                        bytes.fromhex(
                            "07e00007e80000" if changed else "07e10007e90000"
                        ),
                        bytes.fromhex("07e10007e90000"),
                    ],
                )
                self.assertEqual(history, [])


if __name__ == "__main__":
    unittest.main()
