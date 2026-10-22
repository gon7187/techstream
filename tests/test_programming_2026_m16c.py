"""Authored wire/metadata fixtures; no vendor bytes or device access."""

import csv
import io
import unittest
from dataclasses import FrozenInstanceError, replace

from scripts.calibration_2026 import parse_cuw_2026
from scripts.native_modules import identify_native_module
from scripts.programming import NativeTransportError
from scripts.programming_2026_common import NativeRuntime2026, bind_native_parameter2026
from scripts.programming_2026_m16c import (
    M16C2026,
    M16C2026Error,
    bind_native_context,
    run_native_context,
    vforest_groups_2026,
)
from tests.test_calibration_2026 import cuw

REQUEST, RESPONSE = bytes.fromhex("00000100"), bytes.fromhex("00000108")


def runtime(replies=(), *, fault=None, cancelled=lambda: False):
    events = []
    replies = iter(replies)

    def action(event, _remaining):
        events.append(event)
        if fault is not None:
            fault(event)
        name = event["operation"]
        if name == "write_messages":
            return event["count"]
        if name == "read_specified_can_message":
            value = next(replies)
            if isinstance(value, BaseException):
                raise value
            return event["address"] + value
        if name == "start_flow_control_filter":
            return 17
        if name == "get_timeout":
            return 999
        return None

    return NativeRuntime2026(action, cancelled=cancelled), events


def source(module):
    hashes = {
        "TCUWCanM16CFlashWriter.dll": "e82a46a96e96c3e5fb0968a603400d7e50df466961129d392467f38d06364a50",
        "TCUWCanSecurityM16CFlashWriter.dll": "59d78a0f198d42f735dfe0376c5ba3a8fc0f19994335bbbd679f92c535582072",
        "TCUWCanSecurityVFORESTFlashWriter.dll": "f5ab9fde922b365a0d8f81481c6cb5f3dd325ed97e9e298d158e45981f48a16e",
        "TCUWP4CanVFORESTFlashWriter.dll": "6bce42aa63c42ec731d2f99241a7db4d294af5d169efc0e34988a23b1864c6cc",
    }
    return identify_native_module(hashes[module], module)


def parameter_bytes(key, **values):
    data = io.StringIO()
    writer = csv.writer(data, lineterminator="\r\n")
    writer.writerow(("ParamFileKeySystemProtocolMicon", *values))
    writer.writerow((key, *values.values()))
    return data.getvalue().encode()


def fixture(
    module="TCUWCanM16CFlashWriter.dll",
    *,
    vforest=False,
    parameters=None,
    new_password="",
    observations=None,
    extra_catalogs=None,
    current_first=False,
    parent_location="01080100AABB0720",
    parent_target="12345678",
    omit_parent_catalog=False,
    observed_cids=None,
):
    cpu_count = 1 if vforest else 2
    text = f"[Format]\nVersion=7\n[Vehicle]\nKindOfECU=8\nContactType=P4\nNumberOfCalibration={cpu_count}\n"
    image = b"ZV\x00\x00\x04DATA" if vforest else bytes(range(256)) * 4
    names = ("V",) if vforest else ("M", "P") if current_first else ("P", "M")
    for index, name in enumerate(names, 1):
        location = parent_location if name == "P" else "01080100AABB0720"
        target = parent_target if name == "P" else "12345678"
        text += (
            f"[CPU{index:02}]\nCPUType={name}\nCPUImageName=authored.vbf\n"
            f"LocationID={location}\nNumberOfTargets=1\n"
            f"01_TargetCalibration=OLD{name}\n01_TargetData={target}\n"
            f"Nonce={'11' * 16}\nSeedKey={'22' * 16}\n"
        )
    text += "NewPassword=" + new_password + "\n"
    payloads = (
        (image,)
        if vforest
        else (image, b"parent")
        if current_first
        else (b"parent", image)
    )
    container = parse_cuw_2026(cuw(text, payloads))
    values = {
        "DLLFileNameForFlashWrite": module,
        "GetCANIDFunctionNameForFlashWrite": "GetCanIDsFromLocationIDForWrite",
        "ParentCPUTypeList": "P",
        "PasswordCheckIDAddress": "01\n02\n03",
        "PasswordCheckPassword": "04\n05\n06",
        "BlockSizeInfo": "0,1,1",
        "StartAddress": "1000",
        "CPUIDNo": "01",
        "ShrinkFlag": "1",
    }
    values.update(parameters or {})
    index = 0 if current_first else cpu_count - 1
    name = names[index]
    catalogs = {
        # Authored families: M16C writer M, FOREST parent P, VFOREST writer V.
        "Parameter.ini": (
            b"ParamFileKeySystemProtocolMicon,M16CTypeFlag,FORESTTypeFlag\r\n"
            b"8P4M,1,0\r\n8P4P,0,1\r\n8P4V,0,1\r\n"
        ),
        f"8P4{name}.ini": parameter_bytes("8P4" + name, **values),
        "8P4P.ini": parameter_bytes(
            "8P4P",
            BigEndianFlag="0",
            GetCANIDFunctionNameForFlashWrite="GetCanIDsFromLocationIDForWrite",
        ),
    }
    catalogs.update(extra_catalogs or {})
    if omit_parent_catalog:
        catalogs.pop("8P4P.ini")
    selection = bind_native_parameter2026(
        container, catalogs, "write", cpu_index=index, encoded=False
    )
    context = bind_native_context(
        container,
        1,
        tuple("OLD" + name for name in names)
        if observed_cids is None
        else observed_cids,
        selection,
        source(module),
        observations={"cpu_index": index, **(observations or {})},
    )
    return container, selection, context


def two_node_fixture(current_node=2):
    from scripts.calibration_2026 import native2026_metadata, native2026_with_cpu_type

    _, source_selection, original = fixture()
    text = "[Format]\nVersion=101\n[Vehicle]\nKindOfECU=8\nContactType=P4\nNumberOfNode=2\n"
    payloads = []
    for node in (1, 2):
        cpu = "M" if node == current_node else "P"
        location = "01080100AABB0720" if cpu == "M" else "03080300CCDD0720"
        text += (
            f"[Node{node:02}]\nRequiredSpecReproVer=02\nNumberOfCalibration=1\nDiagID=070{node}\n"
            f"[CPU{node}1]\nCPUType={cpu}\nCPUImageName=authored.vbf\nLocationID={location}\n"
            f"NumberOfTargets=1\n01_TargetCalibration=OLD{cpu}\n01_TargetData="
            + ("12345678" if cpu == "M" else "A1B2C3D4")
            + "\n"
        )
        payloads.append(original.image if cpu == "M" else b"parent")
    container = parse_cuw_2026(cuw(text, tuple(payloads)))
    catalogs = dict(source_selection.catalog_sources)
    catalogs["8P4P.ini"] = parameter_bytes(
        "8P4P",
        BigEndianFlag="0",
        GetCANIDFunctionNameForFlashWrite="GetCanIDsFromParamForGetCID",
        CanIDForGetCID="0300/0308\n0750/0000",
    )
    values = {
        name: "\n".join(value)
        for name, value in source_selection.values.items()
        if name != "ParamFileKeySystemProtocolMicon"
    }
    values.update(
        GetCANIDFunctionNameForFlashWrite="GetCanIDsFromParamForGetCID",
        CanIDForGetCID="0100/0108\n0720/0000",
    )
    catalogs["8P4M.ini"] = parameter_bytes("8P4M", **values)
    state = native2026_metadata(container, node=current_node, cpu_index=0)
    for global_index in range(2):
        state = native2026_with_cpu_type(
            state, global_index, "M" if global_index + 1 == current_node else "P"
        )
    selection = bind_native_parameter2026(
        container,
        catalogs,
        "write",
        node=current_node,
        cpu_index=0,
        encoded=False,
        metadata_state=state,
    )
    context = bind_native_context(
        container,
        current_node,
        ("OLDP", "OLDM"),
        selection,
        original.identity,
        observations={"cpu_index": 0, "recovery": True},
    )
    return container, selection, context


def actual_runtime(context, replies):
    from scripts.j2534_2026 import J2534Device2026, NativeMessage
    from tests.test_j2534_2026 import Provider

    rt, events = runtime(replies)
    run_native_context(context, rt)
    provider = Provider()
    replies = iter(replies)
    for event in events:
        if event["operation"] == "write_messages":
            data = event["data"]
            first = data[0] if isinstance(data, tuple) else data
            provider.reads.append((NativeMessage(6, first[:4], rx_status=9),))
        elif event["operation"] == "read_specified_can_message":
            if event["frame"] == 1:
                provider.reads.append(
                    (NativeMessage(6, event["address"], rx_status=2),)
                )
            provider.reads.append((NativeMessage(6, event["address"] + next(replies)),))
    device = J2534Device2026(provider, clock=lambda: 0, background_workers=False)
    device.open()
    device.connect(6)
    rt = NativeRuntime2026(device.primitive, clock=lambda: 0)
    return rt, device, provider


class M16CPrimitiveTests(unittest.TestCase):
    def test_password_native_batch_and_little_address_page(self):
        rt, events = runtime((b"\x80\x0c", b"\x80\0", b"\0"))
        wire = M16C2026(rt, REQUEST, RESPONSE)
        wire.password(b"\1\2\3", 0x12345678, b"\4\5\6")
        wire.page(0x123400, bytes(256))
        wire.page(0x123400, bytes(256), verify=True)
        writes = [e for e in events if e["operation"] == "write_messages"]
        self.assertEqual(
            writes[0]["data"],
            (
                REQUEST + bytes.fromhex("a001020307"),
                REQUEST + bytes.fromhex("12345678040506"),
            ),
        )
        self.assertEqual(
            writes[3]["data"], (REQUEST + bytes.fromhex("a23412"), REQUEST + bytes(256))
        )
        self.assertEqual((wire.written, wire.verified), (256, 256))
        self.assertTrue(
            all(
                e["frame"] == 0
                for e in events
                if e["operation"] == "read_specified_can_message"
            )
        )

    def test_busy_poll_and_native_failure_masks(self):
        for operation, replies, code in (
            ("erase", (b"\0\0", b"\xb0\0"), 12),
            ("write", (b"\0\0", b"\x80\2"), 13),
            ("verify", (b"\xff", b"\1"), 15),
        ):
            with self.subTest(operation=operation):
                rt, _ = runtime(replies)
                wire = M16C2026(rt, REQUEST, RESPONSE)
                with self.assertRaises(M16C2026Error) as caught:
                    wire.poll(operation, 0)
                self.assertEqual(caught.exception.code, code)

    def test_retry_exact_four_a4_three_a8_three_dummy(self):
        rt, events = runtime([NativeTransportError(9)] * 7)
        with self.assertRaises(M16C2026Error) as caught:
            M16C2026(rt, REQUEST, RESPONSE).prepare_retry(2)
        self.assertEqual(caught.exception.code, 20)
        data = [e["data"][4:] for e in events if e["operation"] == "write_messages"]
        self.assertEqual(data, [b"\xa4", b"\xa8", bytes(256)] * 3 + [b"\xa4"])
        self.assertEqual(
            [e["milliseconds"] for e in events if e["operation"] == "wait"], [2] * 3
        )

    def test_other_driver_error_and_truncated_read_fail(self):
        for reply, error in (
            (NativeTransportError(5), NativeTransportError),
            (b"\x80", ValueError),
        ):
            rt, _ = runtime((reply,))
            with self.assertRaises(error):
                M16C2026(rt, REQUEST, RESPONSE).status()

    def test_partial_batch_is_never_retried(self):
        events = []
        rt = NativeRuntime2026(lambda event, _time: events.append(event) or 1)
        with self.assertRaises(ValueError):
            M16C2026(rt, REQUEST, RESPONSE).password(bytes(3), 0, bytes(3))
        self.assertEqual(len(events), 1)

    def test_malformed_page_has_no_side_effect(self):
        rt, events = runtime()
        for address, data in ((1, bytes(256)), (0, bytes(255)), (1 << 24, bytes(256))):
            with self.assertRaises(ValueError):
                M16C2026(rt, REQUEST, RESPONSE).page(address, data)
        self.assertEqual(events, [])

    def test_cancel_and_late_provider(self):
        rt, events = runtime(cancelled=lambda: True)
        with self.assertRaises(InterruptedError):
            M16C2026(rt, REQUEST, RESPONSE).status()
        self.assertEqual(events, [])
        clock = [0.0]

        def late(event, _time):
            clock[0] = 2
            return 1

        rt = NativeRuntime2026(late, timeout=1, clock=lambda: clock[0])
        with self.assertRaises(TimeoutError):
            M16C2026(rt, REQUEST, RESPONSE).status()

    def test_vforest_group_boundaries(self):
        first, second = b"ZV\0\0\1A", b"ZV\1\0\1XXB"
        self.assertEqual(vforest_groups_2026(first + second), (first, second))
        for image in (b"", b"ZV\0\0", b"ZV\0\xff\xff", b"bad\0\0"):
            with self.assertRaises(ValueError):
                vforest_groups_2026(image)


class M16CWriterTests(unittest.TestCase):
    def replies(self, security=False):
        values = [b"\x3c", b"initial"]
        if security:
            values.append(b"\x3c")
        values += [b"\x80\x0c", b"\x80\0"]
        values += [value for _ in range(4) for value in (b"\x80\0", b"\0")]
        if security:
            values += [b"\x3c", b"\x3c", b"\0", b"\x3c"]
        return values

    def test_full_selected_cuw_to_m16c_wire(self):
        _, _, context = fixture()
        rt, events = runtime(self.replies())
        writing = []
        result = run_native_context(context, rt, writing_observer=writing.append)
        self.assertEqual((result["written"], result["verified"]), (1024, 1024))
        self.assertEqual(result["progress_bytes"], 2048)
        self.assertEqual(events[-1], {"operation": "set_timeout", "milliseconds": 999})
        self.assertEqual(events[-2], {"operation": "stop_filter", "identifier": 17})
        self.assertNotIn(context.image.hex(), repr(context))
        writes = [e["data"] for e in events if e["operation"] == "write_messages"]
        assert context.finish_request is not None
        self.assertIn(context.finish_request + b"\x80", writes)
        self.assertEqual(writing, [True, False])

    def test_security2026_wait_then_falsify_before_finish(self):
        _, _, context = fixture(
            "TCUWCanSecurityM16CFlashWriter.dll",
            parameters={"WaitTimeAfterFlashWrite": "17"},
        )
        rt, events = runtime(self.replies(True))
        run_native_context(context, rt)
        wait_index = next(
            i
            for i, e in enumerate(events)
            if e["operation"] == "wait" and e["milliseconds"] == 17
        )
        falsify = next(
            i
            for i, e in enumerate(events)
            if e.get("data") == context.request + b"\x47"
        )
        assert context.finish_request is not None
        finish = next(
            i
            for i, e in enumerate(events)
            if e.get("data") == context.finish_request + b"\x80"
        )
        self.assertLess(wait_index, falsify)
        self.assertLess(falsify, finish)

    def test_native_failure_cleans_only_own_filter_restores_timeout(self):
        _, _, context = fixture()
        rt, events = runtime([b"\x3c", b"initial", b"\0\0"])
        rt.own("stop_filter", identifier=99)
        progress = []
        with self.assertRaises(M16C2026Error) as caught:
            run_native_context(
                context,
                rt,
                progress_observer=lambda kind, cpu, value: progress.append(
                    (kind, cpu, value)
                ),
            )
        self.assertEqual(caught.exception.code, 7)
        self.assertTrue(rt.owns_resource("stop_filter", identifier=99))
        self.assertFalse(rt.owns_resource("stop_filter", identifier=17))
        self.assertEqual(events[-1], {"operation": "set_timeout", "milliseconds": 999})
        self.assertEqual(progress, [("count", 1, 0), ("percent", 1, 0)])

    def test_cancel_after_acquisition_releases_filter(self):
        _, _, context = fixture()
        cancelled = [False]

        def fault(event):
            if event["operation"] == "start_flow_control_filter":
                cancelled[0] = True

        rt, events = runtime(fault=fault, cancelled=lambda: cancelled[0])
        with self.assertRaises(InterruptedError):
            run_native_context(context, rt)
        self.assertIn({"operation": "stop_filter", "identifier": 17}, events)
        self.assertFalse(rt.owns_resource("stop_filter", identifier=17))

    def vforest_replies(self, security):
        values = [b"\x3c", b"initial"]
        if security:
            values += [b"\x3c"]
        values += [b"\x3c", bytes.fromhex("0000000003ff010100"), b"\x3c"]
        for _ in range(2):
            values += [b"\x3c", b"\x3c", b"\x3c", b"\0", b"\x3c"]
        if security:
            values += [b"\x3c", b"\x3c", b"\0", b"\x3c"]
        return values

    def test_vforest_both_actual2026_writers(self):
        for module in (
            "TCUWCanSecurityVFORESTFlashWriter.dll",
            "TCUWP4CanVFORESTFlashWriter.dll",
        ):
            with self.subTest(module=module):
                _, _, context = fixture(module, vforest=True)
                rt, events = runtime(self.vforest_replies("Security" in module))
                result = run_native_context(context, rt)
                self.assertEqual((result["written"], result["verified"]), (9, 9))
                writes = [
                    e["data"] for e in events if e["operation"] == "write_messages"
                ]
                self.assertIn(context.request + bytes.fromhex("4200000000ff"), writes)
                self.assertIn(context.request + bytes.fromhex("1700000000ff"), writes)
                self.assertEqual(writes.count(context.request + context.image), 2)
                self.assertEqual(
                    any(data == context.request + b"\x47" for data in writes),
                    "Security" in module,
                )

    def test_complete_actual48_dispatch_for_all_four_writers(self):
        for module in (
            "TCUWCanM16CFlashWriter.dll",
            "TCUWCanSecurityM16CFlashWriter.dll",
            "TCUWCanSecurityVFORESTFlashWriter.dll",
            "TCUWP4CanVFORESTFlashWriter.dll",
        ):
            with self.subTest(module=module):
                forest = "VFOREST" in module
                _, _, context = fixture(module, vforest=forest)
                replies = (
                    self.vforest_replies("Security" in module)
                    if forest
                    else self.replies("Security" in module)
                )
                rt, device, provider = actual_runtime(context, replies)
                result = run_native_context(context, rt)
                self.assertEqual(result["state"], "writer_completed")
                self.assertEqual(provider.reads, [])
                batches = [
                    e[0]
                    for e in provider.calls
                    if e[0]["operation"] == "passthru_write"
                ]
                if not forest:
                    self.assertEqual(sum(e["count"] == 2 for e in batches), 9)
                self.assertEqual(device.filters, [])
                self.assertIsNotNone(device.channel_id)

    def test_prepare_retry_bound_export_has_no_timeout_mutation(self):
        _, _, context = fixture(observations={"stage": "prepare_retry"})
        rt, events = runtime((b"\x80\0",))
        result = run_native_context(context, rt)
        self.assertEqual(result["state"], "writer_completed")
        self.assertEqual(
            [e["operation"] for e in events],
            [
                "start_flow_control_filter",
                "write_messages",
                "read_specified_can_message",
                "stop_filter",
            ],
        )

    def test_authored_historical_profile_declares_m16c_and_forest_parent(self):
        from scripts.calibration_2026 import (
            native2026_with_parser_parameters,
        )
        from scripts.programming_2026_common import NativeGeneralParameters2026

        _, selection, _ = fixture()
        general = NativeGeneralParameters2026.from_binding(selection)
        metadata = native2026_with_parser_parameters(selection.metadata, general)
        self.assertTrue(metadata.parser_parameters_validated)
        catalogs = dict(selection.catalog_sources)
        catalogs["Parameter.ini"] = catalogs["Parameter.ini"].replace(
            b"8P4P,0,1", b"8P4P,0,0"
        )
        invalid = NativeGeneralParameters2026.from_sources(catalogs, encoded=False)
        with self.assertRaisesRegex(ValueError, "requires a FOREST CPU"):
            native2026_with_parser_parameters(selection.metadata, invalid)

    def test_reader_recovers_driver_status_only_not_base_enum(self):
        from scripts.j2534_2026 import NativePassThruError2026
        from scripts.programming_2026_common import (
            NativeJ2534Exception2026,
            NativePassThruException2026,
        )

        rt, _ = runtime([NativeJ2534Exception2026(9, "source", 1)])
        self.assertIsNone(M16C2026(rt, REQUEST, RESPONSE).read(1))
        for error in (
            NativePassThruError2026(9),
            NativePassThruException2026(9, "source", 1),
        ):
            rt, _ = runtime([error])
            with self.assertRaises(Exception) as caught:
                M16C2026(rt, REQUEST, RESPONSE).read(1)
            self.assertIs(caught.exception, error)

    def test_explicit_native_catchall_finish_retains_native_return(self):
        from scripts.programming_2026_common import NativeException2026

        _, _, context = fixture()
        error = NativeException2026("native catch-all")
        assert context.finish_request is not None
        finish_request = context.finish_request

        def fault(event):
            if event.get("data") == finish_request + b"\x80":
                raise error

        rt, _ = runtime(self.replies(), fault=fault)
        with self.assertRaises(NativeException2026) as caught:
            run_native_context(context, rt)
        self.assertIs(caught.exception, error)
        state = error.__dict__["native_state"]
        self.assertTrue(state.returned)
        self.assertTrue(state.finish_flag_update)
        self.assertIsNone(state.native_error_code)
        self.assertEqual(state.progress_percent, 100)

    def test_base_native_fault_keeps_absent_driver_at_erase(self):
        from scripts.j2534_2026 import NativePassThruError2026
        from scripts.programming_2026_common import NativePassThruException2026

        for error in (
            NativePassThruError2026(2),
            NativePassThruException2026(2, "source", 1),
        ):
            _, _, context = fixture()

            def fault(event, error=error, context=context):
                if event.get("data") == context.request + bytes.fromhex("a11300d0"):
                    raise error

            rt, _ = runtime(self.replies(), fault=fault)
            with self.assertRaises(Exception) as caught:
                run_native_context(context, rt)
            self.assertIs(caught.exception, error)
            state = caught.exception.__dict__["native_state"]
            self.assertEqual(
                (state.native_error_code, state.result_status_update), (2, 2)
            )
            self.assertIsNone(state.driver_error_code)

    def test_vforest_base_native_phase_remaps_without_driver(self):
        from scripts.j2534_2026 import NativePassThruError2026
        from scripts.programming_2026_common import NativePassThruException2026

        for error in (
            NativePassThruError2026(2),
            NativePassThruException2026(2, "source", 1),
        ):
            _, _, context = fixture("TCUWP4CanVFORESTFlashWriter.dll", vforest=True)
            replies = self.vforest_replies(False)
            replies = replies[:5] + [error] + replies[6:]
            rt, _ = runtime(replies)
            with self.assertRaises(Exception) as caught:
                run_native_context(context, rt)
            state = caught.exception.__dict__["native_state"]
            self.assertEqual(
                (state.native_error_code, state.result_status_update), (29, 2)
            )
            self.assertIsNone(state.driver_error_code)

    def test_host_faults_have_no_invented_native_terminal_state(self):
        for current_first in (False, True):
            for error in (OSError("host I/O"), ValueError("host provider")):
                _, _, context = fixture(current_first=current_first)
                assert context.finish_request is not None or current_first
                finish_request = context.finish_request or b""
                target = (
                    (context.request + b"\x65")
                    if current_first
                    else (finish_request + b"\x80")
                )

                def fault(event, error=error, target=target):
                    if event.get("data") == target:
                        raise error

                rt, events = runtime(self.replies(), fault=fault)
                with self.assertRaises(Exception) as caught:
                    run_native_context(context, rt)
                self.assertIs(caught.exception, error)
                state = error.__dict__["native_state"]
                self.assertIsNone(state.returned)
                self.assertIsNone(state.native_error_code)
                self.assertIsNone(state.driver_error_code)
                self.assertIsNone(state.result_status_update)
                if not current_first:
                    self.assertTrue(state.finish_flag_update)
                    self.assertEqual(
                        (state.progress_bytes, state.progress_percent), (2048, 100)
                    )
                self.assertIn({"operation": "stop_filter", "identifier": 17}, events)

    def test_recovery_skips_initial_password_but_security_still_authenticates(self):
        _, _, context = fixture(
            "TCUWCanSecurityM16CFlashWriter.dll", observations={"recovery": True}
        )
        replies = (
            [b"\x3c", b"\x80\0"]
            + [value for _ in range(4) for value in (b"\x80\0", b"\0")]
            + [b"\x3c", b"\x3c", b"\0", b"\x3c"]
        )
        rt, events = runtime(replies)
        run_native_context(context, rt)
        writes = [e["data"] for e in events if e["operation"] == "write_messages"]
        self.assertEqual(writes[0], context.request + b"\x37" + bytes.fromhex("11" * 6))
        self.assertFalse(
            any(
                isinstance(value, tuple) and value[0][4:5] == b"\xa0"
                for value in writes
            )
        )

    def test_vforest_retry_password_distinguishes_archive_from_new_password(self):
        for module, expected in (
            ("TCUWP4CanVFORESTFlashWriter.dll", 0x41544144),
            ("TCUWCanSecurityVFORESTFlashWriter.dll", 0xDEADBEEF),
        ):
            with self.subTest(module=module):
                _, _, context = fixture(
                    module,
                    vforest=True,
                    new_password="DEADBEEF",
                    parameters={"PasswordAddress": "5", "ByteOrder": "0"},
                    observations={"previous_retry_password": True},
                )
                self.assertEqual(context.password, expected)

    def test_vforest_alternate_uses_distinct_exact_catalog_file(self):
        alternate = parameter_bytes(
            "8P4A",
            CPUIDNo="01",
            ShrinkFlag="1",
            WaitTimeBeforeStatusCheckForWriteBlock="23",
        )
        _, _, context = fixture(
            "TCUWP4CanVFORESTFlashWriter.dll",
            vforest=True,
            parameters={"CPUIDNo": "02", "AlternateCPUType": "A"},
            extra_catalogs={"8P4A.ini": alternate},
        )
        rt, events = runtime(self.vforest_replies(False))
        run_native_context(context, rt)
        self.assertIn({"operation": "wait", "milliseconds": 23}, events)
        _, _, missing = fixture(
            "TCUWP4CanVFORESTFlashWriter.dll",
            vforest=True,
            parameters={"CPUIDNo": "02", "AlternateCPUType": "A"},
        )
        rt, events = runtime(self.vforest_replies(False))
        with self.assertRaises(M16C2026Error) as caught:
            run_native_context(missing, rt)
        self.assertEqual(caught.exception.code, 10)
        self.assertFalse(
            any(
                e.get("data") == context.request + bytes.fromhex("4200000000ff")
                for e in events
            )
        )

    def test_vforest_native_phase_mapping_preserves_driver_code(self):
        _, _, context = fixture("TCUWP4CanVFORESTFlashWriter.dll", vforest=True)
        replies = self.vforest_replies(False)
        replies = replies[:5] + [NativeTransportError(5)] + replies[6:]
        rt, _ = runtime(replies)
        with self.assertRaises(NativeTransportError) as caught:
            run_native_context(context, rt)
        self.assertEqual(caught.exception.code, 5)
        from scripts.programming_2026_legacy import NativeMappedTransportError

        self.assertIsInstance(caught.exception, NativeMappedTransportError)
        assert isinstance(caught.exception, NativeMappedTransportError)
        self.assertEqual(caught.exception.native_error_code, 29)

    def test_cancel_from_writing_observer_is_compensated(self):
        _, _, context = fixture()
        cancelled = [False]
        writing = []

        def observer(value):
            writing.append(value)
            if value:
                cancelled[0] = True

        rt, events = runtime(self.replies(), cancelled=lambda: cancelled[0])
        with self.assertRaises(InterruptedError):
            run_native_context(context, rt, writing_observer=observer)
        self.assertEqual(writing, [True, False])
        self.assertIn({"operation": "stop_filter", "identifier": 17}, events)

    def test_immutable_native_failure_status_password_and_destructive(self):
        from scripts.programming_2026_m16c import NativeWriterState2026

        for replies, observations, code, status, completion in (
            ([b"\x3c", b"initial", b"\0\0"], {}, 7, 1, True),
            ([b"\x3c", b"initial", b"\x80\x0c", b"\xb0\0"], {}, 12, 2, None),
            ([b"\xb0\0"], {"recovery": True}, 12, 2, None),
        ):
            with self.subTest(code=code, recovery=observations):
                _, _, context = fixture(observations=observations)
                rt, _ = runtime(replies)
                with self.assertRaises(M16C2026Error) as caught:
                    run_native_context(context, rt)
                state = caught.exception.__dict__["native_state"]
                self.assertIsInstance(state, NativeWriterState2026)
                with self.assertRaises(FrozenInstanceError):
                    state.returned = True
                self.assertEqual(
                    (
                        state.returned,
                        state.result_status_update,
                        state.native_error_code,
                    ),
                    (False, status, code),
                )
                self.assertEqual(state.completion_flag_update, completion)
                self.assertEqual(state.retry_password, code == 7)
                self.assertIsNone(state.finish_flag_update)

    def test_vforest_code10_preserves_native_nonfatal_status(self):
        for observations, expected in (({}, 1), ({"recovery": True}, 2)):
            _, _, context = fixture(
                "TCUWCanSecurityVFORESTFlashWriter.dll",
                vforest=True,
                parameters={"CPUIDNo": "02"},
                observations=observations,
            )
            rt, _ = runtime(self.vforest_replies(True))
            with self.assertRaises(M16C2026Error) as caught:
                run_native_context(context, rt)
            state = caught.exception.__dict__["native_state"]
            self.assertEqual(state.result_status_update, expected)
            self.assertEqual(state.native_error_code, 10)

    def test_finish_fault_retains_native_suppressed_result_while_host_fails(self):
        _, _, context = fixture()
        assert context.finish_request is not None
        finish_request = context.finish_request

        def fault(event):
            if (
                event["operation"] == "write_messages"
                and event["data"] == finish_request + b"\x80"
            ):
                raise NativeTransportError(5)

        rt, events = runtime(self.replies(), fault=fault)
        with self.assertRaises(NativeTransportError) as caught:
            run_native_context(context, rt)
        state = caught.exception.__dict__["native_state"]
        self.assertTrue(state.returned)
        self.assertTrue(state.finish_flag_update)
        self.assertIsNone(state.result_status_update)
        self.assertIsNone(state.native_error_code)
        self.assertFalse(state.retry_password)
        self.assertEqual((state.progress_bytes, state.progress_percent), (2048, 100))
        self.assertIn({"operation": "stop_filter", "identifier": 17}, events)

    def test_actual48_filter_stop_fault_exposes_native_state_and_retains_resource(self):
        from scripts.j2534_2026 import PrimitiveResult

        _, _, context = fixture()
        rt, device, provider = actual_runtime(context, self.replies())
        provider.responses["passthru_stop_filter"] = PrimitiveResult(status=8)
        with self.assertRaises(OSError) as caught:
            run_native_context(context, rt)
        state = caught.exception.__dict__["native_state"]
        self.assertTrue(state.returned)
        self.assertTrue(state.finish_flag_update)
        self.assertEqual(state.progress_percent, 100)
        self.assertTrue(device.filters)
        self.assertTrue(rt.owns_resource("stop_filter", identifier=0))

    def test_timeout_restore_fault_exposes_native_completed_state(self):
        _, _, context = fixture()

        def fault(event):
            if event == {"operation": "set_timeout", "milliseconds": 999}:
                raise OSError("Authored restore failure")

        rt, _ = runtime(self.replies(), fault=fault)
        with self.assertRaises(OSError) as caught:
            run_native_context(context, rt)
        state = caught.exception.__dict__["native_state"]
        self.assertTrue(state.returned)
        self.assertEqual(state.progress_percent, 100)
        self.assertFalse(rt.owns_resource("stop_filter", identifier=17))

    def test_primary_native_error_preserved_alongside_cleanup_fault(self):
        _, _, context = fixture()

        def fault(event):
            if event["operation"] == "stop_filter":
                raise NativeTransportError(8)

        rt, _ = runtime([b"\x3c", b"initial", b"\0\0"], fault=fault)
        with self.assertRaises(M16C2026Error) as caught:
            run_native_context(context, rt)
        self.assertEqual(caught.exception.code, 7)
        self.assertEqual(caught.exception.__dict__["native_state"].native_error_code, 7)
        self.assertIn(
            "Native cleanup failures: NativeTransportError", caught.exception.__notes__
        )

    def test_mixed_cpu_selects_parent_address_password_and_endian_row(self):
        _, _, context = fixture(
            current_first=True,
            parent_location="02080200CCDD0720",
            parent_target="A1B2C3D4",
            extra_catalogs={
                "8P4P.ini": parameter_bytes(
                    "8P4P",
                    BigEndianFlag="1",
                    GetCANIDFunctionNameForFlashWrite="GetCanIDsFromLocationIDForWrite",
                )
            },
        )
        self.assertEqual((context.cpu_index, context.parent_index), (0, 1))
        self.assertEqual(context.request, bytes.fromhex("00000200"))
        self.assertEqual(context.location_id, bytes.fromhex("02080200CCDD0720"))
        self.assertEqual(context.parent_password, 0xA1B2C3D4)
        self.assertEqual(context.password, 0x12345678)
        self.assertTrue(context.parent_big_endian)
        rt, events = runtime(self.replies() + [b"\x3c"])
        result = run_native_context(context, rt)
        writes = [e["data"] for e in events if e["operation"] == "write_messages"]
        self.assertEqual(writes[4], context.request + bytes.fromhex("a1b2c3d4"))
        self.assertEqual(writes[-1], context.request + b"\x65")
        self.assertIsNone(result["native_result"]["finish_flag_update"])

    def test_change_cpu_fault_has_status2_completion_flag_and_driver_domain(self):
        from scripts.programming_2026_common import NativeException2026

        for error, expected in (
            (NativeTransportError(5), 19),
            (NativeException2026("authored native catch-all"), 9999),
        ):
            _, _, context = fixture(current_first=True)

            def fault(event, context=context, error=error):
                if event.get("data") == context.request + b"\x65":
                    raise error

            rt, _ = runtime(self.replies(), fault=fault)
            with self.assertRaises(Exception) as caught:
                run_native_context(context, rt)
            state = caught.exception.__dict__["native_state"]
            self.assertFalse(state.returned)
            self.assertEqual(state.result_status_update, 2)
            self.assertTrue(state.completion_flag_update)
            self.assertEqual(state.native_error_code, expected)
            self.assertEqual(state.driver_error_code, 5 if expected == 19 else None)

    def test_recovery_skips_target_cids_but_parent_address_catalog_is_required(self):
        _, _, context = fixture(observed_cids=(), observations={"recovery": True})
        self.assertEqual((context.password, context.parent_password), (0, 0))
        replies = [b"\x80\0"] + [
            value for _ in range(4) for value in (b"\x80\0", b"\0")
        ]
        rt, _ = runtime(replies)
        self.assertEqual(run_native_context(context, rt)["state"], "writer_completed")
        with self.assertRaises(LookupError):
            fixture(
                omit_parent_catalog=True,
                observations={"recovery": True},
                parameters={"IGOffRetriableFlag": "1"},
            )

    def test_vforest_retry_does_not_require_unused_old_target_cid(self):
        _, _, context = fixture(
            "TCUWCanSecurityVFORESTFlashWriter.dll",
            vforest=True,
            observed_cids=(),
            new_password="DEADBEEF",
            observations={"previous_retry_password": True},
        )
        self.assertEqual(context.password, 0xDEADBEEF)
        rt, _ = runtime(self.vforest_replies(True))
        self.assertEqual(run_native_context(context, rt)["state"], "writer_completed")

    def test_parent_address_group_uses_parent_strategy_and_functional_record(self):
        parent = parameter_bytes(
            "8P4P",
            BigEndianFlag="0",
            GetCANIDFunctionNameForFlashWrite="GetCanIDsFromParamForGetCID",
            CanIDForGetCID="0300/0308\n0750/0000",
        )
        _, _, context = fixture(extra_catalogs={"8P4P.ini": parent})
        self.assertEqual(
            (context.request, context.response),
            (bytes.fromhex("00000300"), bytes.fromhex("00000308")),
        )
        self.assertEqual(context.finish_request, bytes.fromhex("00000750"))
        rt, events = runtime(self.replies())
        run_native_context(context, rt)
        writes = [e["data"] for e in events if e["operation"] == "write_messages"]
        self.assertEqual(writes[-1], bytes.fromhex("0000075080"))

    def test_native_cpu_type_state_rebinds_exact_writer_row_without_changing_image(
        self,
    ):
        from scripts.calibration_2026 import native2026_with_cpu_type

        container, selection, original = fixture()
        state = native2026_with_cpu_type(selection.metadata, 1, "M2")
        catalogs = dict(selection.catalog_sources)
        values = {
            name: "\n".join(value)
            for name, value in selection.values.items()
            if name != "ParamFileKeySystemProtocolMicon"
        }
        catalogs["8P4M2.ini"] = parameter_bytes("8P4M2", **values)
        catalogs.pop("8P4M.ini")
        selected = bind_native_parameter2026(
            container,
            catalogs,
            "write",
            cpu_index=1,
            encoded=False,
            metadata_state=state,
        )
        context = bind_native_context(
            container,
            1,
            ("OLDP", "OLDM"),
            selected,
            original.identity,
            observations={"cpu_index": 1},
        )
        self.assertEqual(context.binding.cpu_type, "M2")
        self.assertEqual(context.image, original.image)
        rt, _ = runtime(self.replies())
        self.assertEqual(run_native_context(context, rt)["state"], "writer_completed")

    def test_two_nodes_global_cpu_parent_and_finish_transition_through_actual48(self):
        for current_node in (1, 2):
            with self.subTest(current_node=current_node):
                _, _, context = two_node_fixture(current_node)
                self.assertEqual(context.cpu_count, 2)
                self.assertEqual(context.cpu_index, current_node - 1)
                self.assertEqual(context.parent_index, 2 - current_node)
                self.assertEqual(context.location_id, b"")
                self.assertEqual(context.request, bytes.fromhex("00000300"))
                replies = (
                    [b"\x80\0"]
                    + [value for _ in range(4) for value in (b"\x80\0", b"\0")]
                    + ([b"\x3c"] if current_node == 1 else [])
                )
                rt, device, provider = actual_runtime(context, replies)
                result = run_native_context(context, rt)
                writes = [
                    e[0]["messages"][0].data
                    for e in provider.calls
                    if e[0]["operation"] == "passthru_write"
                ]
                self.assertEqual(
                    writes[-1],
                    bytes.fromhex("0000030065")
                    if current_node == 1
                    else bytes.fromhex("0000075080"),
                )
                self.assertEqual(
                    result["native_result"]["finish_flag_update"],
                    None if current_node == 1 else True,
                )
                self.assertEqual(device.filters, [])

    def test_bind_rejects_source_and_cross_build_mismatch(self):
        container, selection, context = fixture()
        with self.assertRaises(ValueError):
            bind_native_context(
                container,
                1,
                ("OLDP", "OLDM"),
                replace(selection, source_sha256="0" * 64),
                context.identity,
                observations={"cpu_index": 1},
            )
        identity = identify_native_module(
            "a04681c2c04564801e07c16dd8b2768520b7c4fea1681745e16d527f2612822b",
            "TCUWCanM16CFlashWriter.dll",
        )
        with self.assertRaises(ValueError):
            bind_native_context(
                container,
                1,
                ("OLDP", "OLDM"),
                selection,
                identity,
                observations={"cpu_index": 1},
            )


if __name__ == "__main__":
    unittest.main()
