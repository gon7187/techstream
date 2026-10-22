"""Authored utility XML fixtures; no proprietary plaintext or keys."""

import unittest
import xml.etree.ElementTree as ET
from typing import Any, cast

from scripts.script_vm import UtilityResource
from scripts.utility import UtilityRuntime


def resource(
    body,
    storage='<DATA DATAID="INT01"/><DATA DATAID="INT02"/><DATA DATAID="BYTE01" LENGTH="1"/>',
):
    return UtilityResource(
        b"test",
        ET.fromstring(
            f"<UTILITY><FUNCTION><FUNCID>demo</FUNCID><STORAGE>{storage}</STORAGE>{body}</FUNCTION></UTILITY>"
        ),
    )


def block(body, name="B1"):
    return f'<BLOCK ID="{name}" TYPE="G002">{body}</BLOCK>'


class UtilityTests(unittest.TestCase):
    def test_schema_rejects_wrong_parent_missing_attribute_and_deep_language(self):
        for text in (
            "<FASTACTION><FRAME>$01</FRAME></FASTACTION>",
            "<FASTACTION><CALC/></FASTACTION>",
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                UtilityRuntime(resource(block(text)))
        nested = "<L>" * 130 + "x" + "</L>" * 130
        xml = resource(block(""))
        xml.root.append(ET.fromstring(f"<LANGUAGE>{nested}</LANGUAGE>"))
        with self.assertRaisesRegex(ValueError, "nesting budget"):
            UtilityRuntime(xml)

    def test_display_selection_reenables_key_and_rejects_undeclared_choice(self):
        xml = resource(
            block("""<RADIOTYPE ID="1" OUT="INT02" DEFAULT="1"><RADIO ID="1"/><RADIO ID="2"/></RADIOTYPE>
        <DISPACTION><IF COND="INT02 EQ 2"><KEYSTATE ID="1" MODE="ENABLE"/></IF></DISPACTION>
        <KEYTYPE><KEY ID="1" MODE="DISABLED"><ACTION MODE="BLOCK" NEXT="END"/></KEY></KEYTYPE>""")
        )
        runtime = UtilityRuntime(xml)
        runtime.start("demo")
        self.assertEqual(runtime.storage["INT02"], 1)
        with self.assertRaises(ValueError):
            runtime.key("1")
        with self.assertRaises(ValueError):
            runtime.display({"INT02": []})  # type: ignore[arg-type]
        runtime.display({"INT02": 2})
        self.assertTrue(runtime.key("1")["done"])

    def test_send_deadline_pending_without_receive_and_negative_repeat_limit(self):
        xml = resource(
            block("""<FASTACTION><ACTION MODE="COMM" NEXT="C1"/></FASTACTION><COMM COMMID="C1">
        <EVENT TYPE="SEND" TIMEOUT="10"><FRAME>$22</FRAME></EVENT>
        <EVENT TYPE="SUCCESS" MODE="BLOCK" NEXT="B2"><FRAME>$62</FRAME></EVENT>
        <EVENT TYPE="NEGREPEAT" REPEAT="1" MODE="BLOCK" NEXT="END"><FRAME>$7F,*,$78</FRAME></EVENT>
        <EVENT TYPE="NORESP" MODE="BLOCK" NEXT="END"/></COMM>""")
            + block("", "B2")
        )
        now = [0.0]

        def delayed(ecu, request):
            now[0] += 0.020
            return b"\x62"

        runtime = UtilityRuntime(
            xml, exchange=delayed, clock=lambda: now[0], wait=lambda _: None
        )
        self.assertEqual(runtime.run("demo")["status"], "completed")
        pending = lambda *_: b"\x7f\x22\x78"
        with self.assertRaisesRegex(ValueError, "receive callback"):
            UtilityRuntime(xml, exchange=pending).start("demo")
        runtime = UtilityRuntime(xml, exchange=pending, receive=pending)
        runtime.run("demo")
        self.assertEqual(len([e for e in runtime.trace if e["kind"] == "exchange"]), 2)

    def test_receive_one_based_and_explicit_endian(self):
        for endian, expected in (("BIG", 0x1234), ("LITTLE", 0x3412)):
            xml = resource(
                block(f'''<FASTACTION><ACTION MODE="COMM" NEXT="C1"/></FASTACTION><COMM COMMID="C1">
            <EVENT TYPE="SEND"><FRAME>$22</FRAME></EVENT><EVENT TYPE="SUCCESS" MODE="BLOCK" NEXT="END"><FRAME>$62</FRAME>
            <AFTER><RECEIVE OUT="INT01" POS="2" SIZE="2" ENDIAN="{endian}"/></AFTER></EVENT></COMM>''')
            )
            report = UtilityRuntime(xml, exchange=lambda *_: b"\x62\x12\x34").run(
                "demo"
            )
            self.assertEqual(report["storage"]["INT01"], expected)

    def test_action_library_byref_branch_comm_receive_and_end(self):
        xml = resource(
            block("""<FASTACTION>
          <CALLFUNC NAME="GetValue" OUT="INT01">"INT02","1"</CALLFUNC>
          <IF COND="INT01 EQ 0"><THEN><ACTION MODE="COMM" NEXT="C1"/></THEN><ELSE><ACTION MODE="BLOCK" NEXT="BAD"/></ELSE></IF>
          </FASTACTION><COMM COMMID="C1"><EVENT TYPE="SEND" TIMEOUT="100"><FRAME>$22,$01,BYTE01</FRAME></EVENT>
          <EVENT TYPE="SUCCESS" MODE="BLOCK" NEXT="END"><FRAME>$62,*</FRAME><AFTER>
          <RECEIVE OUT="BYTE01" POS="2" SIZE="1"/><CALC OUT="INT02" OPE="INT02 _PLUS 1"/>
          </AFTER></EVENT></COMM>""")
        )
        calls = []

        def library(name, args, storage):
            self.assertEqual((name, args), ("GetValue", ("INT02", "1")))
            storage["INT02"] = 6
            return 0

        def exchange(ecu, request):
            calls.append((ecu, request))
            return b"\x62\xa5"

        runtime = UtilityRuntime(xml, library=library, exchange=exchange)
        report = runtime.run("demo")
        self.assertEqual(calls, [("utility", b"\x22\x01\0")])
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["storage"], {"INT01": 0, "INT02": 7, "BYTE01": "a5"})

    def test_popup_restore_and_back(self):
        xml = resource(
            block(
                '<KEYTYPE><KEY ID="1"><ACTION MODE="POPUP" NEXT="P1"/></KEY><KEY ID="2"><ACTION MODE="BLOCK" NEXT="B2"/></KEY></KEYTYPE>'
            )
            + block(
                '<KEYTYPE><KEY ID="1"><ACTION MODE="BLOCK" NEXT="POPUP_OFF"/></KEY></KEYTYPE>',
                "P1",
            )
            + block(
                '<KEYTYPE><KEY ID="1"><ACTION MODE="BLOCK" NEXT="RETURN"/></KEY></KEYTYPE>',
                "B2",
            )
        )
        runtime = UtilityRuntime(xml)
        runtime.start("demo")
        self.assertEqual(runtime.key("1")["block"], "P1")
        self.assertEqual(runtime.key("1")["block"], "B1")
        self.assertEqual(runtime.key("2")["block"], "B2")
        self.assertEqual(runtime.key("1")["block"], "B1")

    def test_radio_key_state_and_progress(self):
        xml = resource(
            block("""<RADIOTYPE ID="1" OUT="INT02"><RADIO ID="1"/><RADIO ID="2"/></RADIOTYPE>
        <DISPACTION><KEYSTATE ID="2" MODE="ENABLE"/></DISPACTION>
        <KEYTYPE><KEY ID="2" MODE="DISABLED"><IF COND="INT02 EQ 2"><ACTION MODE="BLOCK" NEXT="B2"/></IF></KEY></KEYTYPE>""")
            + block(
                '<PROGRESS PROGRESSTIME="10" UPDATETIME="2"><ACTION MODE="BLOCK" NEXT="END"/></PROGRESS>',
                "B2",
            )
        )
        runtime = UtilityRuntime(xml)
        runtime.start("demo")
        with self.assertRaises(ValueError):
            runtime.key("2", {"INT01": 1})
        runtime.key("2", {"INT02": 2})
        runtime.progress(10)
        self.assertTrue(runtime.done)

    def test_retry_and_pending_never_resend_pending_request(self):
        xml = resource(
            block("""<FASTACTION><ACTION MODE="COMM" NEXT="C1"/></FASTACTION><COMM COMMID="C1">
        <EVENT TYPE="SEND"><FRAME>$22</FRAME></EVENT>
        <EVENT TYPE="SUCCESS" MODE="BLOCK" NEXT="END"><FRAME>$62</FRAME></EVENT>
        <EVENT TYPE="NEGRETRY" RETRY="2" MODE="BLOCK" NEXT="END"><FRAME>$7F,*,$21</FRAME></EVENT>
        <EVENT TYPE="NEGREPEAT" REPEAT="2" MODE="BLOCK" NEXT="END"><FRAME>$7F,*,$78</FRAME></EVENT>
        <EVENT TYPE="OTHER" MODE="BLOCK" NEXT="END"><FRAME>*</FRAME></EVENT></COMM>""")
        )
        sent, received = [], []
        responses = iter((b"\x7f\x22\x21", b"\x7f\x22\x78"))

        def exchange(ecu, request):
            sent.append(request)
            return next(responses)

        def receive(ecu):
            received.append(ecu)
            return b"\x62"

        runtime = UtilityRuntime(xml, exchange=exchange, receive=receive)
        runtime.run("demo")
        self.assertEqual(sent, [b"\x22", b"\x22"])
        self.assertEqual(received, ["utility"])

    def test_noresponse_retry_and_transport_timeout(self):
        xml = resource(
            block("""<FASTACTION><ACTION MODE="COMM" NEXT="C1"/></FASTACTION><COMM COMMID="C1">
        <EVENT TYPE="SEND"><FRAME>$22</FRAME></EVENT><EVENT TYPE="NORESP" RETRY="2" MODE="BLOCK" NEXT="END"/></COMM>""")
        )
        calls = []

        def exchange(ecu, request):
            calls.append(request)
            raise TimeoutError("fake transport")

        UtilityRuntime(xml, exchange=exchange).run("demo")
        self.assertEqual(len(calls), 3)

    def test_unknown_tags_attributes_modes_functions_fail(self):
        for body in ("<UNKNOWN/>", '<CALC OUT="INT01" OPE="1" EXTRA="1"/>'):
            with self.subTest(body=body), self.assertRaises(ValueError):
                UtilityRuntime(resource(block(body)))
        for body in (
            '<CALLFUNC NAME="Missing" OUT="INT01"/>',
            '<ACTION MODE="SHELL" NEXT="x"/>',
            '<ACTION MODE="BLOCK" NEXT="MISSING"/>',
            '<ACTION MODE="BLOCK" NEXT="RETURN"/>',
        ):
            with self.subTest(body=body), self.assertRaises(ValueError):
                UtilityRuntime(
                    resource(block(f"<FASTACTION>{body}</FASTACTION>"))
                ).start("demo")

    def test_loop_and_callback_cancellation(self):
        xml = resource(
            block('<FASTACTION><ACTION MODE="BLOCK" NEXT="B1"/></FASTACTION>')
        )
        with self.assertRaisesRegex(ValueError, "instruction budget"):
            UtilityRuntime(xml, max_steps=20).start("demo")
        state = [False]

        def library(name, args, storage):
            state[0] = True
            return 0

        xml = resource(
            block('<FASTACTION><CALLFUNC NAME="Cancel" OUT="INT01"/></FASTACTION>')
        )
        with self.assertRaises(InterruptedError):
            UtilityRuntime(xml, library=library, cancelled=lambda: state[0]).start(
                "demo"
            )

    def test_deadline_and_wait_bound(self):
        xml = resource(
            block(
                '<KEYTYPE><KEY ID="1"><ACTION MODE="BLOCK" NEXT="END"/></KEY></KEYTYPE>'
            )
        )
        now = [0.0]
        runtime = UtilityRuntime(xml, clock=lambda: now[0], timeout=1)
        runtime.start("demo")
        now[0] = 2
        with self.assertRaises(TimeoutError):
            runtime.key("1")
        with self.assertRaises(ValueError):
            UtilityRuntime(xml, timeout=float("nan"))

    def test_memory_and_library_storage_validation(self):
        xml = resource(
            block('<FASTACTION><CALLFUNC NAME="Bad" OUT="INT01"/></FASTACTION>')
        )

        def library(name, args, storage):
            storage["BYTE01"] = b"ab"
            return 0

        runtime = UtilityRuntime(xml, library=library)
        with self.assertRaisesRegex(ValueError, "width"):
            runtime.start("demo")
        self.assertEqual(runtime.storage["BYTE01"], b"\0")
        with self.assertRaisesRegex(ValueError, "byte budget"):
            UtilityRuntime(xml, max_bytes=20)

    def test_calc_bitwise_and_receive_bounds(self):
        xml = resource(
            block(
                '<FASTACTION><CALC OUT="BYTE01" OPE="$80"/><CALC OUT="INT01" OPE="BYTE01 OR 2"/><CALC OUT="INT02" OPE="INT01 AND $7F"/><ACTION MODE="BLOCK" NEXT="END"/></FASTACTION>'
            )
        )
        report = UtilityRuntime(xml).run("demo")
        self.assertEqual(report["storage"]["INT02"], 2)
        xml = resource(
            block('<FASTACTION><RECEIVE OUT="INT01" POS="3" SIZE="1"/></FASTACTION>')
        )
        with self.assertRaisesRegex(ValueError, "outside response"):
            UtilityRuntime(xml).start("demo")

    def test_dialog_execution_and_init_per_entry(self):
        xml = resource(
            block(
                '<INITACTION><CALC OUT="INT01" OPE="INT01 _PLUS 1"/></INITACTION><KEYTYPE><KEY ID="1"><ACTION MODE="BLOCK" NEXT="B2"/></KEY><KEY ID="2"><ACTION MODE="BLOCK" NEXT="END"/></KEY></KEYTYPE>'
            )
            + block(
                '<KEYTYPE><KEY ID="1"><ACTION MODE="BLOCK" NEXT="RETURN"/></KEY></KEYTYPE>',
                "B2",
            )
        )
        selections = iter(("1", "1", "2"))
        runtime = UtilityRuntime(xml, dialog=lambda screen: next(selections))
        self.assertEqual(runtime.run("demo")["storage"]["INT01"], 2)
        runtime.start("demo")
        self.assertEqual(runtime.storage["INT01"], 1)

    def test_dialog_display_updates_radio_without_key_and_screen_instances(self):
        xml = resource(
            block("""<RADIOTYPE ID="1" OUT="INT02" DEFAULT="1"><RADIO ID="1"/><RADIO ID="2"/></RADIOTYPE>
        <DISPACTION><IF COND="INT02 EQ 2"><KEYSTATE ID="1" MODE="ENABLE"/></IF></DISPACTION>
        <KEYTYPE><KEY ID="1" MODE="DISABLED"><ACTION MODE="BLOCK" NEXT="END"/></KEY></KEYTYPE>""")
        )
        screens = []

        def dialog(screen):
            screens.append(screen)
            return {"display": {"INT02": 2}} if len(screens) == 1 else "1"

        runtime = UtilityRuntime(xml, dialog=dialog)
        self.assertEqual(runtime.run("demo")["status"], "completed")
        self.assertEqual(screens[0]["radios"][0]["value"], 1)
        self.assertEqual(screens[1]["radios"][0]["value"], 2)
        self.assertEqual(screens[0]["block_instance"], screens[1]["block_instance"])
        self.assertTrue(screens[1]["keys"][0]["enabled"])
        self.assertIsNone(runtime.screen()["block_instance"])

    def test_progress_elapsed_and_same_block_reentry_gets_new_instance(self):
        xml = resource(
            block(
                '<PROGRESS PROGRESSTIME="10" UPDATETIME="2"><ACTION MODE="BLOCK" NEXT="B1"/></PROGRESS>'
            )
        )
        runtime = UtilityRuntime(xml)
        first = runtime.start("demo")
        runtime.progress(1)
        self.assertEqual(runtime.screen()["progress_elapsed_ms"], 0)
        runtime.progress(2)
        current = runtime.screen()
        self.assertEqual(current["block"], first["block"])
        self.assertGreater(current["block_instance"], first["block_instance"])
        self.assertEqual(current["progress_elapsed_ms"], 0)


class NativeUtilityTests(unittest.TestCase):
    """Real authored TY business provider under the recovered native controller."""

    def native(self, *, initial=0, clear=0, fault=False, hold=False, dcm_value=None):
        from scripts.utility_authored import AuthoredNativeUtility

        fixture = AuthoredNativeUtility(
            initial=initial,
            clear=clear,
            fault=fault,
            hold=hold,
            dcm_value=dcm_value,
        )
        self.addCleanup(fixture.close)
        return fixture.runtime, fixture.events, fixture.entered

    def test_native_selected_controller_executes_real_business_and_reports(self):
        runtime, events, _ = self.native()
        screen = runtime.start(0x1381D)
        self.assertEqual(screen["progress"]["UPDATETIME"], 1000)
        self.assertEqual(runtime.progress(999)["status"], "waiting")
        screen = runtime.progress(1000)
        self.assertEqual(
            (screen["block"], screen["status"]), (str(0x1381E), "completed")
        )
        self.assertIn(b"\x80\x01\x02\x03", events)
        self.assertEqual(events[-1], "finalize")
        self.assertEqual(
            [e["result"] for e in runtime.report()["events"] if "iat_rva" in e], [15, 0]
        )
        self.assertFalse(runtime.report()["done"])
        runtime.key("acknowledge")
        self.assertTrue(runtime.report()["done"])

    def test_bsm_exact_source_mode_rejects_other_mode_without_worker_or_transport(self):
        from scripts.utility import NativeBSMRuntime
        from scripts.utility_authored import AuthoredNativeUtility

        for function, group in ((0x137B8, 0x134A), (0x137EA, 0x134B)):
            with self.subTest(function=function), AuthoredNativeUtility() as fixture:
                runtime = NativeBSMRuntime(fixture.runtime.libraries)
                screen = runtime.open(function)
                self.assertEqual((screen["status"], runtime.result), ("error", 99))
                self.assertEqual(runtime.utility_group, group)
                self.assertEqual(fixture.events, [])
                self.assertIsNone(runtime.libraries.engine.worker._thread)
                with self.assertRaises(ValueError):
                    runtime.key("next", {"invented": 1})
                runtime.key("acknowledge")
                self.assertTrue(runtime.done)

    def test_dcm_full_entry_conditions_cancel_without_native_work(self):
        from scripts.utility import NativeDCM45Runtime

        base, events, _ = self.native()
        runtime = NativeDCM45Runtime(base.libraries)
        initial = runtime.open(0x13723)
        self.assertEqual((initial["title_id"], initial["message_id"]), (0x948A, 0x948D))
        self.assertEqual(initial["keys"], [{"id": "next"}])
        self.assertEqual(runtime.utility_group, 0x1352)
        self.assertEqual(events, [])
        with self.assertRaises(ValueError):
            runtime.key("next", {"invented": 1})
        with self.assertRaises(ValueError):
            runtime.open(0x13723)
        runtime.cancel()
        self.assertEqual(runtime.status, "cancelled")
        self.assertEqual(events, [])

    def test_dcm_cancellation_between_conditions_and_next_starts_no_worker(self):
        from scripts.utility import NativeDCM45Runtime

        base, events, _ = self.native()
        cancelled = [False]
        runtime = NativeDCM45Runtime(base.libraries, cancelled=lambda: cancelled[0])
        runtime.open(0x13723)
        cancelled[0] = True
        with self.assertRaises(InterruptedError):
            runtime.key("next")
        self.assertEqual(events, [])
        self.assertTrue(runtime.done)
        self.assertIsNone(runtime.libraries.engine.worker._thread)

    def test_native_entry_conditions_require_next_before_any_work(self):
        runtime, events, _ = self.native()
        screen = runtime.open(0x1381D)
        self.assertEqual((screen["title_id"], screen["message_id"]), (0x94B5, 0x94B8))
        self.assertEqual(screen["keys"], [{"id": "next"}])
        self.assertEqual(events, [])
        with self.assertRaises(ValueError):
            runtime.key("acknowledge")
        self.assertEqual(runtime.key("next")["status"], "waiting")
        runtime.progress(1000)
        runtime.key("acknowledge")

    def test_native_cancel_on_initial_screen_never_opens_transport(self):
        runtime, events, _ = self.native()
        runtime.open(0x1381D)
        runtime.cancel()
        self.assertEqual(events, [])
        self.assertEqual(runtime.status, "cancelled")
        with self.assertRaises(ValueError):
            runtime.key("next")

    def test_selected_event_runtime_requires_full_cgw_controller_for_dcm_entry(self):
        runtime, events, _ = self.native()
        with self.assertRaisesRegex(LookupError, "NativeDCM45Runtime"):
            runtime.open(0x13723)
        self.assertEqual(events, [])

    def test_native_operation_error_uses_special_native_result_modal(self):
        runtime, events, _ = self.native(clear=3)
        runtime.start(0x1381D)
        screen = runtime.progress(1000)
        self.assertEqual(runtime.result, 1000)
        self.assertEqual((screen["title_id"], screen["message_id"]), (0x94B7, 0x94BC))
        self.assertEqual(events[-1], "finalize")

    def test_dcm_controller_retains_output_and_dispatches_stored_native_result(self):
        from scripts.utility_authored import AuthoredNativeUtility

        for value in (0, 7):
            with (
                self.subTest(value=value),
                AuthoredNativeUtility(dcm_value=value) as fixture,
            ):
                runtime = fixture.runtime
                screen = runtime.start(0x13723)
                self.assertEqual(
                    (screen["title_id"], screen["message_id"]), (0x948B, 0x9490)
                )
                screen = runtime.progress(1000)
                self.assertEqual(runtime.receiver, bytes([value, 0, 0, 0]))
                self.assertEqual(runtime.result, 2005 if value else 0)
                self.assertEqual(runtime.utility_group, 0x1352)
                self.assertEqual(fixture.events[-1], "finalize")
                self.assertEqual(
                    [entry["result"] for entry in runtime.trace if "iat_rva" in entry],
                    [2005 if value else 0, 2005 if value else 0],
                )
                if value:
                    self.assertEqual(
                        (screen["title_id"], screen["message_id"]), (0x948C, 0x9492)
                    )
                else:
                    self.assertEqual(
                        (screen["block"], screen["output"]), (str(0x13724), "0")
                    )
                runtime.key("acknowledge")

    def test_dcm_worker_fault_propagates_with_native_cleanup(self):
        runtime, events, _ = self.native(dcm_value=0, fault=True)
        runtime.start(0x13723)
        with self.assertRaisesRegex(OSError, "authored exchange fault"):
            runtime.progress(1000)
        self.assertEqual(runtime.status, "fault")
        self.assertEqual(events[-1], "finalize")

    def test_native_initial_error_uses_generic_native_modal(self):
        runtime, events, _ = self.native(initial=7)
        runtime.start(0x1381D)
        self.assertEqual(runtime.progress(1000)["message_id"], 0x104B)
        self.assertEqual(events[-1], "finalize")

    def test_native_generic_error_returns_to_conditions_for_source_retry(self):
        runtime, _, _ = self.native(initial=7)
        runtime.open(0x1381D)
        runtime.key("next")
        runtime.progress(1000)
        self.assertEqual(runtime.status, "error")
        screen = runtime.key("acknowledge")
        self.assertFalse(runtime.done)
        self.assertEqual((screen["status"], screen["message_id"]), ("ready", 0x94B8))
        runtime.key("next")
        self.assertEqual(runtime.elapsed, 0)
        runtime.progress(1000)
        runtime.key("acknowledge")
        runtime.cancel()

    def test_native_provider_fault_propagates_and_closes_progress(self):
        runtime, events, _ = self.native(fault=True)
        runtime.start(0x1381D)
        with self.assertRaisesRegex(OSError, "authored exchange fault"):
            runtime.progress(1000)
        self.assertEqual(runtime.report()["status"], "fault")
        self.assertEqual(events[-1], "finalize")
        self.assertFalse(runtime._progress_open)

    def test_native_cancel_joins_owned_worker_and_rejects_more_events(self):
        runtime, events, entered = self.native(hold=True)
        runtime.start(0x1381D)
        self.assertTrue(entered.wait(1))
        runtime.cancel()
        self.assertEqual(events[-1], "finalize")
        self.assertEqual(runtime.report()["status"], "cancelled")
        self.assertIsNone(runtime.libraries.engine.worker._thread)
        with self.assertRaises(ValueError):
            runtime.progress(1000)

    def test_native_malformed_selection_and_events_fail_closed(self):
        runtime, _, _ = self.native()
        for value in ("Ex2DOOR_01_StartConnectionHistoryClear", True, 0x1381E):
            with self.assertRaises(LookupError):
                runtime.start(cast(Any, value))
        runtime.start(0x1381D)
        with self.assertRaises(ValueError):
            runtime.start(0x1381D)
        for value in (-1, True, "1000"):
            with self.assertRaises(ValueError):
                runtime.progress(cast(Any, value))
        with self.assertRaises(ValueError):
            runtime.key("arbitrary")
        runtime.cancel()

    def test_native_busy_poll_preserves_progress_until_cancel(self):
        runtime, _, entered = self.native(hold=True)
        runtime.start(0x1381D)
        self.assertTrue(entered.wait(1))
        self.assertEqual(runtime.progress(1000)["status"], "waiting")
        self.assertTrue(runtime._progress_open)
        runtime.cancel()

    def test_native_host_deadline_cancels_without_native_success(self):
        runtime, _, entered = self.native(hold=True)
        runtime.start(0x1381D)
        self.assertTrue(entered.wait(1))
        with self.assertRaises(TimeoutError):
            runtime.progress(300001)
        self.assertEqual(runtime.report()["status"], "cancelled")
        self.assertIsNone(runtime.libraries.engine.worker._thread)

    def test_native_failed_join_preserves_owned_worker_and_dialog(self):
        from unittest.mock import patch

        runtime, _, entered = self.native(hold=True)
        runtime.start(0x1381D)
        self.assertTrue(entered.wait(1))
        try:
            with (
                patch.object(
                    runtime.libraries.engine.worker, "stop", side_effect=TimeoutError
                ),
                self.assertRaises(TimeoutError),
            ):
                runtime.cancel()
            self.assertEqual(runtime.report()["status"], "cleanup-failed")
            self.assertIsNotNone(runtime.libraries.engine.worker._thread)
            self.assertTrue(runtime._progress_open)
        finally:
            runtime.cancel()

    def test_native_interrupted_join_cannot_discard_still_owned_worker(self):
        from unittest.mock import patch

        runtime, _, entered = self.native(hold=True)
        runtime.start(0x1381D)
        self.assertTrue(entered.wait(1))
        try:
            with (
                patch.object(
                    runtime.libraries.engine.worker,
                    "stop",
                    side_effect=InterruptedError,
                ),
                self.assertRaises(InterruptedError),
            ):
                runtime.cancel()
            self.assertEqual(runtime.status, "cleanup-failed")
            self.assertFalse(runtime.done)
        finally:
            runtime.cancel()

    def test_native_busy_rejection_cannot_cancel_another_procedure_worker(self):
        from scripts.utility import NativeUtilityRuntime

        owner, _, entered = self.native(hold=True)
        owner.start(0x1381D)
        self.assertTrue(entered.wait(1))
        other = NativeUtilityRuntime(owner.libraries)
        self.assertEqual(other.start(0x1381D)["status"], "error")
        self.assertEqual(other.result, 16)
        other.cancel()
        self.assertFalse(owner.libraries.engine.context._cancel.is_set())
        self.assertIsNotNone(owner.libraries.engine.worker._thread)
        owner.cancel()

    def test_native_pre_cancel_and_unknown_source_do_not_start_work(self):
        from scripts.utility import NativeUtilityRuntime

        runtime, events, _ = self.native()
        runtime.cancelled = lambda: True
        with self.assertRaises(InterruptedError):
            runtime.start(0x1381D)
        self.assertEqual(events, [])
        runtime.libraries.caller_sha256 = "0" * 64
        with self.assertRaises(LookupError):
            NativeUtilityRuntime(runtime.libraries)


class NativeUtilityRecordingTests(unittest.TestCase):
    def recording(self, events, *, broker=None):
        import json

        from scripts.utility import NativeUtilityRecording

        return NativeUtilityRecording(
            json.dumps(
                {
                    "schema": "techstream-native-utility-v1",
                    "source": "authored_synthetic",
                    "caller_sha256": "caller",
                    "engine_sha256": "engine",
                    "broker": broker or {"111": 20},
                    "events": events,
                }
            ).encode(),
            "caller",
            "engine",
        )

    def value(self, value):
        if value is None:
            return {"type": "none", "value": None}
        if type(value) is int:
            return {"type": "int", "value": value}
        if type(value) is bytes:
            return {"type": "bytes", "value": value.hex()}
        if type(value) is list:
            return {"type": "sequence", "value": [self.value(item) for item in value]}
        if type(value) is str:
            return {"type": "text", "value": value}
        return {
            "type": "mapping",
            "value": {key: self.value(item) for key, item in value.items()},
        }

    def event(self, operation, arguments, status=0, outputs=None):
        return {
            "kind": "action",
            "request": {"operation": operation, "arguments": arguments},
            "result": self.value({"status": status, "outputs": outputs or {}}),
            "elapsed_ms": 0,
        }

    def test_raw_sdk_replay_preserves_output_pointer_and_chronology(self):
        event = self.event(
            "PassThruConnect",
            [6, 512, {"type": "bytes", "value": "00000000"}],
            outputs={"2": b"\x07\0\0\0"},
        )
        recording = self.recording([event])
        output = bytearray(4)
        result = recording.driver_exports["PassThruConnect"](6, 512, output)
        self.assertEqual(
            (result.status, result.value, output), (0, None, b"\x07\0\0\0")
        )
        recording.assert_complete()
        self.assertEqual(recording.report()["source"], "authored_synthetic")
        with self.assertRaises(ValueError):
            recording.driver_exports["PassThruConnect"](6, 512, output)

    def test_standard_and_sis_controller_tables_share_ordered_primitive_trace(self):
        events = [
            self.event(
                "J2534CtrlInitialize",
                [kind, {"type": "bytes", "value": "00000000"}],
                outputs={"1": value.to_bytes(4, "little")},
            )
            for kind, value in ((1, 51), (2, 52))
        ]
        recording = self.recording(events)
        standard, sis = bytearray(4), bytearray(4)
        recording.driver_exports["J2534CtrlInitialize"](1, standard)
        recording.sis_driver_exports["J2534CtrlInitialize"](2, sis)
        self.assertEqual(
            (int.from_bytes(standard, "little"), int.from_bytes(sis, "little")),
            (51, 52),
        )
        self.assertNotIn("PassThruReadMsgs_v0500", recording.driver_exports)
        self.assertNotIn("PassThruReadMsgs", recording.sis_driver_exports)
        recording.assert_complete()

    def test_raw_read_replays_native_messages_and_count_separately(self):
        from scripts.j2534_2026 import NativeMessage
        from scripts.programming_replay import _native_request

        incoming = NativeMessage(6, b"\x70\x01")
        backing = [NativeMessage(0, b"")]
        event = self.event(
            "PassThruReadMsgs",
            [7, _native_request(backing), {"type": "bytes", "value": "01000000"}, 1000],
            outputs={
                "1": [{"_native_type": "PASSTHRU_MSG_2026", **vars(incoming)}],
                "2": b"\x01\0\0\0",
            },
        )
        recording = self.recording([event])
        count = bytearray(b"\x01\0\0\0")
        recording.driver_exports["PassThruReadMsgs"](7, backing, count, 1000)
        self.assertEqual(backing, [incoming])
        self.assertEqual(count, b"\x01\0\0\0")
        recording.assert_complete()

    def test_wrong_raw_call_and_invalid_output_fail_without_mutation(self):
        event = self.event(
            "PassThruConnect",
            [6, 512, {"type": "bytes", "value": "00000000"}],
            outputs={"2": b"bad-size"},
        )
        recording = self.recording([event])
        output = bytearray(4)
        with self.assertRaises(ValueError):
            recording.driver_exports["PassThruConnect"](6, 513, output)
        self.assertEqual(recording.trace.position, 0)
        with self.assertRaises(ValueError):
            recording.driver_exports["PassThruConnect"](6, 512, output)
        self.assertEqual(output, bytes(4))

    def test_wait_requires_recorded_duration_and_complete_consumption(self):
        event = {
            "kind": "action",
            "request": {"operation": "wait", "milliseconds": 100},
            "result": self.value(None),
            "elapsed_ms": 100,
        }
        recording = self.recording([event])
        with self.assertRaises(ValueError):
            recording.assert_complete()
        recording.sleep(100)
        self.assertEqual(recording.ticks(), 100)
        recording.assert_complete()
        event["elapsed_ms"] = 99
        with self.assertRaises(ValueError):
            self.recording([event])

    def test_business_callbacks_and_absent_broker_are_rejected(self):
        event = self.event("Ex2DOOR_01_StartConnectionHistoryClear", [])
        with self.assertRaises(ValueError):
            self.recording([event])
        recording = self.recording([])
        with self.assertRaises(LookupError):
            recording.get_parameter(112)
        with self.assertRaises(LookupError):
            recording.set_parameter(111, 4)


class NativeUtilityPresentationTests(unittest.TestCase):
    native = NativeUtilityTests.native

    def test_real_utility_text_broker_shapes_normal_dialog_and_keeps_provenance(self):
        import struct

        from scripts.demo import _ddb, _language
        from scripts.diagnostic_db import parse_database
        from scripts.text_resources import UtilityTextResources
        from scripts.utility import native_utility_screen

        ids = (0x94B5, 0x94B6, 0x94BA, 0x94B9, 0x1043)
        rows, symbols = b"", b""
        for index, identifier in enumerate(ids, 1):
            key = f"IDS_AUTHORED_{index}"
            encoded = key.encode("utf-16le")
            rows += encoded.ljust(80, b"\0") + bytes(80) + struct.pack("<I", index)
            symbols += struct.pack("<IIH", 4934, identifier, len(encoded)) + encoded
        pool = parse_database(_language([f"Authored text {i}" for i in ids])).sections[
            0
        ]
        texts = UtilityTextResources(
            _ddb(6, {0: (len(ids), pool.payload), 1: (len(ids), rows)}),
            symbols,
            utility_group=4934,
        )
        runtime, _, _ = self.native()
        runtime.start(0x1381D)
        view = native_utility_screen(runtime, texts)
        self.assertEqual(view["title"], f"Authored text {0x94B6}")
        self.assertTrue(view["areas"][0]["text"])
        self.assertEqual(view["radios"], [])
        self.assertGreater(view["deadline_monotonic"], 0)
        runtime.progress(1000)
        view = native_utility_screen(runtime, texts)
        self.assertEqual(view["keys"][0]["id"], "acknowledge")
        self.assertEqual(view["resources"][0]["resource"]["namespace"], "utility")
        texts.utility_group = 20000
        with self.assertRaises(ValueError):
            native_utility_screen(runtime, texts)


if __name__ == "__main__":
    unittest.main()
