"""Authored primitive captures exercise the real CUW service algorithms."""

import copy
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

from scripts import cuw_services as native
from scripts.service_replay import (
    MAX_CAPTURE,
    PORT_SOURCES,
    ServiceReplay,
    create_demo_service_capture,
)


def capture(kind="tis-check"):
    return json.loads(create_demo_service_capture(kind))


class ServiceReplayTests(unittest.TestCase):
    def test_every_authored_family_and_redacted_json(self):
        for kind in (*native.OPERATIONS, "rks", "notice"):
            with self.subTest(kind=kind):
                replay = ServiceReplay.from_bytes(create_demo_service_capture(kind))
                result = replay.run()
                self.assertEqual(result["state"], "complete")
                self.assertEqual(result["consumed_steps"], result["total_steps"])
                self.assertEqual(result["cleanup_calls"], 1)
                serialized = json.dumps(result)
                for secret in (
                    "NOT-A-SEED",
                    "NOT-A-LICENSE",
                    "AUTHORED-SEED",
                    "TEST000",
                    "AAAA",
                    "example.invalid",
                ):
                    self.assertNotIn(secret, serialized)
                with self.assertRaises(RuntimeError):
                    replay.run()
        self.assertEqual(ServiceReplay(capture("rks")).run()["watch_statuses"], [12])
        self.assertEqual(ServiceReplay(capture("euro-key")).run()["native_status"], 50)

    def test_actual_service_12_structure_and_exact_port_identity(self):
        for kind in ("tis-check", "euro-save"):
            data = capture(kind)
            data["workflow"]["request"]["product_version"] = 12
            if kind.startswith("tis-"):
                data["workflow"]["request"]["user_type"] = 4
            source = "tis12" if kind.startswith("tis-") else "euro12"
            data["port_sources"] = {source: PORT_SOURCES[source]}
            # TIS user-type maps to identical bytes in this authored example.
            result = ServiceReplay(data).run()
            self.assertEqual(result["native_status"], 1)
        data["workflow"]["request"]["product_version"] = 2026
        with self.assertRaises(ValueError):
            ServiceReplay(data)

    def test_strict_chronology_including_unconsumed_and_void(self):
        for mutation in ("reorder", "extra", "request", "void"):
            data = capture()
            if mutation == "reorder":
                data["steps"].reverse()
            elif mutation == "extra":
                data["steps"].append(copy.deepcopy(data["steps"][-1]))
            elif mutation == "request":
                data["steps"][0]["args"]["body"] = "00"
            else:
                data["steps"][-1]["result"] = True
            replay = ServiceReplay(data)
            with self.assertRaises(ValueError):
                replay.run()
            self.assertEqual(replay.report()["state"], "failed")

    def test_fault_at_every_primitive_and_cleanup_stage(self):
        for kind in (*native.OPERATIONS, "rks", "notice"):
            original = capture(kind)
            for index in range(len(original["steps"])):
                with self.subTest(kind=kind, index=index):
                    data = copy.deepcopy(original)
                    data["steps"][index]["fault"] = "io"
                    replay = ServiceReplay(data)
                    with self.assertRaises(OSError):
                        replay.run()
                    self.assertEqual(replay.report()["state"], "failed")
                    self.assertEqual(replay.report()["error_type"], "OSError")

    def test_cancel_and_aggregate_deadline(self):
        replay = ServiceReplay(capture())
        with self.assertRaises(InterruptedError):
            replay.run(cancelled=lambda: True)
        self.assertEqual(replay.report()["consumed_steps"], 0)
        ticks = iter([0.0, 0.0, 0.0, 0.0, 31.0, 31.0, 31.0])
        replay = ServiceReplay(capture())
        with self.assertRaises(TimeoutError):
            replay.run(clock=lambda: next(ticks))
        self.assertEqual(replay.report()["state"], "failed")
        self.assertGreaterEqual(replay.report()["cleanup_calls"], 1)

    def test_native_xml_http_and_rks_negatives(self):
        for bad_body in (
            b"bad",
            b'<!DOCTYPE a [<!ENTITY x "bad">]><a>&x;</a>',
            b"<wrong/>",
        ):
            data = capture()
            data["steps"][0]["result"]["body"] = bad_body.hex()
            replay = ServiceReplay(data)
            with self.assertRaises(native.ServiceError):
                replay.run()
            self.assertEqual(replay.report()["cleanup_calls"], 1)
        data = capture()
        data["steps"][0]["result"]["status"] = 403
        with self.assertRaises(native.ServiceError):
            ServiceReplay(data).run()
        for body in (
            b"<Signature>A</Signature>",
            ("<Signature>" + "Ж" * 512 + "</Signature>").encode(),
            b"<Signature><a/></Signature>",
        ):
            data = capture("rks")
            data["workflow"]["key_xml"] = body.hex()
            replay = ServiceReplay(data)
            with self.assertRaises(native.ServiceError):
                replay.run()
            self.assertEqual(replay.report()["cleanup_calls"], 1)

    def test_browser_readback_foreign_window_and_notice_foreign_event(self):
        for mutation in ("readback", "window", "origin", "duplicate"):
            data = capture("rks")
            snapshot = data["steps"][4]["result"]
            if mutation == "readback":
                snapshot["elements"][0]["value"] = "changed"
            elif mutation == "window":
                snapshot["window"] = "foreign"
            elif mutation == "origin":
                snapshot["url"] = "https://foreign.invalid"
            else:
                snapshot["elements"] *= 2
            with self.assertRaises(native.ServiceError):
                ServiceReplay(data).run()
        data = capture("notice")
        data["steps"][4]["result"]["window"] = "foreign"
        with self.assertRaises(ValueError):
            ServiceReplay(data).run()

    def test_alias_isolation_and_report_copy(self):
        data = capture()
        replay = ServiceReplay(data)
        data["steps"].clear()
        result = replay.run()
        result["port_sources"].clear()
        self.assertTrue(replay.report()["port_sources"])

    def test_bounded_regular_load_and_atomic_export_preservation(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "capture.json")
            payload = create_demo_service_capture("rks")
            source.write_bytes(payload)
            replay = ServiceReplay.load(source)
            exported = Path(directory, "request.xml")
            replay.export_rks_request(exported)
            self.assertEqual(exported.read_bytes(), replay.rks_request_bytes())
            self.assertEqual(exported.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                replay.export_rks_request(source)
            replay.run()
            with self.assertRaises(FileExistsError):
                replay.export_report(source)
            self.assertEqual(source.read_bytes(), payload)
            report = Path(directory, "report.json")
            replay.export_report(report)
            self.assertEqual(json.loads(report.read_bytes()), replay.report())
            self.assertFalse(list(Path(directory).glob(".service-report-*")))
            fifo = Path(directory, "fifo")
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                ServiceReplay.load(fifo)
            with self.assertRaises(ValueError):
                ServiceReplay.load("/dev/null")

    def test_captured_watch_approval_is_separate_from_shape_import(self):
        data = capture("rks")
        data["steps"][5]["result"]["elements"] = [
            {
                "tag": "input",
                "element_id": "result_code",
                "kind": "hidden",
                "value": "0",
            }
        ]
        result = ServiceReplay(data).run()
        self.assertEqual(result["watch_statuses"], [0])
        self.assertEqual(result["signature_characters"], 512)
        self.assertNotIn("value", result)

    def test_notice_cursor_boundary_and_rks_polling(self):
        data = capture("notice")
        event = data["steps"][4]
        event["result"] = {"window": "authored-notice", "kind": "move", "x": 50, "y": 0}
        farther = copy.deepcopy(event)
        farther["result"]["x"] = 51
        data["steps"].insert(5, farther)
        self.assertEqual(ServiceReplay(data).run()["dismissal"], "move")
        data = capture("rks")
        busy = copy.deepcopy(data["steps"][2])
        busy["result"]["busy"] = True
        data["steps"][2:2] = [
            busy,
            {"method": "browser.wait", "args": {}, "result": None, "fault": None},
        ]
        self.assertEqual(ServiceReplay(data).run()["watch_statuses"], [12])

    def test_reentrant_callbacks_reject_without_deadlock(self):
        self._reentry_case("clock")
        self._reentry_case("cancelled")

    def _reentry_case(self, callback_kind):
        replay = ServiceReplay(capture())
        rejected = []

        def callback():
            with self.assertRaises(RuntimeError):
                replay.run()
            rejected.append(True)
            return False

        def clock_callback():
            callback()
            return 0.0

        outcome = []

        def execute():
            result = (
                replay.run(clock=clock_callback)
                if callback_kind == "clock"
                else replay.run(cancelled=callback)
            )
            outcome.append(result)

        thread = threading.Thread(target=execute, daemon=True)
        thread.start()
        thread.join(1)
        self.assertFalse(thread.is_alive(), "Reentrant callback deadlocked")
        self.assertTrue(rejected)
        self.assertEqual(outcome[0]["state"], "complete")

    def test_initial_clock_fault_always_finalizes_redacted_report(self):
        def broken():
            raise OSError("PRIVATE-CLOCK-SENTINEL")

        for callback, exception in (
            (lambda: float("nan"), ValueError),
            (broken, OSError),
        ):
            replay = ServiceReplay(capture())
            with self.assertRaises(exception):
                replay.run(clock=callback)
            report = replay.report()
            self.assertEqual(report["state"], "failed")
            self.assertEqual(report["consumed_steps"], 0)
            self.assertNotIn("PRIVATE-CLOCK-SENTINEL", json.dumps(report))
            with self.assertRaises(RuntimeError):
                replay.run()

    def test_timed_notice_alternates_and_respects_primitive_budget(self):
        data = capture("notice")
        data["workflow"]["config"]["sound_mode"] = 2
        data["workflow"]["config"]["interval_ms"] = 100
        del data["steps"][3]
        first_event = {
            "method": "notice.event",
            "args": {"window": "authored-notice"},
            "result": None,
            "fault": None,
            "elapsed_ms": 50,
        }
        next_render = copy.deepcopy(data["steps"][2])
        next_render["args"]["color"] = 0
        data["steps"][3:3] = [first_event, copy.deepcopy(first_event), next_render]
        result = ServiceReplay(data).run()
        self.assertEqual(result["elapsed_ms"], 100)
        self.assertEqual(result["dismissal"], "key")
        data["steps"][3]["elapsed_ms"] = 51
        with self.assertRaises(TimeoutError):
            ServiceReplay(data).run()

    def test_recorded_elapsed_bounds_and_outer_deadline(self):
        data = capture()
        data["steps"][0]["elapsed_ms"] = 1000
        with self.assertRaises(TimeoutError):
            ServiceReplay(data).run(timeout=0.5)
        for elapsed in (-1, True, float("inf"), 600001):
            data = capture()
            data["steps"][0]["elapsed_ms"] = elapsed
            with self.assertRaises(ValueError):
                ServiceReplay(data)
        data = capture()
        for step in data["steps"]:
            step["elapsed_ms"] = 400000
        with self.assertRaises(ValueError):
            ServiceReplay(data)

    def test_dom_and_calibration_budgets_precede_object_allocation(self):
        data = capture("rks")
        data["steps"][2]["result"]["elements"] = [{}] * 1025
        with self.assertRaisesRegex(ValueError, "element budget"):
            ServiceReplay(data).run()
        data = capture()
        data["workflow"]["request"]["old_calibrations"] = [{}] * 11
        with self.assertRaisesRegex(ValueError, "ten captured"):
            ServiceReplay(data)

    def test_timed_browser_wait_and_cleanup_budget(self):
        data = capture("rks")
        busy = copy.deepcopy(data["steps"][2])
        busy["result"]["busy"] = True
        wait = {
            "method": "browser.wait",
            "args": {},
            "result": None,
            "fault": None,
            "elapsed_ms": 100,
        }
        data["steps"][2:2] = [busy, wait]
        self.assertEqual(ServiceReplay(data).run()["elapsed_ms"], 100)
        data["steps"][3]["elapsed_ms"] = 101
        with self.assertRaises(TimeoutError):
            ServiceReplay(data).run()
        data = capture()
        data["steps"][-1]["elapsed_ms"] = 5001
        replay = ServiceReplay(data)
        with self.assertRaises(TimeoutError):
            replay.run()
        self.assertEqual(replay.report()["state"], "failed")

    def test_schema_duplicate_budget_identity_and_malformed(self):
        for payload in (
            b'{"schema":1,"schema":2}',
            b"NaN",
            b"[",
            b"\xff",
            b" " * (MAX_CAPTURE + 1),
        ):
            with self.assertRaises((ValueError, TypeError)):
                ServiceReplay.from_bytes(payload)
        for mutation in ("hash", "source", "fault", "steps", "unknown"):
            data = capture()
            if mutation == "hash":
                data["port_sources"]["tis18"] = "0" * 64
            elif mutation == "source":
                data["port_sources"] = {"tis12": PORT_SOURCES["tis12"]}
            elif mutation == "fault":
                data["steps"][0]["fault"] = "success"
            elif mutation == "steps":
                data["steps"] = []
            else:
                data["extra"] = 1
            with self.assertRaises(ValueError):
                ServiceReplay(data)


if __name__ == "__main__":
    unittest.main()
