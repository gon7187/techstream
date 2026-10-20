"""Production procedure helpers over authored resources and explicit recordings."""

import hashlib
import json
import os
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

import scripts.native_procedures as procedures
from scripts.native_procedures import (
    ProcedureRecording,
    create_example_files,
    load_translations,
    open_utility,
    read_utility_symbols,
    replay_script,
    replay_utility,
)
from scripts.profiles import VehicleCatalog
from scripts.utility_bindings import UtilityBindings


def database(kind, sections):
    header = bytearray(36 + 4 * (max(sections) + 1))
    header[8:10] = bytes([kind, max(sections) + 1])
    header[10:28] = b"DiagTool DataCtrl\0"
    struct.pack_into("<I", header, 28, 0x0100032F)
    body = bytearray()
    for slot, (count, payload) in sorted(sections.items()):
        struct.pack_into("<I", header, 36 + slot * 4, len(header) + len(body))
        body += struct.pack("<BBII", slot, 0, count, len(payload)) + payload
    return bytes(header + body)


class NativeProcedureTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        category = bytearray(76)
        category[:18] = "demo.ddb\0".encode("utf-16le")
        struct.pack_into("<H", category, 68, 42)
        (self.root / "Toyota.ddb").write_bytes(database(1, {16: (1, bytes(category))}))
        (self.root / "M_English.ddb").write_bytes(database(4, {0: (0, b"")}))
        (self.root / "demo.ddb").write_bytes(database(2, {0: (0, b"")}))
        self.profile = VehicleCatalog(self.root).build_profile(42)
        self.files = create_example_files(self.root / "examples")

    def modify(self, key, change):
        path = self.files[key]
        data = json.loads(path.read_text())
        change(data)
        path.write_text(json.dumps(data))

    def utility(self, dialog=None, cancelled=lambda: False):
        selections = iter(({"display": {"INT02": 2}}, "1"))
        return replay_utility(
            self.profile,
            self.files["utility"],
            self.files["utility_recording"],
            function_id="demo",
            dialog=dialog or (lambda screen: next(selections)),
            cancelled=cancelled,
        )

    def script(self, **kwargs):
        return replay_script(
            self.profile,
            self.files["script"],
            self.files["script_recording"],
            cancelled=lambda: False,
            **kwargs,
        )

    def test_mixed_driver_pdu_and_actual_dialog_round_trip(self):
        screens = []

        def dialog(screen):
            screens.append(screen)
            return {"display": {"INT02": 2}} if len(screens) == 1 else "1"

        result = self.utility(dialog)
        self.assertEqual(result["status"], "completed", result)
        self.assertEqual(result["remaining_events"], 0)
        self.assertEqual(
            [event["kind"] for event in result["events"] if event["kind"] != "dialog"],
            ["driver", "pdu", "driver"],
        )
        self.assertEqual(screens[0]["title"], "Recorded procedure")
        self.assertFalse(screens[0]["keys"][0]["enabled"])
        self.assertTrue(screens[1]["keys"][0]["enabled"])
        self.assertEqual(screens[1]["radios"][0]["value"], 2)
        self.assertEqual(screens[0]["block_instance"], screens[1]["block_instance"])
        self.assertEqual(result["physical_status"], "PHYSICAL_UNCONFIRMED")

    def test_csdf_actual_file_provider_options_and_variables(self):
        result = self.script()
        self.assertEqual(result["status"], "completed", result)
        self.assertEqual(result["remaining_events"], 0)
        self.modify(
            "script_recording",
            lambda data: data["events"][0]["options"].update(retry_count=1),
        )
        self.assertEqual(self.script()["status"], "failed")

    def test_driver_interleaving_and_arguments_are_not_no_ops(self):
        self.modify("utility_recording", lambda data: data["events"].reverse())
        result = self.utility()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["remaining_events"], 3)
        create_example_files(self.root / "other")

    def test_native_status_partial_bytes_preserved(self):
        def change(data):
            transaction = data["events"][1]["transaction"]
            transaction.pop("response")
            transaction.update(status=0xC0040001, partial_response="7f")

        self.modify("utility_recording", change)
        result = self.utility()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error"]["native_status"], 0xC0040001)
        self.assertEqual(result["error"]["partial_response"], "7f")
        self.assertEqual(result["remaining_events"], 1)

    def test_unused_events_and_driver_failure_are_not_success(self):
        self.modify(
            "script_recording",
            lambda data: data["events"].append(
                {
                    "kind": "driver",
                    "operation": "abort",
                    "arguments": [],
                    "result": None,
                }
            ),
        )
        self.assertEqual(self.script()["status"], "failed")
        self.modify(
            "utility_recording", lambda data: data["events"][0].update(result=19)
        )
        result = self.utility()
        self.assertEqual(result["status"], "partial", result)
        self.assertEqual(result["observed_native_failures"][0]["result"], 19)

    def test_no_implicit_broker_initial_variables_or_decryption_key(self):
        with self.assertRaises(ValueError):
            open_utility(self.files["script"])
        self.modify(
            "utility_recording", lambda data: data["context"].update(broker=None)
        )
        with self.assertRaises(ValueError):
            self.utility()
        self.modify(
            "script_recording",
            lambda data: data["context"].update(initial_variables=None),
        )
        with self.assertRaises(TypeError):
            self.script()
        for initial in (
            {"00001": {"tag": 3, "payload": ""}},
            {"32768": {"tag": 0, "payload": ""}},
        ):
            self.modify(
                "script_recording",
                lambda data, initial=initial: data["context"].update(
                    initial_variables=initial
                ),
            )
            with self.assertRaisesRegex(ValueError, "variable ID or type"):
                self.script()

    def test_cancelled_dialog_and_timeout_are_reported(self):
        result = self.utility(cancelled=lambda: True)
        self.assertEqual(result["status"], "cancelled", result)
        self.assertEqual(result["remaining_events"], 3)

        def dialog(screen):
            raise TimeoutError("Dialog timeout")

        self.assertEqual(self.utility(dialog)["error"]["type"], "TimeoutError")

    def test_duplicate_json_key_malformed_transaction_and_bounds(self):
        path = self.files["script_recording"]
        path.write_text('{"schema":"a","schema":"b"}')
        with self.assertRaises(ValueError):
            ProcedureRecording(path, lambda: False)
        path.write_bytes(b" " * (16 * 1024 * 1024 + 1))
        with self.assertRaises(ValueError):
            ProcedureRecording(path, lambda: False)

    def test_explicit_record_attachments_cannot_escape_to_filesystem(self):
        secret = self.root / "private.bin"
        secret.write_bytes(b"sentinel")
        with self.assertRaises(ValueError):
            self.script(record_files={b"bad\0name": secret})
        self.assertEqual(
            self.script(record_files={b"logical": secret})["status"], "completed"
        )

    def test_language_missing_and_external_translation_remain_honest(self):
        path = self.files["utility"]
        raw = path.read_bytes().replace(
            "Recorded procedure".encode("utf-16le"),
            "IDS_EXTERNAL_TITLE".encode("utf-16le"),
        )
        path.write_bytes(raw)
        result = self.utility()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["unresolved_language_tokens"], ["IDS_EXTERNAL_TITLE"])

    def test_script_sequence_failure_is_partial_and_plural_receive_is_correlated(self):
        self.modify(
            "script_recording",
            lambda data: data["events"][0]["options"].update(
                sequence_code=8, response_count=0
            ),
        )
        self.assertEqual(self.script()["status"], "partial")
        path = self.files["script"]
        path.write_bytes(
            path.read_bytes().replace(
                bytes.fromhex("4003010002"), bytes.fromhex("4003050002")
            )
        )

        def plural(data):
            data["events"][0]["options"].update(
                sequence_code=0, response_count=2, plural=True
            )
            data["events"].append(
                {
                    "kind": "pdu",
                    "transaction": {
                        "ecu": "authored-ecu",
                        "request": "",
                        "response": "410d33",
                    },
                    "options": None,
                }
            )

        self.modify("script_recording", plural)
        result = self.script()
        self.assertEqual(result["status"], "completed", result)
        self.assertEqual(result["remaining_events"], 0)
        self.modify(
            "script_recording",
            lambda data: data["events"][1]["transaction"].update(request="010d"),
        )
        self.assertEqual(self.script()["status"], "failed")

    def test_cooperative_worker_cleanup_consumes_recorded_abort(self):
        self.modify(
            "utility_recording",
            lambda data: data["events"].append(
                {
                    "kind": "driver",
                    "operation": "abort",
                    "arguments": [],
                    "result": None,
                }
            ),
        )
        original = UtilityBindings.from_profile
        workers = []

        def binding(*args, **kwargs):
            host = original(*args, **kwargs)

            def work():
                host._stop.wait(2)
                host._status = 0

            host._worker = threading.Thread(target=work)
            host._worker.start()
            workers.append(host._worker)
            return host

        with patch(
            "scripts.native_procedures.UtilityBindings.from_profile",
            side_effect=binding,
        ):
            result = self.utility()
        self.assertEqual(result["status"], "completed", result)
        self.assertFalse(workers[0].is_alive())
        self.assertEqual(result["events"][-1]["operation"], "abort")
        self.assertEqual(result["remaining_events"], 0)

    def test_pure_vm_loop_obeys_wall_clock_deadline(self):
        self.files["script"].write_bytes(bytes.fromhex("0000000000010041020000"))
        self.modify(
            "script_recording",
            lambda data: (
                data.update(events=[]),
                data["context"].update(initial_variables={}),
                data["context"]["limits"].update(seconds=0.001, steps=1000000),
            ),
        )
        result = self.script()
        self.assertEqual(result["status"], "failed", result)
        self.assertEqual(result["error"]["type"], "TimeoutError")

    def test_driver_boolean_types_extra_fields_and_context_dimensions(self):
        for replacement in (1, None, "false"):
            with self.subTest(replacement=replacement):
                data = json.loads(self.files["utility_recording"].read_text())
                data["events"][0]["arguments"][1] = replacement
                path = self.root / "invalid.json"
                path.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    ProcedureRecording(path, lambda: False)
        self.modify(
            "script_recording",
            lambda data: data["context"]["limits"].update(exchanges=0),
        )
        with self.assertRaises(ValueError):
            self.script()

    def test_fifo_input_is_rejected_without_blocking(self):
        fifo = self.root / "input.fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, "regular file"):
            open_utility(fifo)
        with self.assertRaisesRegex(ValueError, "regular file"):
            ProcedureRecording(fifo, lambda: False)

    def test_native_symbol_catalogue_has_real_namespaced_ids(self):
        name = "IDS_COM_NEXT".encode("utf-16le")
        data = struct.pack("<IIH", 20000, 4143, len(name)) + name
        path = self.root / "symbols.rsd"
        path.write_bytes(data)
        self.assertEqual(read_utility_symbols(path), {"IDS_COM_NEXT": (20000, 4143)})
        for malformed in (data[:-1], data + data, b"\0", data[:8] + b"\x01\0" + b"x"):
            path.write_bytes(malformed)
            with self.assertRaises((ValueError, UnicodeError)):
                read_utility_symbols(path)

    def test_explicit_translation_catalogue_resolves_original_symbol(self):
        path = self.files["utility"]
        path.write_bytes(
            path.read_bytes().replace(
                "Recorded procedure".encode("utf-16le"),
                "IDS_EXTERNAL_TITLE".encode("utf-16le"),
            )
        )
        catalogue = self.root / "translations.json"
        catalogue.write_text(
            json.dumps(
                {
                    "schema": "techstream-utility-translations-v1",
                    "source": "authored_synthetic",
                    "locale": "en",
                    "translations": {"IDS_EXTERNAL_TITLE": "Provided title"},
                }
            )
        )
        screens = []

        def dialog(screen):
            screens.append(screen)
            return {"display": {"INT02": 2}} if len(screens) == 1 else "1"

        report = replay_utility(
            self.profile,
            self.files["utility"],
            self.files["utility_recording"],
            function_id="demo",
            dialog=dialog,
            cancelled=lambda: False,
            translation_file=catalogue,
        )
        self.assertEqual(report["status"], "completed", report)
        self.assertEqual(screens[0]["title"], "Provided title")
        self.assertIn(str(catalogue.resolve()), report["source_paths"])

    def test_native_utility_language_ddb_uses_symbol_table_and_first_match(self):
        text = "Original caption\0".encode("utf-16le")
        pool = struct.pack("<IH", 0, len(text)) + text
        row = bytearray(164)
        symbol = "IDS_EXTERNAL_TITLE\0".encode("utf-16le")
        row[: len(symbol)] = symbol
        struct.pack_into("<I", row, 160, 1)
        catalogue = self.root / "U_English.ddb"
        catalogue.write_bytes(database(6, {0: (1, pool), 1: (2, bytes(row) * 2)}))
        loaded = load_translations(catalogue)
        self.assertEqual(
            loaded["translations"], {"IDS_EXTERNAL_TITLE": "Original caption"}
        )
        self.assertIsNone(loaded["locale"])
        resource = self.files["utility"]
        resource.write_bytes(
            resource.read_bytes().replace(
                "Recorded procedure".encode("utf-16le"),
                "IDS_EXTERNAL_TITLE".encode("utf-16le"),
            )
        )
        screens = []

        def dialog(screen):
            screens.append(screen)
            return {"display": {"INT02": 2}} if len(screens) == 1 else "1"

        report = replay_utility(
            self.profile,
            resource,
            self.files["utility_recording"],
            function_id="demo",
            dialog=dialog,
            cancelled=lambda: False,
            translation_file=catalogue,
        )
        self.assertEqual(report["status"], "completed", report)
        self.assertEqual(screens[0]["title"], "Original caption")
        struct.pack_into("<I", row, 160, 2)
        catalogue.write_bytes(database(6, {0: (1, pool), 1: (1, bytes(row))}))
        with self.assertRaisesRegex(ValueError, "outside language table"):
            load_translations(catalogue)

    def test_presentation_expansion_is_bounded_before_join_across_fields(self):
        resource = open_utility(self.files["utility"])
        resolve, _ = procedures._presentation(
            resource, {"locale": "XX", "missing": "error"}
        )
        with patch.object(procedures, "MAX_FILE", 50):
            with self.assertRaisesRegex(ValueError, "presentation budget"):
                resolve({"title": "{LANG001}" * 1000})
            with self.assertRaisesRegex(ValueError, "presentation budget"):
                resolve({"a": "x" * 30, "b": "y" * 30})
        with (
            patch.object(procedures, "MAX_EVENTS", 5),
            self.assertRaisesRegex(ValueError, "presentation entry"),
        ):
            resolve("{LANG001}" * 6)

    def test_native_translation_pool_is_bounded_before_language_allocation(self):
        with patch.object(procedures, "Language") as language:
            data = database(6, {0: (100001, b""), 1: (0, b"")})
            with self.assertRaisesRegex(ValueError, "entry limit"):
                procedures._translations(data)
            data = database(6, {0: (1, bytes(201)), 1: (0, b"")})
            with (
                patch.object(procedures, "MAX_FILE", 200),
                self.assertRaisesRegex(ValueError, "decoded translation budget"),
            ):
                procedures._translations(data)
            language.assert_not_called()

    def test_report_hashes_executed_bytes_when_resource_is_replaced_after_read(self):
        for key in ("utility", "script"):
            path = self.files[key]
            original = path.read_bytes()
            captured = []
            reader = procedures.read_regular

            def read(selected, *, limit, reader=reader, path=path, captured=captured):
                data = reader(selected, limit=limit)
                if Path(selected) == path:
                    captured.append(data)
                    path.write_bytes(b"replacement")
                return data

            try:
                with patch.object(procedures, "read_regular", side_effect=read):
                    report = self.utility() if key == "utility" else self.script()
                self.assertEqual(report["status"], "completed", report)
                self.assertEqual(captured, [original])
                self.assertEqual(
                    report["resource_sha256"], hashlib.sha256(original).hexdigest()
                )
                self.assertEqual(report["input_sources"][0]["bytes"], len(original))
            finally:
                path.write_bytes(original)

    def test_interrupt_during_abort_preserves_primary_and_joins_worker(self):
        original = UtilityBindings.from_profile
        workers = []

        def binding(*args, **kwargs):
            host = original(*args, **kwargs)

            def work():
                host._stop.wait(2)
                host._status = 0

            host._worker = threading.Thread(target=work)
            host._worker.start()
            workers.append(host._worker)
            return host

        driver = ProcedureRecording.driver

        def interrupted(state, operation, arguments):
            if operation == "abort":
                raise KeyboardInterrupt("abort interrupted")
            return driver(state, operation, arguments)

        def dialog(_screen):
            raise ValueError("primary dialog failure")

        with (
            patch.object(UtilityBindings, "from_profile", side_effect=binding),
            patch.object(ProcedureRecording, "driver", interrupted),
        ):
            report = replay_utility(
                self.profile,
                self.files["utility"],
                self.files["utility_recording"],
                function_id="demo",
                dialog=dialog,
                cancelled=lambda: False,
            )
        self.assertFalse(workers[0].is_alive())
        self.assertEqual(
            report["error"], {"type": "ValueError", "message": "primary dialog failure"}
        )
        self.assertEqual(report["cleanup_error"]["type"], "KeyboardInterrupt")

    def test_dialog_keyboard_interrupt_returns_cancelled_report(self):
        def dialog(_screen):
            raise KeyboardInterrupt("cancel")

        report = replay_utility(
            self.profile,
            self.files["utility"],
            self.files["utility_recording"],
            function_id="demo",
            dialog=dialog,
            cancelled=lambda: False,
        )
        self.assertEqual(report["status"], "cancelled")
        self.assertEqual(report["error"]["type"], "KeyboardInterrupt")
        with patch.object(
            procedures, "evaluate", side_effect=KeyboardInterrupt("provider cancel")
        ):
            report = self.script()
        self.assertEqual(report["status"], "cancelled")
        self.assertEqual(report["error"]["type"], "KeyboardInterrupt")

    def test_presentation_deadline_is_checked_before_entering_dialog(self):
        clock = [0.0]
        presentation = procedures._presentation

        def delayed(*args):
            resolve, unresolved = presentation(*args)

            def resolve_late(screen):
                shown = resolve(screen)
                clock[0] += 100
                return shown

            return resolve_late, unresolved

        with (
            patch.object(procedures.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(procedures, "_presentation", side_effect=delayed),
        ):

            def dialog(_screen):
                self.fail("Expired presentation must not enter a dialog")

            report = replay_utility(
                self.profile,
                self.files["utility"],
                self.files["utility_recording"],
                function_id="demo",
                dialog=dialog,
                cancelled=lambda: False,
            )
        self.assertEqual(report["error"]["type"], "TimeoutError")

    def test_input_aggregate_is_checked_during_read_not_file_stat(self):
        size = (
            self.files["utility"].stat().st_size
            + self.files["utility_recording"].stat().st_size
        )
        with (
            patch.object(procedures, "MAX_FILE", size - 1),
            self.assertRaisesRegex(ValueError, "exceeds"),
        ):
            self.utility()
        with (
            patch.object(procedures, "MAX_FILE", 3),
            self.assertRaisesRegex(ValueError, "input limit/type"),
        ):
            ProcedureRecording(
                self.files["script_recording"], lambda: False, raw=b"1234"
            )
        with self.assertRaisesRegex(ValueError, "input limit/type"):
            invalid: Any = "invalid"
            ProcedureRecording(
                self.files["script_recording"], lambda: False, raw=invalid
            )

    def test_worker_base_exception_group_is_reported_and_does_not_mask_primary(self):
        original = UtilityBindings.from_profile

        def binding(*args, **kwargs):
            host = original(*args, **kwargs)
            host._worker = threading.Thread(target=lambda: None)
            host._worker.start()
            host._worker.join()
            host._failure = BaseExceptionGroup(
                "Worker and cleanup failed",
                [KeyboardInterrupt("stop"), ValueError("release failed")],
            )
            return host

        with patch.object(UtilityBindings, "from_profile", side_effect=binding):
            report = self.utility()
        self.assertEqual(report["status"], "failed", report)
        self.assertEqual(report["error"]["type"], "BaseExceptionGroup")
        self.assertEqual(
            [e["type"] for e in report["error"]["exceptions"]],
            ["KeyboardInterrupt", "ValueError"],
        )

        def dialog(_screen):
            raise ValueError("primary failure")

        with patch.object(UtilityBindings, "from_profile", side_effect=binding):
            report = replay_utility(
                self.profile,
                self.files["utility"],
                self.files["utility_recording"],
                function_id="demo",
                dialog=dialog,
                cancelled=lambda: False,
            )
        self.assertEqual(
            report["error"], {"type": "ValueError", "message": "primary failure"}
        )
        self.assertEqual(report["thread_error"]["type"], "BaseExceptionGroup")
        self.assertEqual(len(report["thread_error"]["exceptions"]), 2)


if __name__ == "__main__":
    unittest.main()
