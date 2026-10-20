"""Source-only end-to-end workflows and preservation at the file boundary."""

import contextlib
import io
import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import offline_tools, snapshot, tse_reports


class OfflineToolsTests(unittest.TestCase):
    def test_tse_named_reports_require_explicit_encoding_and_preserve_source(self):
        name = "Сохранённая процедура"
        section = tse_reports.ReportSection(
            "FuncName",
            7,
            0xFFFFFF31,
            0x1000,
            ((0x2716, 7, name.encode("cp1251")),),
        )
        template = snapshot.create_tse_header(
            snapshot.TSEHeader(
                "TSE", 1, 0x102C, 0, 0, 0, 0, b"", b"", (), (0x2725,), b""
            )
        )
        parsed = snapshot.assemble_tse(
            template,
            tuple(
                tse_reports.encode_section(section)
                if entry["tag"].rstrip("\0") == "FuncName"
                else b""
                for entry in template.metadata["index_entries"]
            ),
        )
        raw = snapshot.dumps(parsed)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.tse"
            path.write_bytes(raw)
            self.assertNotIn("report_views", offline_tools.inspect_path(path)["result"])
            result = offline_tools.inspect_path(path, encoding="cp1251")["result"]
            self.assertEqual(result["report_encoding"], "cp1251")
            self.assertEqual(result["report_views"][0]["family"], "FuncName")
            self.assertEqual(result["report_views"][0]["functions"][0]["name"], name)
            for encoding in ("ascii", "not-an-encoding", "utf-16"):
                with self.subTest(encoding=encoding), self.assertRaises(ValueError):
                    offline_tools.inspect_path(path, encoding=encoding)
            self.assertEqual(path.read_bytes(), raw)

    def test_generated_all_dtc_example_contains_a_saved_diagnostic_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            files = offline_tools.create_examples(Path(temporary) / "inputs")
            source = files["all-dtc.xml"]
            before = source.read_bytes()
            result = offline_tools.inspect_path(source)["result"]
            self.assertEqual(result["format"], "all-dtc-xml")
            self.assertEqual(result["ecus"][0]["dtcs"][0]["DTCDispValue"], "P0123")
            self.assertEqual(
                result["ecus"][0]["dtcs"][0]["StatusGridName"],
                "Authored saved status",
            )
            self.assertEqual(source.read_bytes(), before)

    def test_all_dtc_xml_is_identified_by_schema_and_retains_saved_labels(self):
        xml = """<AllDiag><array-ECUInfo><ECUInfo><ECUId>7</ECUId>
<ECUName>Authored ECU</ECUName><array-DTCInfo><DTCInfo>
<DTCDispValue>P0123</DTCDispValue><DTCName>Authored fault</DTCName>
<StatusGridName>Saved status</StatusGridName>
</DTCInfo></array-DTCInfo></ECUInfo></array-ECUInfo></AllDiag>"""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.xml"
            for raw in (xml.encode(), b"\xfe\xff" + xml.encode("utf-16be")):
                path.write_bytes(raw)
                report = offline_tools.inspect_path(path)["result"]
                self.assertEqual(report["format"], "all-dtc-xml")
                self.assertEqual(report["ecus"][0]["ECUId"], "7")
                self.assertEqual(
                    report["ecus"][0]["dtcs"][0]["StatusGridName"], "Saved status"
                )
                self.assertEqual(path.read_bytes(), raw)
            for raw in (b"<unrelated/>", b"<!DOCTYPE AllDiag><AllDiag/>"):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    offline_tools.inspect_path(path)

    def test_workflow_gate_executes_imported_engines_not_only_inspectors(self):
        for target in (
            "scripts.programming_replay.load_programming_files",
            "scripts.recorder_replay.replay_recorder",
            "scripts.service_replay.ServiceReplay.run",
        ):
            with (
                self.subTest(target=target),
                patch(target, side_effect=ValueError("execution sentinel")),
                self.assertRaisesRegex(ValueError, "execution sentinel"),
            ):
                offline_tools.verify_workflows()

    def test_native_outputs_over_recording_input_limit_reopen_and_copy(self):
        raw = snapshot.dumps(
            snapshot.TableFile(
                snapshot.DM_MAGIC,
                1,
                0,
                (snapshot.Table(0xF001, bytes(offline_tools.MAX_SIZE)),),
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            source, target = Path(temporary) / "large.dm", Path(temporary) / "copy.dm"
            source.write_bytes(raw)
            self.assertEqual(offline_tools.inspect_path(source)["size"], len(raw))
            offline_tools.copy_native(source, target)
            self.assertEqual(target.read_bytes(), raw)

    def test_static_metadata_and_hash_use_the_same_read(self):
        from scripts.demo_calibration import create_calibration_examples

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "SyntheticCID.dll"
            original = create_calibration_examples()[path.name]
            path.write_bytes(original)

            def read_then_replace(*args, **kwargs):
                path.write_bytes(b"changed after read")
                return original

            with patch(
                "scripts.offline_tools.read_regular", side_effect=read_then_replace
            ):
                result = offline_tools.inspect_path(path)
            self.assertEqual(result["size"], len(original))
            self.assertEqual(result["result"]["format"], "static-pe-metadata")

    def test_generated_recordings_use_real_schema_inspectors_and_recorder_execution(
        self,
    ):
        from scripts.recorder_replay import replay_recorder

        with tempfile.TemporaryDirectory() as temporary:
            files = offline_tools.create_examples(Path(temporary) / "inputs")
            result = offline_tools.inspect_path(files["recorder-recording.json"])[
                "result"
            ]
            self.assertEqual(result["format"], "native-recorder-recording")
            self.assertGreater(result["events"], 0)
            result = offline_tools.inspect_path(files["authored-programming.json"])[
                "result"
            ]
            self.assertEqual(result["format"], "native-programming-recording")
            self.assertFalse(result["source_identity_validated"])
            for kind in (
                "tis-check",
                "tis-save",
                "euro-online",
                "euro-save",
                "euro-key",
                "rks",
                "notice",
            ):
                result = offline_tools.inspect_path(files[f"service-{kind}.json"])[
                    "result"
                ]
                self.assertEqual(result["format"], "native-service-recording")
                self.assertEqual(result["workflow"], kind)
                self.assertNotIn("key_xml", result)
            report = replay_recorder(
                files["recorder-settings.drs"], files["recorder-recording.json"]
            )
            self.assertEqual(report["status"], "completed")

    def test_inspect_selects_each_buffer_and_rejects_missing_indices(self):
        parsed = snapshot.parse(offline_tools.example_snapshot())
        self.assertIsInstance(parsed, snapshot.TableFile)
        assert isinstance(parsed, snapshot.TableFile)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "multiple.dm"
            raw = snapshot.dumps(
                snapshot.TableFile(
                    parsed.magic, parsed.version, parsed.revision, parsed.tables * 2
                )
            )
            path.write_bytes(raw)
            for index in (0, 1):
                report = offline_tools.inspect_path(path, buffer_index=index)["result"]
                self.assertEqual(
                    [item["index"] for item in report["available_buffers"]], [0, 1]
                )
                self.assertEqual(report["playback_index"], index)
                self.assertEqual(report["playback"]["buffer_index"], index)
                self.assertTrue(report["playback"]["samples"])
            for index in (-1, True, 2, "1"):
                with self.subTest(index=index), self.assertRaises(ValueError):
                    offline_tools.inspect_path(path, buffer_index=index)  # pyright: ignore[reportArgumentType]
            self.assertEqual(path.read_bytes(), raw)

    def test_tse_native_capture_selection_and_report_only_header(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "capture.tse"
            raw = offline_tools.example_tse()
            path.write_bytes(raw)
            for index in (0, 1):
                result = offline_tools.inspect_path(path, buffer_index=index)["result"]
                self.assertEqual(len(result["available_buffers"]), 2)
                self.assertEqual(
                    result["available_buffers"][index]["family"], "DataList"
                )
                self.assertEqual(result["playback_index"], index)
                self.assertEqual(result["playback"]["record_index"], index)
                self.assertEqual(
                    [
                        row["values"][0]["value"]
                        for row in result["playback"]["samples"]
                    ],
                    [6, 14],
                )
            with self.assertRaises(ValueError):
                offline_tools.inspect_path(path, buffer_index=2)
            self.assertEqual(path.read_bytes(), raw)
            header = snapshot.create_tse_header(
                snapshot.TSEHeader("TSE", 1, 0x102C, 0, 0, 0, 0, b"", b"", (), (), b"")
            )
            path.write_bytes(snapshot.dumps(header))
            result = offline_tools.inspect_path(path)["result"]
            self.assertEqual(result["available_buffers"], [])
            self.assertIsNone(result["playback_index"])
            self.assertNotIn("playback", result)

    def test_every_scenario_executes_and_exports_a_serializable_report(self):
        for key in offline_tools.WORKFLOWS:
            with self.subTest(workflow=key):
                report = offline_tools.run_example(key)
                self.assertEqual(report["workflow"], key)
                self.assertEqual(report["source"], "authored_synthetic")
                self.assertEqual(report["physical_status"], "PHYSICAL_UNCONFIRMED")
                self.assertEqual(json.loads(json.dumps(report)), report)
                self.assertTrue(report["result"])

    def test_cancel_before_execution_and_after_a_native_exchange(self):
        for key in offline_tools.WORKFLOWS:
            with self.subTest(workflow=key), self.assertRaises(InterruptedError):
                offline_tools.run_example(key, lambda: True)
        calls = []

        def stop():
            calls.append(None)
            return len(calls) == 3

        with self.assertRaises(InterruptedError):
            offline_tools.run_example("toyota", stop)
        with self.assertRaises(ValueError):
            offline_tools.run_example("unknown")

    def test_created_native_examples_inspect_without_original_resources(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "inputs"
            files = offline_tools.create_examples(directory)
            for name, path in files.items():
                with self.subTest(name=name):
                    before = path.read_bytes()
                    report = offline_tools.inspect_path(path)
                    self.assertEqual(path.read_bytes(), before)
                    self.assertEqual(report["size"], len(before))
                    self.assertEqual(report["source"], "local_file_unverified")
                    self.assertTrue(report["result"]["format"])
            playback = offline_tools.inspect_path(files["capture.dm"])["result"][
                "playback"
            ]
            self.assertEqual(
                [row["timestamp_raw"] for row in playback["samples"]], [100, 120]
            )
            self.assertEqual(
                [row["values"][0]["value"] for row in playback["samples"]], [6, 14]
            )
            with self.assertRaises(FileExistsError):
                offline_tools.create_examples(directory)
            self.assertEqual(
                files["capture.dm"].read_bytes(), offline_tools.example_snapshot()
            )

    def test_native_copy_preserves_unknown_duplicate_tables_and_all_source_aliases(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "source.dm"
            raw = snapshot.dumps(
                snapshot.TableFile(
                    snapshot.DM_MAGIC,
                    7,
                    8,
                    (snapshot.Table(0xF001, b"\0\xff"), snapshot.Table(0xF001, b"")),
                )
            )
            source.write_bytes(raw)
            destination = directory / "copy.dm"
            offline_tools.copy_native(source, destination)
            self.assertEqual(destination.read_bytes(), raw)
            symbolic, hard = directory / "symlink.dm", directory / "hardlink.dm"
            symbolic.symlink_to(source)
            os.link(source, hard)
            for alias in (source, symbolic, hard):
                with self.subTest(alias=alias), self.assertRaises(ValueError):
                    offline_tools.copy_native(source, alias)
                self.assertEqual(source.read_bytes(), raw)

    def test_failed_copy_keeps_source_and_existing_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source, destination = directory / "source.dm", directory / "copy.dm"
            source.write_bytes(offline_tools.example_snapshot())
            destination.write_bytes(b"keep previous export")
            with (
                patch(
                    "scripts.offline_tools.os.replace",
                    side_effect=OSError("disk failure"),
                ),
                self.assertRaises(OSError),
            ):
                offline_tools.copy_native(source, destination)
            self.assertEqual(source.read_bytes(), offline_tools.example_snapshot())
            self.assertEqual(destination.read_bytes(), b"keep previous export")
            self.assertEqual(set(directory.iterdir()), {source, destination})
            source.write_bytes(b"corrupt")
            with self.assertRaises(ValueError):
                offline_tools.copy_native(source, destination)
            self.assertEqual(destination.read_bytes(), b"keep previous export")

    def test_cli_inspect_and_report_source_protection(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source, output = directory / "capture.dm", directory / "report.json"
            raw = offline_tools.example_snapshot()
            source.write_bytes(raw)
            with patch.object(
                sys,
                "argv",
                ["offline_tools", "inspect", str(source), "--output", str(output)],
            ):
                self.assertEqual(offline_tools.main(), 0)
            self.assertEqual(json.loads(output.read_text())["size"], len(raw))
            with (
                patch.object(
                    sys,
                    "argv",
                    ["offline_tools", "inspect", str(source), "--output", str(source)],
                ),
                contextlib.redirect_stderr(io.StringIO()) as stderr,
            ):
                self.assertEqual(offline_tools.main(), 1)
            self.assertIn("must differ", stderr.getvalue())
            self.assertEqual(source.read_bytes(), raw)

    def test_inspection_rejects_corrupt_oversize_and_unknown_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "invalid.dm"
            for raw in (
                b"",
                b"MZexecutable",
                struct.pack("<I", snapshot.DM_MAGIC),
                b"x" * (offline_tools.MAX_SIZE + 1),
            ):
                path.write_bytes(raw)
                with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                    offline_tools.inspect_path(path)
            path = Path(temporary) / "invalid.xml"
            path.write_bytes(b"<UTILITY/>")
            with self.assertRaises(ValueError):
                offline_tools.inspect_path(path)


if __name__ == "__main__":
    unittest.main()
