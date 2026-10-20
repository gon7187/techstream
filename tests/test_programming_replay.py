import hashlib
import io
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.programming_replay import (
    ProgrammingTrace,
    create_programming_examples,
    inspect_recording,
    load_programming_files,
    load_programming_recording_stream,
    load_programming_replay,
)


class ProgrammingReplayTests(unittest.TestCase):
    def setUp(self):
        self.files = create_programming_examples()
        self.document = json.loads(self.files["authored-programming.json"])
        self.first_exchange = next(
            i
            for i, row in enumerate(self.document["events"])
            if row["kind"] == "exchange"
        )

    def test_same_json_stream_is_validated_before_execution_and_spooled(self):
        class SmallReads(io.BytesIO):
            def read(self, size=-1):
                return super().read(min(size, 7))

        raw = self.files["authored-programming.json"]
        source = SmallReads(raw)
        session = load_programming_recording_stream(
            self.files["authored.cuw"],
            source,
            {"DEMOP5DEMO.ini": self.files["DEMOP5DEMO.ini"]},
            {"SyntheticProgramming.dll": self.files["SyntheticProgramming.dll"]},
        )
        rows = session.trace.rows
        try:
            self.assertNotIsInstance(rows, tuple)
            self.assertEqual(session.trace.position, 0)
            self.assertEqual(
                session.input_hashes["context"], hashlib.sha256(raw).hexdigest()
            )
            self.assertEqual(session.run()["state"], "writer_completed")
            self.assertFalse(source.closed)
        finally:
            session.trace.close()
        for broken in (
            raw + b"{}",
            raw[:-1],
            raw.replace(b'"events":', b'"events":[],"events":'),
        ):
            with self.assertRaises(ValueError):
                load_programming_recording_stream(
                    self.files["authored.cuw"],
                    SmallReads(broken),
                    {"DEMOP5DEMO.ini": self.files["DEMOP5DEMO.ini"]},
                    {
                        "SyntheticProgramming.dll": self.files[
                            "SyntheticProgramming.dll"
                        ]
                    },
                )

    def load(
        self,
        document=None,
        *,
        cuw=None,
        module=None,
        cancelled=lambda: False,
        attachments=None,
    ):
        return load_programming_replay(
            cuw or self.files["authored.cuw"],
            json.dumps(self.document if document is None else document).encode(),
            {"DEMOP5DEMO.ini": self.files["DEMOP5DEMO.ini"]},
            {
                "SyntheticProgramming.dll": self.files["SyntheticProgramming.dll"]
                if module is None
                else module
            },
            attachments=attachments,
            cancelled=cancelled,
        )

    def test_fresh_clone_actual_import_metadata_writer_and_identity(self):
        from scripts.calibration_catalog import inspect_module_bytes

        module = self.files["SyntheticProgramming.dll"]
        inspected = inspect_module_bytes(module, "SyntheticProgramming.dll")
        self.assertEqual(inspected["version"], "1.0.0007.0")
        self.assertEqual(inspected["exports"], ["StartFlashWrite"])
        self.assertEqual(struct.unpack_from("<I", module, 0xA8)[0], 0)
        self.assertEqual(struct.unpack_from("<I", module, 0x19C)[0] & 0x20000000, 0)
        session = self.load()
        result = session.run()
        self.assertEqual(result["state"], "writer_completed")
        self.assertEqual(result["source_identity"]["kind"], "authored_fixture")
        self.assertEqual(result["events_remaining"], 0)
        self.assertFalse(result["programming_completed"])
        self.assertEqual(
            result["input_hashes"]["calibration"],
            hashlib.sha256(self.files["authored.cuw"]).hexdigest(),
        )
        with self.assertRaises(ValueError):
            session.run()

    def test_request_digest_compares_actual_bytes_without_replacing_payload(self):
        payload = b"authored actual calibration bytes"
        descriptor = {
            "type": "bytes_sha256",
            "length": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        row = {
            "kind": "action",
            "request": {"operation": "write_messages", "data": descriptor},
            "result": {"type": "int", "value": 1},
            "elapsed_ms": 0,
        }
        trace = ProgrammingTrace.validate([row])
        self.assertEqual(
            trace.action({"operation": "write_messages", "data": payload}, 1), 1
        )
        for wrong in (payload + b"x", bytes(len(payload)), descriptor):
            trace = ProgrammingTrace.validate([row])
            with self.assertRaises(ValueError):
                trace.action({"operation": "write_messages", "data": wrong}, 1)
            self.assertEqual(trace.position, 0)
        broken = json.loads(json.dumps(row))
        broken["request"]["data"]["sha256"] = "unknown"
        with self.assertRaises(ValueError):
            ProgrammingTrace.validate([broken])

    def test_native_progress_float_requests_are_finite_and_chronological(self):
        row = {
            "kind": "action",
            "request": {"operation": "progress", "percent": 12.5},
            "result": {"type": "none", "value": None},
            "elapsed_ms": 0,
        }
        trace = ProgrammingTrace.validate([row])
        self.assertIsNone(trace.action({"operation": "progress", "percent": 12.5}, 1))
        trace.assert_complete()
        for invalid in (float("nan"), float("inf"), 1e13):
            row["request"]["percent"] = invalid
            with self.assertRaises(ValueError):
                ProgrammingTrace.validate([row])

    def test_explicit_native2026_error_domains_and_cleanup_metadata(self):
        from scripts.programming_2026_common import (
            NativeJ2534Exception2026,
            NativePassThruException2026,
        )
        from scripts.programming_replay import _report

        for domain, code, detail in (("cpass2026", 73, None), ("j2534_2026", 1, 99)):
            fault = {"domain": domain, "code": code}
            if detail is not None:
                fault["detail"] = detail
            trace = ProgrammingTrace.validate(
                [
                    {
                        "kind": "action",
                        "request": {"operation": "get_timeout"},
                        "result": {"type": "error", "value": fault},
                        "elapsed_ms": 0,
                    }
                ]
            )
            expected = (
                NativePassThruException2026
                if detail is None
                else NativeJ2534Exception2026
            )
            with self.assertRaises(expected) as caught:
                trace.action({"operation": "get_timeout"}, 1)
            self.assertEqual(caught.exception.error, code)
            if detail is not None:
                assert isinstance(caught.exception, NativeJ2534Exception2026)
                self.assertEqual(caught.exception.j2534_error, detail)
        result = _report(
            {
                "native_error_code": 3,
                "native_error_domain": "CPassThruException",
                "cleanup_error_details": [
                    {
                        "phase": "stop_filter",
                        "native_error_domain": "CJ2534Exception",
                        "native_error_code": 99,
                        "error_chain": ["private key material"],
                    }
                ],
            }
        )
        details = result["cleanup_error_details"]
        assert isinstance(details, list)
        self.assertEqual(details[0]["native_error_code"], 99)
        self.assertNotIn("private key material", json.dumps(result))
        auxiliary = _report(
            {
                "native_results": [
                    {
                        "assembly": "AUTHORED12345",
                        "assembly_valid": False,
                        "assembly_error": {
                            "native_error_code": 92,
                            "error_chain": ["private"],
                        },
                        "history": ["private"],
                    }
                ]
            }
        )
        self.assertIn('"native_error_code": 92', json.dumps(auxiliary))
        self.assertNotIn("private", json.dumps(auxiliary))
        ansi = _report(
            {"identifiers": (b"\xff ", b"ASCII", b"ASCII"), "native_success": True}
        )
        self.assertEqual(ansi["identifiers"], ["ASCII", "ASCII"])
        self.assertEqual(
            ansi["identifier_bytes_hex"], ["ff20", "4153434949", "4153434949"]
        )
        records = ansi["identifier_records"]
        assert isinstance(records, list)
        self.assertEqual(records[0], {"bytes_hex": "ff20", "ascii": None})

    def test_native_error_reports_and_engine_binding_are_bounded(self):
        from scripts.programming_replay import _report

        self.assertEqual(
            _report(
                {
                    "native_error_code": 73,
                    "error_type": "NativeIDError",
                    "response": b"secret",
                }
            ),
            {"native_error_code": 73, "error_type": "NativeIDError"},
        )
        self.assertEqual(
            _report({"native_error": -(1 << 31) - 1, "error_type": "secret material"}),
            {},
        )
        session = self.load()
        with self.assertRaises(TypeError):
            session.bind_engine2026(object())
        self.assertEqual(session.trace.position, 0)
        self.assertFalse(session.used)

    def test_all_dh_writer_modules_reach_the_strict_native_binder(self):
        from scripts.programming_replay import BoundModule

        class BinderReached(Exception):
            pass

        for name in (
            "TCUWCanDHFlashWriter.dll",
            "TCUWCanDHGatewayFlashWriter.dll",
            "TCUWCanDH19PFSURegGatewayFlashWriter.dll",
            "TCUWCanDHMultiROMFlashWriter.dll",
        ):
            with self.subTest(module=name):
                session = self.load()
                module = BoundModule(name, "0" * 64, 2026, name[:-4], ())
                with (
                    patch(
                        "scripts.programming_2026_dh.bind_native_context",
                        side_effect=BinderReached,
                    ) as binder,
                    self.assertRaises(BinderReached),
                ):
                    session._runner2026(SimpleNamespace(operation="write"), module, ())
                binder.assert_called_once()
                self.assertEqual(session.trace.position, 0)

    def test_sil_controller_state_cannot_be_supplied_by_json(self):
        from scripts.programming_replay import BoundModule

        for key, value in (
            ("use_new_password", False),
            ("reset_requested", False),
            ("prepare_status", 0),
            ("received_cid_count", 0),
        ):
            with self.subTest(key=key):
                session = self.load()
                session.context["observations"]["host"]["native2026"] = {key: value}
                module = BoundModule(
                    "TCUWSilFlashWriter.dll", "0" * 64, 2026, "TCUWSilFlashWriter", ()
                )
                with self.assertRaisesRegex(ValueError, "SIL state must originate"):
                    session._runner2026(SimpleNamespace(operation="write"), module, ())
                self.assertEqual(session.trace.position, 0)

    def test_alternate_getter_requires_actual_native_cid_selection(self):
        session = self.load()
        with self.assertRaisesRegex(ValueError, "actual CID phase"):
            session.next_alternate_getter2026()
        with self.assertRaisesRegex(ValueError, "engine and controller required"):
            session.selected_binding2026()
        self.assertEqual(session.trace.position, 0)

    def test_ethernet_writer_requires_retained_engine_rks_identity(self):
        from scripts.programming_replay import BoundModule

        module = BoundModule(
            "TCUWEthernetReprostdFlashWriter.dll",
            "0" * 64,
            2026,
            "TCUWEthernetReprostdFlashWriter",
            (),
        )
        session = self.load()
        with self.assertRaisesRegex(ValueError, "Actual loaded RKS engine state"):
            session._runner2026(SimpleNamespace(operation="write"), module, ())
        session.context["observations"]["host"]["native2026"] = {
            "rks_software_identity": {"software_id": "CAPTURED"}
        }
        with self.assertRaisesRegex(ValueError, "must originate from engine"):
            session._runner2026(SimpleNamespace(operation="write"), module, ())
        self.assertEqual(session.trace.position, 0)

    def test_gateway_phase_cannot_reuse_an_ordinary_preparation_or_probe(self):
        from scripts.programming_replay import BoundModule

        document = json.loads(json.dumps(self.document))
        document["operation"] = "change_gateway"
        session = self.load(document)
        self.assertEqual(
            inspect_recording(json.dumps(document).encode())["operation"],
            "change_gateway",
        )
        for build, exports in (
            (18, ("ChangeToReprogGatewayMode",)),
            (2026, ("StartPrepareWrite", "IsFinishReprogramming")),
        ):
            with self.subTest(build=build):
                module = BoundModule(
                    "Candidate.dll", "0" * 64, build, "Candidate", exports
                )
                with self.assertRaisesRegex(ValueError, "actual gateway-mode export"):
                    session._runner(None, module, (), {}, {}, {})
        self.assertEqual(session.trace.position, 0)

    def test_ordinary_legacy_prepare_cannot_select_gateway_through_host_flag(self):
        session = self.load()
        session.context["operation"] = "prepare"
        session.context["observations"]["host"]["legacy"] = {"stage": "gateway"}
        with self.assertRaisesRegex(ValueError, "distinct gateway operation"):
            session._legacy_runner(None, SimpleNamespace(), 30)
        self.assertEqual(session.trace.position, 0)

    def test_raw_catalog_presence_does_not_parse_native_profile(self):
        session = self.load()
        session._catalog_sources = {"8P4A.ini": b"malformed native profile"}
        self.assertTrue(session.has_catalog_source2026("8P4A.ini"))
        self.assertFalse(session.has_catalog_source2026("missing.ini"))
        for name in ("../8P4A.ini", "", "x" * 261):
            with self.assertRaises(ValueError):
                session.has_catalog_source2026(name)
        self.assertEqual(session.trace.position, 0)

    def test_native_gateway_cached_byte_preserves_full_unsigned_domain(self):
        from scripts.programming_replay import _report

        for value in (0, 1, 2, 3, 255):
            self.assertEqual(_report({"gateway_kind": value})["gateway_kind"], value)
        for value in (-1, 256, True, "3"):
            self.assertNotIn("gateway_kind", _report({"gateway_kind": value}))

    def test_nested_online_clock_requires_bounded_captured_elapsed(self):
        trace = ProgrammingTrace(())
        trace.absorb_online_elapsed(0.125)
        self.assertEqual(trace.clock(), 0.125)
        for value in (True, -1, 601, float("nan"), float("inf"), "0.1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                trace.absorb_online_elapsed(value)  # pyright: ignore[reportArgumentType]
            self.assertEqual(trace.clock(), 0.125)
        self.assertEqual(trace.position, 0)

    def test_online_attachment_descriptor_cannot_supply_a_successful_key(self):
        from scripts.programming_2026_common import NativeRuntime2026

        session = self.load()
        runtime = NativeRuntime2026(session.trace.action)
        for descriptor in (
            {"key": "SUCCESS"},
            {"configuration": "missing", "recording": "missing"},
        ):
            with self.subTest(descriptor=descriptor), self.assertRaises(ValueError):
                session._bind_online2026(runtime, {"online2026": descriptor})
        self.assertEqual(session.trace.position, 0)

    def test_recording_inspection_is_structural_and_omits_observations(self):
        raw = self.files["authored-programming.json"]
        report = inspect_recording(raw)
        self.assertEqual(report["operation"], "write")
        self.assertEqual(report["events"], 37)
        self.assertFalse(report["source_identity_validated"])
        self.assertNotIn("AUTHORED-OLD", json.dumps(report))
        for invalid in (b"{}", b"[]", b'{"schema":1,"schema":2}'):
            with (
                self.subTest(invalid=invalid),
                self.assertRaises((TypeError, ValueError)),
            ):
                inspect_recording(invalid)
        changed = json.loads(raw)
        changed["events"][0]["result"] = {"type": "bool", "value": 1}
        with self.assertRaises(ValueError):
            inspect_recording(json.dumps(changed).encode())

    def test_nested_native_results_and_recovery_error_detail(self):
        from scripts.programming import NativeRecoveryTransportError

        for operation, maximum in (
            ("get_local_seconds_of_day", 86399),
            ("get_local_milliseconds_of_day", 86399999),
        ):
            row = {
                "kind": "action",
                "request": {"operation": operation},
                "result": {"type": "int", "value": maximum + 1},
                "elapsed_ms": 0,
            }
            with self.assertRaises(ValueError):
                ProgrammingTrace.validate([row])
            row["result"]["value"] = maximum
            trace = ProgrammingTrace.validate([row])
            callback = (
                trace.native_local_seconds_of_day
                if operation == "get_local_seconds_of_day"
                else trace.native_local_milliseconds_of_day
            )
            self.assertEqual(callback(), maximum)

        for tag, expected in (("tuple", (1, 2)), ("sequence", [1, 2])):
            trace = ProgrammingTrace.validate(
                [
                    {
                        "kind": "action",
                        "request": {"operation": "observed_native_values"},
                        "result": {
                            "type": tag,
                            "value": [
                                {"type": "int", "value": 1},
                                {"type": "int", "value": 2},
                            ],
                        },
                        "elapsed_ms": 0,
                    }
                ]
            )
            self.assertEqual(
                trace.action({"operation": "observed_native_values"}, 1), expected
            )

        result = {
            "type": "mapping",
            "value": {
                "data": {"type": "bytes", "value": "55aa"},
                "rx_status": {"type": "int", "value": 0},
            },
        }
        request = {"operation": "FAST_INIT"}
        trace = ProgrammingTrace.validate(
            [
                {
                    "kind": "action",
                    "request": request,
                    "result": result,
                    "elapsed_ms": 0,
                },
                {
                    "kind": "action",
                    "request": {"operation": "reconnect"},
                    "result": {
                        "type": "error",
                        "value": {
                            "domain": "native",
                            "code": 9,
                            "detail": 16,
                        },
                    },
                    "elapsed_ms": 0,
                },
            ]
        )
        self.assertEqual(
            trace.action(request, 1), {"data": b"\x55\xaa", "rx_status": 0}
        )
        with self.assertRaises(NativeRecoveryTransportError) as caught:
            trace.action({"operation": "reconnect"}, 1)
        self.assertEqual((caught.exception.code, caught.exception.detail), (9, 16))
        result["value"]["rx_status"]["value"] = True
        with self.assertRaises(ValueError):
            ProgrammingTrace.validate(
                [
                    {
                        "kind": "action",
                        "request": request,
                        "result": result,
                        "elapsed_ms": 0,
                    }
                ]
            )

    def test_unknown_and_spoofed_module_or_source_rejected_before_events(self):
        for raw in (b"MZ" + bytes(200), self.files["SyntheticProgramming.dll"] + b"x"):
            with self.subTest(module=len(raw)), self.assertRaises(ValueError):
                self.load(module=raw)
        self.document["source"] = "recorded_unverified"
        with self.assertRaises(ValueError):
            self.load()
        self.document["source"] = "authored_synthetic"
        self.document["calibration_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.load()

    def test_chronology_pending_receive_and_trailing_records(self):
        changed = json.loads(json.dumps(self.document))
        changed["events"][self.first_exchange]["request"]["payload_hex"] = "22f181"
        result = self.load(changed).run()
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(result["events_consumed"], self.first_exchange)
        changed = json.loads(json.dumps(self.document))
        changed["events"].append(changed["events"][-1])
        result = self.load(changed).run()
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(result["events_remaining"], 1)
        changed = json.loads(json.dumps(self.document))
        original = changed["events"][self.first_exchange]["result"]["value"]
        changed["events"][self.first_exchange]["result"]["value"] = "7f2e78"
        changed["events"].insert(
            self.first_exchange + 1,
            {
                "kind": "action",
                "request": {"operation": "set_timeout", "milliseconds": 1000},
                "result": {"type": "none", "value": None},
                "elapsed_ms": 0,
            },
        )
        changed["events"].insert(
            self.first_exchange + 2,
            {
                "kind": "receive",
                "request": {"ecu": "0700", "payload_hex": ""},
                "result": {"type": "bytes", "value": original},
                "elapsed_ms": 0,
            },
        )
        self.assertEqual(self.load(changed).run()["state"], "writer_completed")

    def test_each_captured_io_fault_remains_uncertain_and_never_resumes(self):
        for index in range(len(self.document["events"])):
            changed = json.loads(json.dumps(self.document))
            changed["events"][index]["result"] = {
                "type": "error",
                "value": {"domain": "host", "code": 1},
            }
            session = self.load(changed)
            with self.subTest(event=index):
                result = session.run()
                self.assertEqual(result["state"], "recovery_required")
                self.assertFalse(result["automatic_retry"])
                self.assertFalse(result["resume_authorized"])
                with self.assertRaises(ValueError):
                    session.run()

    def test_cancellation_and_callback_elapsed_deadline(self):
        session = self.load(cancelled=lambda: True)
        self.assertEqual(session.run()["events_consumed"], 0)
        changed = json.loads(json.dumps(self.document))
        changed["events"][0]["elapsed_ms"] = 31000
        result = self.load(changed).run()
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(result["events_consumed"], 1)

    def test_every_callback_cancellation_and_deadline_including_final_cleanup(self):
        for index in range(len(self.document["events"])):
            holder = {}
            session = self.load(
                cancelled=lambda index=index, holder=holder: bool(
                    holder and holder["session"].trace.position >= index + 1
                )
            )
            holder["session"] = session
            with self.subTest(event=index, fault="cancel"):
                self.assertEqual(session.run()["state"], "recovery_required")
            changed = json.loads(json.dumps(self.document))
            changed["events"][index]["elapsed_ms"] += 31000
            with self.subTest(event=index, fault="deadline"):
                self.assertEqual(self.load(changed).run()["state"], "recovery_required")

    def test_schema_types_unknown_fields_duplicate_keys_and_path_aliases(self):
        malformed = json.loads(json.dumps(self.document))
        malformed["events"][self.first_exchange]["result"] = {
            "type": "none",
            "value": None,
        }
        with self.assertRaises(ValueError):
            self.load(malformed)
        malformed = json.loads(json.dumps(self.document))
        malformed["events"][self.first_exchange]["request"]["payload_hex"] = ""
        with self.assertRaises(ValueError):
            self.load(malformed)
        malformed = json.loads(json.dumps(self.document))
        malformed["input_path"] = "/etc/passwd"
        with self.assertRaises(ValueError):
            self.load(malformed)
        with self.assertRaises(ValueError):
            self.load(attachments={"../key": b"secret"})
        with self.assertRaises(ValueError):
            load_programming_replay(
                self.files["authored.cuw"], b'{"schema":1,"schema":2}', {}, {}
            )
        with self.assertRaises(ValueError):
            ProgrammingTrace.validate(
                [
                    {
                        "kind": "receive",
                        "request": {"ecu": "x", "payload_hex": "22"},
                        "result": {"type": "bytes", "value": "62"},
                        "elapsed_ms": 0,
                    }
                ]
            )

    def test_secrets_hidden_and_atomic_export_preserves_every_selected_source(self):
        secret = b"SECRET-AUTHORIZATION-MATERIAL"
        session = self.load(attachments={"authorized.bin": secret})
        report = session.run()
        self.assertNotIn(secret.decode(), repr(session))
        self.assertNotIn(secret.decode(), json.dumps(report))
        self.assertNotIn("history", json.dumps(report))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = []
            for name, data in {**self.files, "authorized.bin": secret}.items():
                path = root / name
                path.write_bytes(data)
                inputs.append(path)
            for source in inputs:
                before = source.read_bytes()
                with self.assertRaises(ValueError):
                    session.export_result(source, input_paths=inputs)
                self.assertEqual(source.read_bytes(), before)
            hard = root / "hard.json"
            os.link(inputs[-1], hard)
            with self.assertRaises(ValueError):
                session.export_result(hard, input_paths=inputs)
            link = root / "link.json"
            link.symlink_to(inputs[0])
            with self.assertRaises(ValueError):
                session.export_result(link, input_paths=inputs)
            output = root / "result.json"
            session.export_result(output, input_paths=inputs)
            self.assertEqual(
                json.loads(output.read_bytes())["state"], "writer_completed"
            )
            self.assertFalse(tuple(root.glob(".programming-*")))
            imported, all_paths = load_programming_files(
                root / "authored.cuw",
                root / "authored-programming.json",
                {"DEMOP5DEMO.ini": root / "DEMOP5DEMO.ini"},
                {"SyntheticProgramming.dll": root / "SyntheticProgramming.dll"},
                attachment_paths={"authorized.bin": root / "authorized.bin"},
            )
            self.assertEqual(len(all_paths), 5)
            self.assertEqual(imported.run()["state"], "writer_completed")


class RecordedDeviceTests(unittest.TestCase):
    @staticmethod
    def tagged(value):
        if value is None:
            return {"type": "none", "value": None}
        if type(value) is int:
            return {"type": "int", "value": value}
        if isinstance(value, bytes):
            return {"type": "bytes", "value": value.hex()}
        if isinstance(value, str):
            return {"type": "text", "value": value}
        if isinstance(value, tuple):
            return {
                "type": "tuple",
                "value": [RecordedDeviceTests.tagged(v) for v in value],
            }
        return {
            "type": "mapping",
            "value": {k: RecordedDeviceTests.tagged(v) for k, v in value.items()},
        }

    @classmethod
    def row(cls, request, status=0, value=None):
        return {
            "kind": "action",
            "request": request,
            "result": cls.tagged({"status": status, "value": value}),
            "elapsed_ms": 1,
        }

    def test_retained_device_state_and_cleanup_after_host_cancel(self):
        from scripts.programming_2026_common import NativeRuntime2026

        stopped = [False]
        trace = ProgrammingTrace.validate(
            [
                self.row(
                    {"operation": "passthru_open", "name": None, "version": 0}, value=41
                ),
                self.row({"operation": "passthru_close", "device": 41}),
            ],
            cancelled=lambda: stopped[0],
        )
        device = trace.bind_recorded_device2026(timeout=30, max_calls=20)
        runtime = NativeRuntime2026(
            trace.action, clock=trace.clock, cancelled=trace.cancelled, max_calls=20
        )
        runtime.bind_recorded_device2026(trace, device)
        self.assertIs(runtime.recorded_device2026(), device)
        device.open()
        self.assertTrue(device.opened)
        stopped[0] = True
        trace.cleanup_primitive({"operation": "disconnect"}, 5)
        self.assertFalse(device.opened)
        self.assertEqual(trace.position, 2)
        with self.assertRaises(ValueError):
            trace.bind_recorded_device2026(timeout=30, max_calls=21)

    def test_distinct_native_views_share_exact_provider_and_release_once(self):
        from scripts.programming_replay import native_device_action2026

        trace = ProgrammingTrace.validate(
            [
                self.row(
                    {"operation": "passthru_open", "name": None, "version": 0}, value=41
                ),
                self.row({"operation": "passthru_close", "device": 41}),
            ]
        )
        control = trace.bind_recorded_device2026(timeout=30, max_calls=20)
        pair = trace.interface_pair
        self.assertIsNotNone(pair)
        assert pair is not None
        self.assertIs(control, pair.control)
        self.assertIs(trace.engine_device, pair.engine)
        self.assertIs(pair.engine.provider, control.provider)
        self.assertIs(pair.engine.clock, control.clock)
        self.assertIs(pair.engine.cancelled, control.cancelled)
        from scripts.j2534_2026 import DriverMetadata2026

        pair.engine.set_driver(DriverMetadata2026("authored", "offline.dll"))
        control.set_driver(DriverMetadata2026("authored", "offline.dll"))
        pair.engine.open()
        self.assertTrue(pair.engine.opened)
        self.assertFalse(control.opened)
        pair.import_into(control, pair.export_from(pair.engine))
        self.assertTrue(control.opened)
        native_device_action2026(control, {"operation": "disconnect"}, 5, cleanup=True)
        pair.engine.close()
        self.assertFalse(control.opened)
        self.assertFalse(pair.engine.opened)
        self.assertEqual(trace.position, 2)

    def test_driver_failure_preserves_unopened_device(self):
        from scripts.j2534_2026 import NativeJ2534Error2026

        trace = ProgrammingTrace.validate(
            [
                self.row(
                    {"operation": "passthru_open", "name": None, "version": 0}, status=7
                )
            ]
        )
        device = trace.bind_recorded_device2026(timeout=30, max_calls=20)
        with self.assertRaises(NativeJ2534Error2026):
            device.open()
        self.assertFalse(device.opened)
        self.assertEqual(trace.position, 1)

    def test_message_bytes_digest_and_explicit_typed_read_batch(self):
        from scripts.j2534_2026 import NativeMessage, NativeReadBatch2026

        message = {
            "_native_type": "PASSTHRU_MSG_2026",
            "protocol_id": 6,
            "data": b"\x00\x00\x01\x08\x62",
            "rx_status": 0,
            "tx_flags": 0,
            "timestamp": 13,
            "extra_data_index": 0,
        }
        request = {
            "operation": "passthru_write_msgs",
            "message": {
                **message,
                "data": {
                    "type": "bytes_sha256",
                    "length": 5,
                    "sha256": hashlib.sha256(message["data"]).hexdigest(),
                },
            },
        }
        trace = ProgrammingTrace.validate(
            [
                self.row(
                    request,
                    value={
                        "_native_type": "READ_BATCH_2026",
                        "messages": (message,),
                        "count": 1,
                    },
                )
            ]
        )
        result = trace.driver_primitive(
            {
                "operation": "passthru_write_msgs",
                "message": NativeMessage(6, message["data"], timestamp=13),
            },
            30,
        )
        self.assertIsInstance(result.value, NativeReadBatch2026)
        self.assertEqual(result.value.messages[0].data, message["data"])
        changed = ProgrammingTrace.validate([self.row(request)])
        with self.assertRaises(ValueError):
            changed.driver_primitive(
                {
                    "operation": "passthru_write_msgs",
                    "message": NativeMessage(6, b"wrong", timestamp=13),
                },
                30,
            )
        self.assertEqual(changed.position, 0)

    def test_no_default_driver_success_and_no_unknown_native_objects(self):
        for value in (
            None,
            {"value": 3},
            {"status": 0, "value": {"_native_type": "arbitrary"}},
        ):
            trace = ProgrammingTrace.validate(
                [
                    {
                        "kind": "action",
                        "request": {"operation": "passthru_open"},
                        "result": self.tagged(value),
                        "elapsed_ms": 0,
                    }
                ]
            )
            with self.subTest(value=value), self.assertRaises(ValueError):
                trace.driver_primitive({"operation": "passthru_open"}, 30)


if __name__ == "__main__":
    unittest.main()
