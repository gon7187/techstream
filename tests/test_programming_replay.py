import hashlib
import io
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
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

    def test_vbf_resume_root_is_fresh_and_uses_prepared_source_view(self):
        from scripts.programming_replay import ProgrammingReplay

        session = self.load()
        session.used = True
        runtime, controller, engine, job = (object() for _ in range(4))
        session._runtime2026 = runtime
        session._controller2026 = controller
        session._engine2026 = engine
        session.context["observations"]["host"].update(
            stage="stale-stage",
            native2026={"export": "stale-export", "stage": "stale-stage", "keep": 1},
        )
        container = SimpleNamespace(digest="a" * 64)
        request = SimpleNamespace(
            previous_session=session,
            container=container,
            source_sha256=container.digest,
            node=3,
            cpu_index=2,
            received_identifiers=(b"CID\x00", b"\xff"),
        )
        trace_position = session.trace.position
        from scripts import cuw_engine_threads

        with (
            patch.object(
                cuw_engine_threads,
                "validate_vbf_process_before2026",
                return_value=request,
                create=True,
            ) as validate,
            patch.object(
                session,
                "selected_identity",
                side_effect=AssertionError(
                    "root construction must not select a module"
                ),
            ) as select_identity,
        ):
            following = session._next_vbf_prepare2026(job, request)

        validate.assert_called_once_with(request, job, states=("prepared",))
        select_identity.assert_not_called()
        self.assertIs(type(following), ProgrammingReplay)
        self.assertIs(following.container, container)
        self.assertEqual(following.context["operation"], "prepare")
        self.assertEqual(following.context["node"], 3)
        self.assertEqual(following.context["calibration_sha256"], "a" * 64)
        self.assertEqual(
            following.context["observations"]["current_cids"], ("CID\x00", "\xff")
        )
        host = following.context["observations"]["host"]
        self.assertEqual(host["cpu_index"], 2)
        self.assertEqual(host["native2026"], {"keep": 1, "cpu_index": 2})
        self.assertNotIn("export", host["native2026"])
        self.assertNotIn("stage", host)
        self.assertNotIn("export", host)
        self.assertEqual(following.input_hashes["calibration"], "a" * 64)
        for name in (
            "catalog",
            "modules",
            "attachments",
            "trace",
            "_catalog_sources",
            "_module_files",
        ):
            self.assertIs(getattr(following, name), getattr(session, name))
        self.assertIs(following._runtime2026, runtime)
        self.assertIs(following._controller2026, controller)
        self.assertIs(following._engine2026, engine)
        self.assertFalse(following.used)
        for name in (
            "_selection2026",
            "_executed_selection2026",
            "_control_target2026",
            "_control_export2026",
            "_retained_export2026",
            "_alternate_parent2026",
        ):
            self.assertIsNone(getattr(following, name))
        host["native2026"]["keep"] = 2
        self.assertEqual(
            session.context["observations"]["host"]["native2026"]["keep"], 1
        )
        self.assertEqual(session.trace.position, trace_position)

    def test_vbf_resume_root_rejects_a_different_previous_root(self):
        session = self.load()
        session.used = True
        request = SimpleNamespace(previous_session=object())
        from scripts import cuw_engine_threads

        with (
            patch.object(
                cuw_engine_threads,
                "validate_vbf_process_before2026",
                return_value=request,
                create=True,
            ),
            self.assertRaisesRegex(ValueError, "previous raw root"),
        ):
            session._next_vbf_prepare2026(object(), request)

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


def make_authentic_sbr_replay_fixture(
    case,
    *,
    data: bytes = b"DATA",
    cpu_count: int = 1,
    cpu_type_second: str = "283",
    block_response: bytes = bytes.fromhex("7420000a"),
    events_override=None,
    capture_progress: bool = True,
):
    """Build real SBR family outputs into one raw CONTROL chronology."""
    import csv
    import hashlib
    import io
    from pathlib import Path

    from scripts.calibration import CalibrationContainer
    from scripts.calibration_2026 import parse_cuw_2026
    from scripts.j2534_2026 import J2534Device2026, PrimitiveResult
    from scripts.native_modules import identify_native_module
    from scripts.programming_2026_common import (
        NativeRuntime2026,
        bind_native_parameter2026,
    )
    from scripts.programming_2026_vendor import bind_native_context, run_native
    from tests.private_evidence import read_private_bytes
    from tests.test_calibration_2026 import cuw
    from tests.test_cuw_engine_worker import encoded_table
    from tests.test_programming_2026_common import make_raw_control_fixture2026
    from tests.test_programming_2026_vendor import (
        TypedDriver,
    )
    from tests.test_programming_2026_vendor import (
        context as vendor_context,
    )

    prepare_name = "TCUWCanSBRPrepareWriter.dll"
    writer_name = "TCUWCanSBRFlashWriter.dll"
    utility_name = "TCUWSBRUtils.dll"
    original = vendor_context(prepare_name)
    catalog_name, original_table = next(
        iter(original.selection.catalog_sources.items())
    )
    source_rows = list(csv.reader(io.StringIO(original_table.decode())))
    fields = source_rows[0]
    row = dict(zip(fields, source_rows[1], strict=True))
    if cpu_count not in (1, 2):
        raise ValueError("The authored SBR replay fixture supports one or two CPUs")
    row.update(
        DLLFileNameForFlashWrite=writer_name,
        DLLFileNameForChangeToReprogGatewayMode="",
        GetCANIDFunctionNameForFlashWrite="GetCanIDsFromParamForPrepareWrite",
        CanIDForFlashWrite="07E0/07E8",
        CanIDForPrepareWrite=(
            "07E0/07E8\n07E1/07E9" if cpu_count == 2 else "07E0/07E8"
        ),
        EnableDLLVersionInformation="0\n0\n0\n0",
        CpuLoopBetweenPrepareAndWriteFlag="0",
    )
    for name in (
        "DLLFileNameForFlashWrite",
        "DLLFileNameForChangeToReprogGatewayMode",
        "GetCANIDFunctionNameForFlashWrite",
        "CanIDForFlashWrite",
        "CanIDForPrepareWrite",
        "EnableDLLVersionInformation",
    ):
        if name not in fields:
            fields.append(name)
    values = tuple(row[name] for name in fields)
    plain_table = io.StringIO(newline="")
    plain_writer = csv.writer(plain_table, lineterminator="\r\n")
    plain_writer.writerow(fields)
    plain_writer.writerow(values)
    raw_catalog = {catalog_name: plain_table.getvalue().encode()}
    catalog = {catalog_name: encoded_table(tuple(fields), (values,))}
    if cpu_count == 2:
        second_row = dict(row)
        second_row["ParamFileKeySystemProtocolMicon"] = (
            row["ParamFileKeySystemProtocolMicon"][:-3] + cpu_type_second
        )
        second_row["CanIDForFlashWrite"] = "07E1/07E9"
        second_row["CanIDForPrepareWrite"] = "07E1/07E9"
        second_values = tuple(second_row[name] for name in fields)
        second_catalog_name = catalog_name[: -len("282.ini")] + cpu_type_second + ".ini"
        second_table = io.StringIO(newline="")
        second_writer = csv.writer(second_table, lineterminator="\r\n")
        second_writer.writerow(fields)
        second_writer.writerow(second_values)
        raw_catalog[second_catalog_name] = second_table.getvalue().encode()
        catalog[second_catalog_name] = encoded_table(tuple(fields), (second_values,))
    general_fields = (
        "ParamFileKeySystemProtocolMicon",
        "M16CTypeFlag",
        "FlagToChangeToReprogGWModeForCentralGW",
        "FORESTTypeFlag",
        "PasswordAddress",
        "ByteOrder",
        "FlagToDoIGOFFONAtCPUTypeChange",
    )
    general_rows = [
        (row["ParamFileKeySystemProtocolMicon"], "0", "0", "0", "00", "1", "0")
    ]
    if cpu_count == 2:
        general_rows.append(
            (
                second_row["ParamFileKeySystemProtocolMicon"],
                "0",
                "0",
                "0",
                "00",
                "1",
                "0",
            )
        )
    catalog["Parameter.ini"] = encoded_table(general_fields, tuple(general_rows))
    cpu_sections = [
        (
            "[CPU01]\nCPUType=282\nNumberOfFiles=1\n[File1001]\n"
            "ALFID=44\nEraseBlock=1\nDownloadAddress=00001000\n"
            f"DownloadMemsize={len(data):08X}\n"
        )
    ]
    if cpu_count == 2:
        cpu_sections.append(
            f"[CPU02]\nCPUType={cpu_type_second}\nNumberOfFiles=1\n"
            "[File2001]\nALFID=44\nEraseBlock=1\n"
            "DownloadAddress=00002000\n"
            f"DownloadMemsize={len(data):08X}\n"
        )
    source = cuw(
        "[Format]\nVersion=9\n[Vehicle]\n"
        f"NumberOfCalibration={cpu_count}\n"
        "ContactType=P5-CAN\nKindOfECU=106\n" + "".join(cpu_sections),
        (data,) * cpu_count,
    )
    container = parse_cuw_2026(source)
    if not isinstance(container, CalibrationContainer):
        raise TypeError("Authored SBR fixture must remain a CUW container")
    image_root = Path("runtime/no-car-21/recovered")
    module_bytes = {
        name: read_private_bytes(image_root / name)
        for name in (prepare_name, writer_name, utility_name)
    }

    class CapturingDriver(TypedDriver):
        def __init__(self, replies):
            self.rows = []
            self.replies = {
                request: list(values) for request, values in replies.items()
            }
            self.pending = []
            self.events = []
            self.fault = None
            self.now = 0.0
            self.timeout = 100
            self.device = J2534Device2026(
                cast(Any, self), clock=lambda: self.now, background_workers=False
            )

        def __call__(self, event, remaining):
            if event["operation"] in (
                "calculate_sbr_key",
                "calculate_sbr_gateway_key",
                "progress",
                "notify_progress_count",
                "notify_progress_percent",
            ):
                result = (
                    bytes(4)
                    if event["operation"] == "calculate_sbr_key"
                    else bytes(256)
                    if event["operation"] == "calculate_sbr_gateway_key"
                    else None
                )
                self.rows.append((event, result, False))
                return result
            result = super().__call__(event, remaining)
            self.rows.append((event, result, True))
            return result

    def tag(value):
        from scripts.j2534_2026 import NativeMessage, NativeReadBatch2026

        if isinstance(value, PrimitiveResult):
            value = {"status": value.status, "value": value.value}
        if value is None:
            return {"type": "none", "value": None}
        if type(value) is bool:
            return {"type": "bool", "value": value}
        if type(value) is int:
            return {"type": "int", "value": value}
        if isinstance(value, bytes):
            return {"type": "bytes", "value": value.hex()}
        if isinstance(value, str):
            return {"type": "text", "value": value}
        if isinstance(value, (tuple, list)):
            kind = "tuple" if isinstance(value, tuple) else "sequence"
            return {"type": kind, "value": [tag(item) for item in value]}
        if isinstance(value, dict):
            return {
                "type": "mapping",
                "value": {key: tag(item) for key, item in value.items()},
            }
        if type(value) is NativeMessage:
            return {
                "type": "mapping",
                "value": {
                    "_native_type": {"type": "text", "value": "PASSTHRU_MSG_2026"},
                    **{key: tag(item) for key, item in vars(value).items()},
                },
            }
        if type(value) is NativeReadBatch2026:
            return {
                "type": "mapping",
                "value": {
                    "_native_type": {"type": "text", "value": "READ_BATCH_2026"},
                    "messages": tag(value.messages),
                    "count": tag(value.count),
                },
            }
        raise TypeError(f"Unsupported captured primitive value {type(value)!r}")

    if (
        not isinstance(block_response, bytes)
        or len(block_response) != 4
        or block_response[:2] != bytes.fromhex("7420")
    ):
        raise ValueError("SBR block response must be a four-byte 74 20 response")
    block_width = int.from_bytes(block_response[2:], "big") - 6
    if block_width < 1:
        raise ValueError("SBR max block length must leave room for one data byte")
    replies = {
        b"\x27\x33": [b"\x67\x33" + bytes(range(16))],
        b"\x27\x34" + bytes(256): [b"\x67\x34"],
        b"\x31\x01\x02\0": [b"\x71\x01\x02\0"],
        b"\x31\x01\x02\x01": [b"\x71\x01\x02\x01"],
        b"\x22\xf1\0": [b"\x62\xf1\0\xe0\0\0"],
        b"\x27\x01": [b"\x67\x01" + bytes(4)],
        b"\x10\x02": [b"\x50\x02"],
        b"\x37": [b"\x77"] * cpu_count,
    }
    for cpu_index in range(cpu_count):
        address = 0x1000 + cpu_index * 0x1000
        cpu_area = bytes.fromhex("440000") + address.to_bytes(2, "big")
        cpu_area += len(data).to_bytes(4, "big")
        replies[bytes.fromhex("3101ff00") + cpu_area] = [bytes.fromhex("7101ff00")]
        replies[bytes.fromhex("3404") + cpu_area] = [block_response]
        replies[bytes.fromhex("3101ff01") + cpu_area] = [bytes.fromhex("7101ff0101")]
        for sequence, offset in enumerate(range(0, len(data), block_width), 1):
            chunk = data[offset : offset + block_width]
            request = (
                bytes((0x36, sequence & 0xFF))
                + (address + offset).to_bytes(4, "big")
                + chunk
            )
            replies[request] = [bytes((0x76, sequence & 0xFF))]
    driver = CapturingDriver(replies)
    driver.device.open()
    driver.device.connect(6)
    direct_device_action = driver.device.primitive

    def direct_action(event, remaining):
        if event["operation"] in (
            "switch_connection",
            "switch_connection_with_version",
            "start_periodic",
            "stop_periodic",
            "connect",
            "start_sync_periodic",
            "set_local_time_to_previous_send_time",
            "is_sending_sync_periodic",
            "disconnect",
            "stop_sync_periodic",
            "stop_sync_periodic_message",
            "get_protocol_id",
            "get_send_timeout",
            "set_send_timeout",
            "set_history_enabled",
            "get_system_time",
            "local_time_ms",
            "get_timeout",
            "set_timeout",
            "write_messages",
            "read_specified_can_messages",
            "read_messages_result",
            "read_after_indication_result",
            "read_messages",
            "read_after_indication",
            "queue_messages",
            "write_tcp",
            "read_tcp",
            "logical_connect",
            "logical_disconnect",
            "logical_connect_udp_discovery",
            "logical_disconnect_udp_discovery",
            "start_sync_periodic_0500",
            "five_baud_init",
            "fast_init",
            "read_specified_can_message",
            "start_flow_control_filter",
            "stop_filter",
            "control_io",
            "wait",
            "lock",
            "unlock",
            "ioctl",
            "wrap_read_messages",
        ):
            return direct_device_action(event, remaining)
        if event["operation"] == "get_local_milliseconds_of_day":
            result = 1500
        elif event["operation"] == "get_local_seconds_of_day":
            result = 1
        elif event["operation"] == "calculate_sbr_key":
            result = bytes(4)
        elif event["operation"] == "calculate_sbr_gateway_key":
            result = bytes(256)
        elif event["operation"] == "progress" or event["operation"] in (
            "notify_progress_count",
            "notify_progress_percent",
        ):
            result = None
        elif event["operation"] == "set_communication_log_mode":
            result = 0
        else:
            raise AssertionError(f"Unexpected authored family primitive: {event}")
        driver.rows.append((event, result, False))
        return result

    def local_ms():
        driver.rows.append(
            ({"operation": "get_local_milliseconds_of_day"}, 1500, False)
        )
        return 1500

    def local_seconds():
        driver.rows.append(({"operation": "get_local_seconds_of_day"}, 1, False))
        return 1

    runtime = NativeRuntime2026(
        direct_action,
        timeout=1800,
        clock=lambda: driver.now,
        native_cancelled=lambda: False,
        local_seconds_of_day=local_seconds,
        local_milliseconds_of_day=local_ms,
    )

    def family_context(name, operation):
        selection = bind_native_parameter2026(
            container, raw_catalog, operation, encoded=False, node=1
        )
        identity = identify_native_module(
            hashlib.sha256(module_bytes[name]).hexdigest(), name
        )
        return bind_native_context(
            container, 1, (), selection, identity, {}, {"cpu_index": 0}
        )

    direct_events = []
    prepare_ctx = family_context(prepare_name, "prepare")
    prepare_result = run_native(
        prepare_ctx,
        runtime,
        key_provider=lambda secret_type, seed, aes, encrypt: runtime.call(
            "calculate_sbr_key",
            secret_type=secret_type,
            seed=seed,
            aes=aes,
            encrypt=encrypt,
        ),
        gateway_key_provider=lambda seed: runtime.call(
            "calculate_sbr_gateway_key", seed=seed
        ),
    )
    assert prepare_result["state"] == "prepare_completed"
    prepare_count = len(driver.rows)
    driver.rows.append(
        (
            {"operation": "set_communication_log_mode", "mode": 2},
            0,
            False,
        )
    )
    writer_ctx = family_context(writer_name, "write")
    writer_result = run_native(
        writer_ctx,
        runtime,
        notify=lambda field, value: (
            runtime.call("progress", field=field, value=value)
            if field in ("writing", "next_cpu")
            else None
        ),
    )
    assert writer_result["state"] == "writer_completed"
    driver.rows.append(
        (
            {"operation": "set_communication_log_mode", "mode": 0},
            0,
            False,
        )
    )
    direct_events.extend(driver.rows[:prepare_count])
    direct_events.append(driver.rows[prepare_count])
    direct_events.extend(driver.rows[prepare_count + 1 :])
    event_rows = []
    from scripts.programming_replay import _native_request

    for request, output, is_driver in direct_events:
        if is_driver and isinstance(output, PrimitiveResult):
            output_value = {"status": output.status, "value": output.value}
        elif is_driver:
            output_value = {"status": 0, "value": output}
        else:
            output_value = output
        event_rows.append(
            {
                "kind": "action",
                "request": _native_request(request),
                "result": tag(output_value),
                "elapsed_ms": max(
                    1,
                    request.get("milliseconds", 1)
                    if request["operation"] == "wait"
                    else 1,
                ),
            }
        )

    if cpu_count == 2:
        for mode in (2, 0):
            event_rows.append(
                {
                    "kind": "action",
                    "request": {
                        "operation": "set_communication_log_mode",
                        "mode": mode,
                    },
                    "result": {"type": "int", "value": 0},
                    "elapsed_ms": 1,
                }
            )
    events = (
        {
            "kind": "action",
            "request": {"operation": "get_local_milliseconds_of_day"},
            "result": {"type": "int", "value": 1000},
            "elapsed_ms": 1,
        },
        *event_rows,
        {
            "kind": "action",
            "request": {"operation": "get_local_milliseconds_of_day"},
            "result": {"type": "int", "value": 2000},
            "elapsed_ms": 1,
        },
    )
    engine, control, session = make_raw_control_fixture2026(
        case,
        source=source,
        catalog=catalog,
        module_files=module_bytes,
        operation="prepare",
        events=events if events_override is None else events_override,
        paired=True,
    )

    class ProgrammingTraceCapture:
        """Capture native order using only already-authored primitive inputs."""

        def __init__(self):
            self.actions = []
            self.recorded_consume = session.trace.consume

        def __call__(self, kind, request, remaining=None):
            if kind == "action" and request.get("operation") in (
                "notify_progress_count",
                "notify_progress_percent",
            ):
                self.actions.append(dict(request))
                rows = session.trace.rows
                if type(rows) is not list:
                    raise TypeError("Mutable source trace capture rows required")
                rows.insert(
                    session.trace.position,
                    {
                        "kind": "action",
                        "request": _native_request(request),
                        "result": {"type": "none", "value": None},
                        "elapsed_ms": 0,
                    },
                )
            if kind == "action":
                rows = session.trace.rows
                if type(rows) is not list:
                    raise TypeError("Mutable source trace capture rows required")
                position = session.trace.position
                expected = (
                    rows[position].get("request") if position < len(rows) else None
                )
                normalized = _native_request(request)
                if expected != normalized:
                    match = next(
                        (
                            index
                            for index in range(position + 1, len(rows))
                            if rows[index].get("kind") == "action"
                            and rows[index].get("request") == normalized
                        ),
                        None,
                    )
                    if match is not None:
                        rows[position], rows[match] = rows[match], rows[position]
            return self.recorded_consume(kind, request, remaining)

    from scripts.programming_replay import _native_request

    canonical_actions = []
    if capture_progress:
        session.trace.rows = list(session.trace.rows)
        trace_capture = ProgrammingTraceCapture()
        canonical_actions = trace_capture.actions
        session.trace.consume = trace_capture
    return (
        engine,
        control,
        session,
        driver,
        control.runtime,
        canonical_actions,
        row["ParamFileKeySystemProtocolMicon"],
    )


class ControlStagedReplayTests(unittest.TestCase):
    def setUp(self):
        helper = ProgrammingReplayTests()
        helper.setUp()
        self.helper = helper
        self.session = helper.load()

    def _load_private_dh_retry_proof(self):
        import importlib.util

        from tests.private_evidence import require_private

        relative_paths = (
            "runtime/no-car-119/verify_failed_dh_retry.py",
            "runtime/no-car-119/verify_failed_sonar_retry.py",
            "runtime/no-car-119/dh_retry_fixture.py",
            "runtime/no-car-119/sonar_retry_fixture.py",
            "runtime/no-car-21/recovered/CUW.dll",
            "runtime/no-car-21/recovered/TCUWCanDHFlashWriter.dll",
            "runtime/no-car-21/recovered/TCUWCanDHPrepareWriter.dll",
            "runtime/no-car-21/recovered/TCUWControlCommPhase.dll",
            "runtime/no-car-21/recovered/TCUWJ2534DeviceIF.dll",
            "runtime/no-car-21/recovered/TCUWDHUtils.dll",
            "runtime/no-car-21/recovered/SecretInfo.dll",
        )
        require_private(*relative_paths)
        repo_root = Path(__file__).resolve().parents[1]
        proof_path = repo_root / relative_paths[0]
        spec = importlib.util.spec_from_file_location("dh_retry_raw_proof", proof_path)
        if spec is None or spec.loader is None:
            raise AssertionError("Private DH retry proof loader is unavailable")
        proof = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(proof)
        return proof

    def test_dh_retry_proof_skips_when_private_source_is_absent(self):
        from tests import private_evidence

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(private_evidence, "_REPO_ROOT", Path(directory)),
            self.assertRaises(unittest.SkipTest),
        ):
            self._load_private_dh_retry_proof()

    def test_private_stage_rejects_forged_or_unbound_target(self):
        from scripts.programming_2026_common import NativeControlExportTarget2026

        with self.assertRaisesRegex(ValueError, "exact replay owners"):
            self.session._next_control_export2026(object(), "StartFlashWrite")
        with self.assertRaisesRegex(ValueError, "exact replay owners"):
            self.session._next_control_export2026(
                object.__new__(NativeControlExportTarget2026), "StartFlashWrite"
            )
        self.assertEqual(self.session.trace.position, 0)
        self.assertFalse(self.session.used)

    def test_private_stage_rejects_unknown_export(self):
        with self.assertRaisesRegex(ValueError, "exact replay owners"):
            self.session._next_control_export2026(object(), "caller_selected_stage")
        self.assertEqual(self.session.trace.position, 0)

    def test_control_root_binding_requires_live_raw_driver_owners(self):
        with self.assertRaisesRegex(ValueError, "exact native owners"):
            self.session._bind_control_root2026(object(), object(), object())
        self.assertIsNone(self.session._engine2026)
        self.assertIsNone(self.session._controller2026)
        self.assertIsNone(self.session._runtime2026)
        self.assertEqual(self.session.trace.position, 0)

    def test_public_clone_cannot_receive_private_target_authority(self):
        from scripts.programming_replay import ProgrammingReplay

        with self.assertRaises(TypeError):
            cast(Any, self.session.next_session2026)(
                "write", node=1, cpu_index=0, _control_target2026=object()
            )
        forged = ProgrammingReplay(
            self.session.container,
            dict(self.session.context),
            self.session.catalog,
            self.session.modules,
            self.session.attachments,
            self.session.trace,
            dict(self.session.input_hashes),
            _control_target2026=object(),
            _control_export2026="StartFlashWrite",
        )
        with self.assertRaisesRegex(ValueError, "Private CONTROL replay lineage"):
            forged._validate_control_stage2026()

    def test_recording_cannot_supply_a_stage_override(self):
        document = dict(self.helper.document)
        document["stage"] = "write"
        with self.assertRaises(ValueError):
            self.helper.load(document)

    def test_control_return_receipt_requires_explicit_native_boolean(self):
        from scripts.programming_replay import ProgrammingReplay

        read_return = ProgrammingReplay._explicit_control_native_return2026
        self.assertIs(read_return({"native_return": True}), True)
        self.assertIs(read_return({"native_return": False}), False)
        self.assertIs(read_return({"native_result": {"returned": True}}), True)
        self.assertIsNone(
            read_return({"native_return": None, "native_result": {"returned": True}})
        )
        self.assertIsNone(
            read_return({"state": "writer_completed", "native_success": True})
        )
        self.assertIsNone(read_return({"identifiers": (b"CID",)}))

    def test_dh_binding_rejects_caller_supplied_export_override(self):
        proof = self._load_private_dh_retry_proof()
        from scripts import programming_2026_dh as dh2026

        with proof.factory.canonical(authoring=True) as (
            _engine,
            _control,
            session,
            _cancel,
        ):
            selection, module, *_ = session._dispatch2026()
            with self.assertRaisesRegex(ValueError, "undeclared overrides"):
                dh2026.bind_native_context(
                    session.container,
                    session.node,
                    (),
                    selection,
                    module.native_identity,
                    {"selected_module": session._module_files[module.name]},
                    {"export": "PrepareRetry"},
                )

    def test_actual_dh_retry_uses_private_export_on_fresh_strict_trace(self):
        proof = self._load_private_dh_retry_proof()
        authored_rows, captured = proof.exercise(1, author=True)
        rows, strict = proof.exercise(1, events=authored_rows)

        self.assertEqual(rows, authored_rows)
        self.assertEqual(captured["events"], 97)
        self.assertFalse(captured["exact_final_trace"])
        self.assertEqual(captured["native_prepare_retry_exports"], 1)
        self.assertEqual(strict["events"], 97)
        self.assertTrue(strict["exact_final_trace"])
        self.assertEqual(strict["native_prepare_retry_exports"], 1)
        self.assertTrue(strict["source_retry_decision"])

    def test_authentic_sbr_two_cpu_shared_execute_frozen_strict_replay(self):
        import copy

        capture_engine, capture_control, capture_session, *_ = (
            make_authentic_sbr_replay_fixture(self, cpu_count=2)
        )
        with capture_engine.controller_execution(capture_control, 1):
            capture_session._bind_control_prelude2026(
                capture_engine, capture_control, capture_control.runtime
            )
            device = capture_engine.engine_runtime_device()
            device.open()
            device.connect(6)
            capture_result = capture_control.execute(capture_engine, capture_session)
        self.assertTrue(capture_result["native_return"])
        self.assertEqual(
            tuple(report["entrypoint"] for report in capture_result["exports"]),
            ("StartPrepareWrite", "StartFlashWrite", "StartFlashWrite"),
        )
        self.assertEqual(capture_result["exports"][1]["transferred"], 8)
        self.assertEqual(capture_result["exports"][1]["next_cpu_index"], 2)
        self.assertEqual(capture_result["exports"][2]["transferred"], 0)
        self.assertTrue(capture_result["exports"][2]["native_skipped_completed"])
        self.assertEqual(capture_result["exports"][2]["next_cpu_index"], 1)
        self.assertEqual(capture_engine.comm_phase, 2)
        self.assertEqual(
            capture_session.trace.position, len(capture_session.trace.rows)
        )
        captured_events = tuple(copy.deepcopy(capture_session.trace.rows))
        captured_wire = json.dumps(captured_events)
        self.assertEqual(captured_wire.count("36010000100044415441"), 1)
        self.assertEqual(captured_wire.count("36010000200044415441"), 1)
        self.assertIn("000007e0", captured_wire)
        self.assertIn("000007e1", captured_wire)
        self.assertEqual(
            [
                event["request"]["mode"]
                for event in captured_events
                if event.get("request", {}).get("operation")
                == "set_communication_log_mode"
            ],
            [2, 0, 2, 0],
        )
        self.assertEqual(
            [
                action["cpu_index"]
                for action in (
                    event["request"]
                    for event in captured_events
                    if event.get("request", {}).get("operation")
                    == "notify_progress_count"
                )
            ],
            [0, 1],
        )

        engine, control, session, *_ = make_authentic_sbr_replay_fixture(
            self,
            cpu_count=2,
            events_override=captured_events,
            capture_progress=False,
        )
        with engine.controller_execution(control, 1):
            session._bind_control_prelude2026(engine, control, control.runtime)
            device = engine.engine_runtime_device()
            device.open()
            device.connect(6)
            result = control.execute(engine, session)
        self.assertTrue(result["native_return"])
        self.assertEqual(session.trace.position, len(captured_events))
        self.assertEqual(
            tuple(report["entrypoint"] for report in result["exports"]),
            ("StartPrepareWrite", "StartFlashWrite", "StartFlashWrite"),
        )
        self.assertEqual(result["exports"][1]["transferred"], 8)
        self.assertEqual(result["exports"][2]["transferred"], 0)
        self.assertTrue(result["exports"][2]["native_skipped_completed"])
        self.assertEqual(engine.comm_phase, 2)
        self.assertIsNone(control._native_control_raw_execution2026)

    def test_authentic_sbr_prepare_empty_gateway_write_shared_execute(self):
        import copy

        from scripts.programming_replay import _native_request
        from tests.test_cuw_engine_worker import encoded_table

        (
            capture_engine,
            capture_control,
            capture_session,
            _capture_driver,
            _capture_runtime,
            canonical_actions,
            parameter_key,
        ) = make_authentic_sbr_replay_fixture(self)
        with capture_engine.controller_execution(capture_control, 1):
            from types import MappingProxyType

            held_metadata = capture_control.native_control_context2026(
                capture_engine
            )._capture.metadata
            self.assertTrue(held_metadata.parser_parameters_validated)
            original_sources = capture_session._catalog_sources
            unrelated_sources = dict(original_sources)
            unrelated_sources["Parameter.ini"] = encoded_table(
                (
                    "ParamFileKeySystemProtocolMicon",
                    "M16CTypeFlag",
                    "FlagToChangeToReprogGWModeForCentralGW",
                    "FORESTTypeFlag",
                    "PasswordAddress",
                    "ByteOrder",
                    "FlagToDoIGOFFONAtCPUTypeChange",
                ),
                (
                    (
                        parameter_key,
                        "0",
                        "0",
                        "0",
                        "00",
                        "1",
                        "1",
                    ),
                ),
            )
            capture_session._catalog_sources = MappingProxyType(unrelated_sources)
            with self.assertRaisesRegex(ValueError, "General source differs"):
                capture_session._bind_control_prelude2026(
                    capture_engine, capture_control, capture_control.runtime
                )
            capture_session._catalog_sources = original_sources
            capture_session._bind_control_prelude2026(
                capture_engine, capture_control, capture_control.runtime
            )
            self.assertIsNone(capture_control._native_control_raw_execution2026)
            capture_session.context["observations"]["current_cids"] = [
                "ROOT-JSON-MUST-NOT-WIN"
            ]
            engine_device = capture_engine.engine_runtime_device()
            engine_device.open()
            engine_device.connect(6)
            capture_result = capture_control.execute(capture_engine, capture_session)
        self.assertTrue(capture_result["native_return"])
        self.assertEqual(
            capture_session.trace.position, len(capture_session.trace.rows)
        )
        captured_events = tuple(copy.deepcopy(capture_session.trace.rows))

        (
            engine,
            control,
            session,
            _driver,
            _runtime,
            strict_actions,
            _parameter_key,
        ) = make_authentic_sbr_replay_fixture(
            self, events_override=captured_events, capture_progress=False
        )
        self.assertEqual(strict_actions, [])
        requests = tuple(
            event["request"]
            for event in captured_events
            if event["request"].get("operation")
            in ("notify_progress_count", "notify_progress_percent")
        )
        self.assertEqual(
            requests,
            tuple(_native_request(event) for event in canonical_actions),
        )
        with engine.controller_execution(control, 1):
            session._bind_control_prelude2026(engine, control, control.runtime)
            session.context["observations"]["current_cids"] = ["ROOT-JSON-MUST-NOT-WIN"]
            engine_device = engine.engine_runtime_device()
            engine_device.open()
            engine_device.connect(6)
            result = control.execute(engine, session)
        self.assertEqual(
            tuple(report["native_return"] for report in result["exports"]),
            (True, True),
        )
        self.assertEqual(
            tuple(report["entrypoint"] for report in result["exports"]),
            ("StartPrepareWrite", "StartFlashWrite"),
        )
        self.assertEqual(engine.comm_phase, 2)
        self.assertTrue(result["native_return"])
        self.assertEqual(session.trace.position, len(session.trace.rows))
        self.assertTrue(session.used)
        self.assertEqual(
            tuple(canonical_actions),
            (
                {
                    "operation": "notify_progress_count",
                    "cpu_index": 0,
                    "transferred_bytes": 0,
                },
                {
                    "operation": "notify_progress_percent",
                    "cpu_index": 0,
                    "progress": 100,
                },
            ),
        )
        self.assertEqual(session.trace.position, len(captured_events))
        wire = json.dumps(session.trace.rows)
        self.assertIn("1063", wire)
        self.assertIn("360100001000", wire)
        self.assertIn("44415441", wire)
        self.assertFalse(engine.worker.control_state.failed)
        self.assertIsNone(control._native_control_helper_entry2026)
        self.assertIsNone(control._native_control_raw_execution2026)


if __name__ == "__main__":
    unittest.main()
