"""Authored selected metadata-to-wire workflows, without vendor or hardware I/O."""

import copy
import hashlib
import json
import os
import struct
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from scripts.active_replay import (
    ActiveReplay,
    create_active_examples,
    create_signed_active_examples,
)
from scripts.active_tests import SAKeyMaterial
from scripts.demo import _ddb
from scripts.diagnostic_db import parse_database
from scripts.profiles import VehicleCatalog
from scripts.toyota import VariableTable
from scripts.toyota_session import Cancelled, NativeStatus, P5ActiveQueue


def arguments(**changes):
    return {
        "value": 5,
        "auxiliary": 0,
        "display_index": None,
        "input_hex": "",
        "button_index": None,
    } | changes


class ActiveReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.files = create_active_examples()
        for name, payload in cls.files.items():
            path = cls.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        cls.profile = VehicleCatalog(cls.root / "Techstream_DB_NA").build_profile(1)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def document(self, family="p3"):
        return json.loads(self.files[f"active-{family}.json"])

    def replay(self, family="p3", **options):
        return ActiveReplay(self.document(family), self.profile, **options)

    def changed(self, slot, alter):
        sections = {
            key: (section.count, section.payload)
            for key, section in self.profile.database.sections.items()
        }
        count, raw = sections[slot]
        payload = bytearray(raw)
        alter(payload)
        sections[slot] = (count, bytes(payload))
        database = parse_database(_ddb(2, sections))
        return replace(self.profile, database=database)

    def for_profile(self, document, profile):
        document["context"]["version"] = profile.database.version
        document["context"]["ecu_sha256"] = profile.database.sha256
        document["context"]["management_sha256"] = profile.catalog.management.sha256
        return ActiveReplay(document, profile)

    def version12_profile(self):
        def convert(database, management):
            sections = {
                key: (section.count, section.payload)
                for key, section in database.sections.items()
            }
            if management:
                sections[13] = (
                    1,
                    database.sections[13].payload[:22]
                    + database.sections[13].payload[24:26],
                )
            else:
                displays = []
                for source in database.sections[14].rows(24):
                    target = bytearray(20)
                    target[:4] = source[:4]
                    for old, new in ((12, 4), (16, 8), (4, 10), (8, 12), (18, 14)):
                        target[new : new + 2] = source[old : old + 2]
                    target[18], target[19] = source[22], source[23]
                    displays.append(bytes(target))
                sections[14] = (len(displays), b"".join(displays))
                row = database.sections[71].payload
                sections[71] = (1, row[:32] + row[34:62])
            raw = bytearray(_ddb(database.kind, sections))
            struct.pack_into("<I", raw, 28, 0x0100030C)
            return parse_database(bytes(raw))

        catalog = copy.copy(self.profile.catalog)
        catalog.management = convert(catalog.management, True)
        return replace(
            self.profile,
            catalog=catalog,
            database=convert(self.profile.database, False),
        )

    def test_version12_selected_layout_uses_proven_wire_paths_without18_overrides(self):
        profile = self.version12_profile()
        for family in ("p3", "p4", "dk", "psa", "p5", "routine"):
            with self.subTest(family=family):
                replay = self.for_profile(self.document(family), profile)
                names = replay.available_tests()
                signal = 3 if family == "routine" else 2 if family == "p5" else 1
                result = replay.run_test(
                    signal,
                    arguments(value=0 if family == "psa" else 5),
                    family=next(
                        row["family"] for row in names if row["signal_id"] == signal
                    ),
                )
                self.assertEqual(result["state"], "stopped")
        document = self.document("p5")
        document["context"]["did_lengths"] = {}
        replay = self.for_profile(document, profile)
        with self.assertRaisesRegex(ValueError, "Missing observed active DID length"):
            replay.run_test(2, arguments())
        self.assertEqual(replay.replay.position, 0)
        replay = self.for_profile(self.document("p5"), profile)
        with self.assertRaisesRegex(ValueError, "Version 12"):
            replay.run_test(2, arguments(output_mask=1))

    def duplicate_frame(self, function):
        management = self.profile.catalog.management
        sections = {
            key: (section.count, section.payload)
            for key, section in management.sections.items()
        }
        rows = list(management.sections[18].rows(16))
        original = next(
            row for row in rows if struct.unpack_from("<H", row, 2)[0] == function
        )
        duplicate = bytearray(original)
        struct.pack_into("<H", duplicate, 10, 2)
        rows.append(bytes(duplicate))
        rows.sort(
            key=lambda row: (
                struct.unpack_from("<HH", row, 0)
                + (struct.unpack_from("<H", row, 10)[0],)
            )
        )
        sections[18] = (len(rows), b"".join(rows))
        catalog = copy.copy(self.profile.catalog)
        catalog.management = parse_database(_ddb(1, sections))
        return replace(self.profile, catalog=catalog)

    def variable(self, profile, reference, payload):
        management = profile.catalog.management
        sections = {
            key: (section.count, section.payload)
            for key, section in management.sections.items()
        }
        section = management.sections[0]
        table = VariableTable(section.payload, section.count)
        values = [table.get(index) for index in range(1, section.count + 1)]
        values[reference - 1] = payload
        directory, body = bytearray(), bytearray()
        for value in values:
            directory += struct.pack("<IH", len(body), len(value))
            body += value
        sections[0] = (len(values), bytes(directory + body))
        catalog = copy.copy(profile.catalog)
        raw = bytearray(_ddb(1, sections))
        struct.pack_into("<I", raw, 28, management.version)
        catalog.management = parse_database(bytes(raw))
        return replace(profile, catalog=catalog)

    def test_all_recovered_families_execute_selected_native_workflows(self):
        for family in ("p3", "p4", "dk", "old_body", "sa", "psa", "p5", "routine"):
            with self.subTest(family=family):
                with patch.object(
                    SAKeyMaterial, "from_library", return_value=SAKeyMaterial(0, 0)
                ):
                    replay = self.replay(
                        family,
                        sa_library="authored-provider" if family == "sa" else None,
                    )
                signal = 3 if family == "routine" else 2 if family == "p5" else 1
                names = replay.available_tests()
                self.assertTrue(
                    all(row["name"].startswith("Authored") for row in names)
                )
                result = replay.run_test(
                    signal,
                    arguments(value=0 if family == "psa" else 5),
                    family=next(
                        row["family"] for row in names if row["signal_id"] == signal
                    ),
                )
                self.assertEqual(
                    (result["state"], result["remaining_exchanges"]), ("stopped", 0)
                )
                self.assertEqual(result["physical_status"], "PHYSICAL_UNCONFIRMED")
                self.assertNotIn("pass", result)
                replay.close()
                replay.close()

    def test_demo_manifest_hashes_cover_final_resources_and_workflows(self):
        manifest = json.loads(self.files["demo-manifest.json"])
        self.assertEqual(
            set(manifest["files"]), set(self.files) - {"demo-manifest.json"}
        )
        for name, digest in manifest["files"].items():
            self.assertEqual(digest, hashlib.sha256(self.files[name]).hexdigest())

    def test_production_signed_examples_load_selected_profiles_and_negative_wire(self):
        files = create_signed_active_examples()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, payload in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
            profile = VehicleCatalog(root / "Techstream_DB_NA").build_profile(1)
            for family, signal in (("p3", 1), ("p5", 2), ("routine", 3)):
                replay = ActiveReplay.loads(
                    files[f"active-{family}-negative.json"], profile
                )
                self.assertEqual(
                    (
                        replay.initialize(signal)["minimum"],
                        replay.initialize(signal)["maximum"],
                    ),
                    (-5, 5),
                )
                self.assertEqual(
                    replay.run_test(signal, arguments(value=-1))["state"], "stopped"
                )
            manifest = json.loads(files["demo-manifest.json"])
            self.assertEqual(
                manifest["files"],
                {
                    name: hashlib.sha256(payload).hexdigest()
                    for name, payload in files.items()
                    if name != "demo-manifest.json"
                },
            )

    def test_family_driver_guard_precedes_any_exchange(self):
        for family, driver in (
            ("p3", "dual"),
            ("p4", "p5"),
            ("p5", "psa"),
            ("psa", "j2534"),
            ("dk", "dual"),
        ):
            with self.subTest(family=family, driver=driver):
                document = self.document(family)
                document["context"]["driver"] = driver
                with self.assertRaisesRegex(
                    ValueError, "family and native driver disagree"
                ):
                    ActiveReplay(document, self.profile)
        document = self.document()
        document["context"]["bus_id"] = 0
        with self.assertRaisesRegex(ValueError, "nonzero observed connected bus"):
            ActiveReplay(document, self.profile)

    def test_exported_lifecycle_evidence_is_a_deep_snapshot(self):
        replay = self.replay()
        exported = replay.run_test(1, arguments())
        exported["events"][0]["action"] = "forged"
        exported["events"][0]["replies_hex"].append("forged")
        self.assertEqual(replay.report()["events"][0]["action"], "start")
        self.assertNotIn("forged", replay.report()["events"][0]["replies_hex"])

    def test_combined_p5_list_requires_family_for_colliding_signal_ids(self):
        profile = self.changed(71, lambda row: struct.pack_into("<H", row, 30, 2))
        replay = self.for_profile(self.document("p5"), profile)
        with self.assertRaisesRegex(ValueError, "unambiguous"):
            replay.initialize(2)
        self.assertEqual(replay.replay.position, 0)
        self.assertEqual(replay.initialize(2, family="p5")["family"], "p5")

    def test_phase_template_report_names_actual_selected_ddb_provenance(self):
        replay = self.replay("p5")
        report = replay.run_test(2, arguments())
        for function in (0x9D, 0x64):
            self.assertEqual(
                report["selected_templates"][f"{function:04x}"],
                self.profile.frame_records(function)[0].provenance,
            )
        report["selected_templates"].clear()
        self.assertEqual(len(replay.report()["selected_templates"]), 2)

    def test_version18_scalar_output_mask_is_not_restricted_to_special_protocol(self):
        profile = self.changed(67, lambda row: row.__setitem__(10, 1))
        document = self.document("p5")
        document["context"]["protocol"] = 0
        document["native"]["transactions"][0]["request"] = "2f1234030570"
        document["native"]["transactions"][1]["request"] = "2f12340070"
        document["native"]["transactions"].insert(
            0, {"ecu": "authored-ecu", "request": "221234", "response": "621234ff"}
        )
        replay = self.for_profile(document, profile)
        self.assertEqual(
            replay.run_test(2, arguments(output_mask=0x70))["state"], "stopped"
        )

    def test_routine_byte_arguments_do_not_validate_an_unused_scalar_placeholder(self):
        profile = self.changed(71, lambda row: struct.pack_into("<II", row, 0, 10, 3))
        replay = self.for_profile(self.document("routine"), profile)
        self.assertEqual(
            replay.run_test(3, arguments(value=0, input_hex="05"))["state"], "stopped"
        )

    def test_signed_scalar_ranges_cover_crosszero_negative_intervals_and_endpoints(
        self,
    ):
        for minimum, maximum, accepted, rejected in (
            (-5, 5, (-5, 0, 5), (-6, 6)),
            (-10, -1, (-10, -1), (-11, 0)),
            (
                -0x80000000,
                0x7FFFFFFF,
                (-0x80000000, 0x7FFFFFFF),
                (-0x80000001, 0x80000000, 0xFFFFFFFF),
            ),
        ):

            def bounds(row, minimum=minimum, maximum=maximum):
                struct.pack_into(
                    "<II", row, 24, maximum & 0xFFFFFFFF, minimum & 0xFFFFFFFF
                )

            profile = self.changed(11, bounds)
            for value in accepted:
                with self.subTest(minimum=minimum, maximum=maximum, value=value):
                    document = self.document()
                    document["native"]["transactions"][0]["request"] = (
                        f"3012{value & 255:02x}"
                    )
                    replay = self.for_profile(document, profile)
                    self.assertEqual(
                        replay.run_test(1, arguments(value=value))["state"], "stopped"
                    )
            for value in rejected:
                replay = self.for_profile(self.document(), profile)
                with self.assertRaises(ValueError):
                    replay.run_test(1, arguments(value=value))
                self.assertEqual(replay.replay.position, 0)

    def test_negative_scalar_reaches_p5_and_routine_as_exact_low_dword(self):
        for family, slot, signal, request in (
            ("p5", 68, 2, "2f123403ff"),
            ("routine", 71, 3, "31014321af"),
        ):
            profile = self.changed(
                slot,
                lambda row, family=family: struct.pack_into(
                    "<II", row, 0 if family == "routine" else 4, 5, 0xFFFFFFFB
                ),
            )
            document = self.document(family)
            document["native"]["transactions"][1 if family == "routine" else 0][
                "request"
            ] = request
            replay = self.for_profile(document, profile)
            self.assertEqual(
                replay.run_test(signal, arguments(value=-1))["state"], "stopped"
            )

    def test_p5_signed_scalar_serializes_modulo_each_native_byte_width(self):
        for width in range(1, 5):

            def fields(row, width=width):
                struct.pack_into("<II", row, 4, 0x7FFFFFFF, 0x80000000)
                struct.pack_into("<HH", row, 40, 0, width * 8 - 1)

            profile = self.changed(68, fields)
            for value in (-1, -2, -0x80000000):
                with self.subTest(width=width, value=value):
                    document = self.document("p5")
                    document["context"]["did_lengths"]["1234"] = width
                    document["native"]["transactions"][0]["request"] = (
                        "2f123403"
                        + (value & ((1 << (width * 8)) - 1))
                        .to_bytes(width, "big")
                        .hex()
                    )
                    replay = self.for_profile(document, profile)
                    self.assertEqual(
                        replay.run_test(2, arguments(value=value))["state"], "stopped"
                    )

    def driver_document(self, driver="dk_kwp"):
        document = self.document("p3")
        document["context"].update(family="dk", init_family="dk", driver=driver)
        document["events"][-1]["initialize"] = True
        ecu = document["context"]["ecu"]
        document["driver_events"] = [
            {
                "operation": "send",
                "after_exchange": 2,
                "ecu": ecu,
                "request": None,
                "timeout": 1000,
                "protocol": 1,
                "initialize": True,
                "status": 77,
            },
            {
                "operation": "receive",
                "after_exchange": 2,
                "ecu": ecu,
                "buffer": False,
                "maximum": 0,
                "timeout": 1000,
                "argument_5": 0,
                "flags": 100,
                "data": "",
                "source_id": 0,
                "status": 88,
            },
        ]
        return document

    def test_kwp_fuel_stop_uses_literal_null_primitives_and_retains_errors(self):
        for driver in ("dk_kwp", "fuel"):
            with self.subTest(driver=driver):
                document = self.driver_document(driver)
                replay = ActiveReplay(document, self.profile)
                result = replay.run_test(1, arguments())
                self.assertEqual(result["state"], "stopped")
                self.assertEqual(result["driver_events"], document["driver_events"])
                result["driver_events"][0]["status"] = 0
                self.assertEqual(replay.report()["driver_events"][0]["status"], 77)

    def test_null_primitive_evidence_is_required_and_ordered(self):
        document = self.driver_document()
        del document["driver_events"]
        with self.assertRaisesRegex(ValueError, "NULL send/receive"):
            ActiveReplay(document, self.profile)
        for field, value in (
            ("request", ""),
            ("after_exchange", 1),
            ("protocol", 2),
            ("timeout", 999),
        ):
            with self.subTest(field=field):
                document = self.driver_document()
                document["driver_events"][0][field] = value
                replay = ActiveReplay(document, self.profile)
                with self.assertRaisesRegex(ValueError, "primitive replay mismatch"):
                    replay.run_test(1, arguments())
                self.assertEqual(replay._driver_replay.position, 0)

    def test_direct_driver_evidence_enforces_aggregate_budget_before_copy(self):
        document = self.driver_document()
        document["driver_events"][1]["data"] = "00"
        with self.assertRaisesRegex(ValueError, "supplied buffer"):
            ActiveReplay(document, self.profile)
        document = self.driver_document()
        document["driver_events"] = [
            dict(
                document["driver_events"][1],
                data="00" * 4096,
                buffer=True,
                maximum=4096,
            )
        ] * 2100
        with self.assertRaisesRegex(ValueError, "exceeds16 MiB"):
            ActiveReplay(document, self.profile)

        class NoCopy:
            def __deepcopy__(self, memo):
                self.fail_if_copied = True
                raise AssertionError("Unknown nested values must not be copied")

        document = self.driver_document()
        document["driver_events"][0]["unknown"] = NoCopy()
        with self.assertRaisesRegex(ValueError, "driver event fields"):
            ActiveReplay(document, self.profile)

    def test_driver_timeouts_select_a7_settings_and_native_missing_settings_fallback(
        self,
    ):
        for configured in (True, False):
            with self.subTest(configured=configured):
                management = self.profile.catalog.management
                sections = {
                    key: (section.count, section.payload)
                    for key, section in management.sections.items()
                }
                if configured:
                    row = bytearray(16)
                    struct.pack_into("<HHH", row, 0, 1, 0xA7, 2)
                    rows = list(management.sections[18].rows(16)) + [bytes(row)]
                    rows.sort(key=lambda value: struct.unpack_from("<HH", value))
                    sections[18] = (len(rows), b"".join(rows))
                    settings = bytearray(16)
                    struct.pack_into("<II", settings, 0, 123, 456)
                    struct.pack_into("<H", settings, 10, 2)
                    count, payload = sections[29]
                    sections[29] = (count + 1, payload + settings)
                    expected = (123, 456)
                else:
                    del sections[29]
                    expected = (1000, 200)
                catalog = copy.copy(self.profile.catalog)
                catalog.management = parse_database(_ddb(1, sections))
                profile = replace(self.profile, catalog=catalog)
                document = self.driver_document()
                (
                    document["driver_events"][0]["timeout"],
                    document["driver_events"][1]["timeout"],
                ) = expected
                replay = self.for_profile(document, profile)
                self.assertEqual(replay.run_test(1, arguments())["state"], "stopped")

    def test_list_and_init_are_cached_including_routine_probe(self):
        replay = self.replay("routine")
        self.assertEqual(replay.replay.position, 0)
        replay.available_tests()
        first = replay.initialize(3)
        self.assertEqual(replay.replay.position, 1)
        self.assertEqual(first, replay.initialize(3))
        self.assertEqual(replay.replay.position, 1)
        self.assertEqual(first["routine_spec_id"], 0)
        self.assertTrue(first["routine_status_supported"])

    def test_profile_identity_mismatch_is_rejected_before_exchange(self):
        for field in ("category", "version", "ecu_sha256", "management_sha256"):
            document = self.document()
            document["context"][field] = 0
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(ValueError, "mismatch"),
            ):
                ActiveReplay(document, self.profile)

    def test_unknown_fields_and_nested_duplicate_keys_are_rejected(self):
        raw = self.files["active-p3.json"].replace(b'"auxiliary":', b'"auxiliary":')
        for replacement in (
            b'"schema": "duplicate", "schema":',
            b'"context": {}, "schema":',
        ):
            with self.assertRaises(ValueError):
                ActiveReplay.loads(
                    raw.replace(b'"schema":', replacement, 1), self.profile
                )
        document = self.document()
        document["context"]["guessed_support"] = True
        with self.assertRaisesRegex(ValueError, "fields"):
            ActiveReplay(document, self.profile)

    def test_recording_bounds_and_bad_json_are_rejected(self):
        for raw in (
            b"{",
            b"\xff",
            b"null",
            b"{}",
            b"[]",
            b"x" * (16 * 1024 * 1024 + 1),
        ):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                ActiveReplay.loads(raw, self.profile)

    def test_support_observations_have_no_implicit_available_defaults(self):
        profile = self.changed(11, lambda row: row.__setitem__(83, 0))
        document = self.document()
        replay = self.for_profile(document, profile)
        self.assertEqual(replay.available_tests(), ())
        self.assertEqual(replay.replay.position, 0)
        with self.assertRaisesRegex(ValueError, "absent"):
            replay.initialize(1)

    def test_missing_p5_data_length_fails_before_start(self):
        document = self.document("p5")
        document["context"]["did_lengths"] = {}
        replay = ActiveReplay(document, self.profile)
        with self.assertRaisesRegex(ValueError, "DID length"):
            replay.run_test(2, arguments())
        self.assertEqual(replay.replay.position, 0)

    def test_invalid_arguments_do_not_consume_start(self):
        for change in (
            {"value": True},
            {"value": -1},
            {"value": 256},
            {"auxiliary": 256},
            {"display_index": 0},
            {"button_index": 0},
            {"input_hex": "0"},
            {"input_hex": "aa"},
        ):
            replay = self.replay()
            with self.subTest(change=change), self.assertRaises(ValueError):
                replay.run_test(1, arguments(**change))
            self.assertEqual(replay.replay.position, 0)

    def test_event_schema_requires_exact_start_and_final_stop(self):
        for events in (
            [],
            [{"action": "start", "tick": 0}],
            [
                {"action": "start", "tick": True},
                {"action": "stop", "tick": 2, "initialize": False},
            ],
            [{"action": "start", "tick": 0}, {"action": "stop", "tick": 2}],
            [
                {"action": "start", "tick": 0},
                {"action": "start", "tick": 1},
                {"action": "stop", "tick": 2, "initialize": False},
            ],
        ):
            document = self.document()
            document["events"] = events
            with self.subTest(events=events), self.assertRaises(ValueError):
                ActiveReplay(document, self.profile)

    def test_native_status_failure_preserves_actual_recorded_cleanup(self):
        for family, signal in (("p3", 1), ("p5", 2)):
            document = self.document(family)
            first = document["native"]["transactions"][0]
            first.pop("response")
            first.update(status=77, partial_response="")
            replay = ActiveReplay(document, self.profile)
            with (
                self.subTest(family=family),
                self.assertRaises(NativeStatus) as failure,
            ):
                replay.run_test(signal, arguments())
            self.assertEqual(failure.exception.code, 77)
            self.assertEqual(replay.replay.remaining, 0)
            self.assertIsNone(replay.session.active)
            self.assertIsNone(replay._legacy)

    def test_cancel_before_start_performs_no_exchange(self):
        replay = self.replay(cancelled=lambda: True)
        with self.assertRaises(Cancelled):
            replay.run_test(1, arguments())
        self.assertEqual(replay.replay.position, 0)
        replay.close()

    def test_post_io_cancel_cannot_hide_and_cleanup_bypasses_cancel(self):
        for family, signal in (("p3", 1), ("p5", 2)):
            state = {"cancelled": False}
            replay = self.replay(
                family, cancelled=lambda state=state: state["cancelled"]
            )
            exchange = replay.session.exchange

            def cancel_after_exchange(ecu, request, exchange=exchange, state=state):
                reply = exchange(ecu, request)
                state["cancelled"] = True
                return reply

            replay.session.exchange = cancel_after_exchange
            with self.subTest(family=family), self.assertRaises(Cancelled):
                replay.run_test(signal, arguments())
            self.assertEqual(replay.replay.remaining, 0)
            self.assertIsNone(replay.session.active)
            self.assertIsNone(replay._legacy)

    def test_stop_failure_retains_ownership_and_close_retries_recorded_stop(self):
        document = self.document()
        document["native"]["transactions"].insert(
            1,
            {
                "ecu": "authored-ecu",
                "request": "30",
                "status": 77,
                "partial_response": "",
            },
        )
        replay = ActiveReplay(document, self.profile)
        with self.assertRaises(NativeStatus):
            replay.run_test(1, arguments())
        replay.close()
        self.assertEqual(replay.replay.remaining, 0)

    def test_report_cannot_overwrite_source_symlink_hardlink_or_existing_export(self):
        replay = ActiveReplay.load(self.root / "active-p3.json", self.profile)
        source_hash = hashlib.sha256(self.files["active-p3.json"]).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            symbolic, hard = root / "symlink.json", root / "hardlink.json"
            symbolic.symlink_to(self.root / "active-p3.json")
            os.link(self.root / "active-p3.json", hard)
            for path in (self.root / "active-p3.json", symbolic, hard):
                with self.assertRaises(FileExistsError):
                    replay.write_report(path)
            export = root / "report.json"
            replay.write_report(export)
            with self.assertRaises(FileExistsError):
                replay.write_report(export)
        self.assertEqual(
            hashlib.sha256((self.root / "active-p3.json").read_bytes()).hexdigest(),
            source_hash,
        )

    def test_sa_requires_verified_local_material_before_native_probe(self):
        with self.assertRaisesRegex(ValueError, "key-material"):
            self.replay("sa")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "authored-not-a-library"
            path.write_bytes(b"authored")
            with self.assertRaisesRegex(ValueError, "identity"):
                self.replay("sa", sa_library=path)

    def test_native_document_is_snapshotted_and_chronology_is_strict(self):
        document = self.document()
        original = copy.deepcopy(document)
        replay = ActiveReplay(document, self.profile)
        document["native"]["transactions"][0]["request"] = "ff"
        self.assertEqual(replay.run_test(1, arguments())["state"], "stopped")
        self.assertNotEqual(document, original)
        replay = self.replay()
        with self.assertRaises(BaseExceptionGroup):
            replay.run_test(1, arguments(value=6))
        self.assertEqual(replay.replay.position, 0)

    def test_execution_uses_first_native_frame_but_initial_read_requires_one(self):
        for function in (0x9D, 0x64):
            profile = self.duplicate_frame(function)
            replay = self.for_profile(self.document("p5"), profile)
            self.assertEqual(replay.run_test(2, arguments())["remaining_exchanges"], 0)
        profile = self.duplicate_frame(0xCA)
        sections = dict(profile.database.sections)
        row = bytearray(sections[68].payload)
        row[57] = 0
        sections[68] = replace(sections[68], payload=bytes(row))
        profile = replace(
            profile, database=replace(profile.database, sections=sections)
        )
        replay = self.for_profile(self.document("p5"), profile)
        self.assertEqual(replay.initialize(2)["initial_value"], 0)
        self.assertEqual(replay.replay.position, 0)
        self.assertEqual(replay.run_test(2, arguments())["remaining_exchanges"], 0)

    def test_support_probe_and_initial_reads_consume_real_captured_pdus(self):
        document = self.document("p5")
        document["context"]["protocol"] = 0
        document["native"]["transactions"].insert(
            0, {"ecu": "authored-ecu", "request": "221234", "response": "62123480"}
        )
        replay = ActiveReplay(document, self.profile)
        replay.available_tests()
        self.assertEqual(replay.replay.position, 1)
        self.assertEqual(replay.run_test(2, arguments())["remaining_exchanges"], 0)
        for family in ("p3", "p4"):

            def read_mode(row):
                row[84] = 1
                struct.pack_into("<H", row, 58, 1)

            profile = self.changed(11, read_mode)
            document = self.document(family)
            document["context"]["positions"] = {"0c": "0101"}
            document["native"]["transactions"].insert(
                0, {"ecu": "authored-ecu", "request": "010c", "response": "410c0014"}
            )
            replay = self.for_profile(document, profile)
            self.assertEqual(replay.initialize(1)["initial_value"], 5)
            self.assertEqual(replay.replay.position, 1)
            self.assertEqual(replay.run_test(1, arguments())["remaining_exchanges"], 0)

    def test_repeat_deadline_rearms_then_sends_and_dk_terminal_does_not_repeat(self):
        for family, signal in (("p3", 1), ("p5", 2)):
            document = self.document(family)
            document["native"]["transactions"].insert(
                1, copy.deepcopy(document["native"]["transactions"][0])
            )
            document["events"][1:1] = [
                {"action": "step", "tick": tick} for tick in (199, 200, 201)
            ]
            document["events"][-1]["tick"] = 400
            replay = ActiveReplay(document, self.profile)
            result = replay.run_test(signal, arguments())
            self.assertEqual(result["remaining_exchanges"], 0)
            self.assertEqual(
                [len(event["replies_hex"]) for event in result["events"]],
                [1, 0, 0, 1, 1],
            )
            self.assertEqual(result["native_queue"][-1]["state"], 5)
        document = self.document("dk")
        document["events"].insert(1, {"action": "step", "tick": 150})
        replay = ActiveReplay(document, self.profile)
        self.assertEqual(replay.run_test(1, arguments())["remaining_exchanges"], 0)

    def test_special_protocol_length_is_selected_table_maximum(self):
        document = self.document("p5")
        document["context"]["protocol"] = 0x35
        document["context"]["did_lengths"] = {}
        profile = self.profile
        replay = ActiveReplay(document, profile)
        self.assertEqual(replay.run_test(2, arguments())["remaining_exchanges"], 0)

    def test_protocol_key_does_not_alias_low_byte(self):
        document = self.document()
        document["context"]["bus_id"] = 257
        with self.assertRaisesRegex(ValueError, "ProtInfo"):
            ActiveReplay(document, self.profile)

    def test_routine_byte_mask_and_failure_reply_bounds(self):
        replay = self.replay("routine")
        initialized = replay.initialize(3)
        self.assertEqual(initialized["input_byte_count"], 1)
        self.assertEqual(initialized["button_byte_count"], 0)
        for value in ("0102", "zz"):
            with self.assertRaises(ValueError):
                replay.run_test(3, arguments(input_hex=value))
        document = self.document("routine")
        document["native"]["transactions"][2]["response"] = "71034321"
        replay = ActiveReplay(document, self.profile)
        with self.assertRaisesRegex(Exception, "routine status reply is invalid"):
            replay.run_test(3, arguments())
        self.assertEqual(replay.replay.remaining, 0)

    def test_normal_routine_status_uses_native_byte_comparison_and_observed_prefix(
        self,
    ):
        reference = struct.unpack_from(
            "<H", self.profile.database.sections[72].payload, 2
        )[0]
        profile = self.variable(self.profile, reference, bytes.fromhex("010203"))
        document = self.document("routine")
        for index in (0, 2):
            document["native"]["transactions"][index]["response"] = "71034321010203"
        replay = self.for_profile(document, profile)
        report = replay.run_test(3, arguments())
        status = next(
            event["routine_status"]
            for event in report["events"]
            if "routine_status" in event
        )
        self.assertEqual(status[0]["size"], 3)
        self.assertFalse(status[0]["normal"])
        self.assertIn(
            "routine_status_unmatched",
            [event.get("state") for event in report["events"]],
        )
        document = self.document("routine")
        document["context"]["routine_info"] = True
        document["native"]["transactions"][2]["response"] = "710343210001"
        replay = self.for_profile(document, self.profile)
        report = replay.run_test(3, arguments())
        status = next(
            event["routine_status"]
            for event in report["events"]
            if "routine_status" in event
        )
        self.assertTrue(status[0]["normal"])
        document = self.document("routine")
        del document["context"]["routine_info"]
        with self.assertRaisesRegex(ValueError, "observed routine-info"):
            ActiveReplay(document, self.profile)

    def test_normal_routine_status_checks_abnormal_group_independently(self):
        profile = self.changed(71, lambda row: struct.pack_into("<H", row, 48, 2))
        sections = {
            key: (section.count, section.payload)
            for key, section in profile.database.sections.items()
        }
        command_reference = struct.unpack_from(
            "<H", profile.database.sections[71].payload, 40
        )[0]
        count, payload = sections[72]
        sections[72] = (
            count + 1,
            payload + struct.pack("<6H", 2, command_reference, 1, 0, 0, 0),
        )
        profile = replace(profile, database=parse_database(_ddb(2, sections)))
        document = self.document("routine")
        document["native"]["transactions"][2]["response"] = "71034321a0"
        replay = self.for_profile(document, profile)
        report = replay.run_test(3, arguments())
        status = next(
            event["routine_status"]
            for event in report["events"]
            if "routine_status" in event
        )
        self.assertEqual((status[0]["normal"], status[0]["abnormal"]), (False, True))
        self.assertIn(
            "abnormal_pattern_matched",
            [event.get("state") for event in report["events"]],
        )

    def test_dual_normal_routine_two_byte_status_is_big_endian(self):
        reference = struct.unpack_from(
            "<H", self.profile.database.sections[72].payload, 2
        )[0]
        profile = self.variable(self.profile, reference, b"\x01\x02")
        document = self.document("routine")
        document["context"]["driver"] = "dual"
        for index in (0, 2):
            document["native"]["transactions"][index]["response"] = "710343210102"
        replay = self.for_profile(document, profile)
        report = replay.run_test(3, arguments())
        status = next(
            event["routine_status"]
            for event in report["events"]
            if "routine_status" in event
        )
        self.assertEqual((status[0]["normal"], status[0]["size"]), (True, 2))
        queue = replay._queue
        assert isinstance(queue, P5ActiveQueue)
        self.assertEqual(queue.last_comm_time, 200)

    def test_normal_routine_missing_selected_button_group_fails_before_start(self):
        sections = {
            key: (section.count, section.payload)
            for key, section in self.profile.database.sections.items()
        }
        sections[73] = (0, b"")
        profile = replace(self.profile, database=parse_database(_ddb(2, sections)))
        replay = self.for_profile(self.document("routine"), profile)
        with self.assertRaisesRegex(ValueError, "button group is empty"):
            replay.run_test(3, arguments())
        self.assertEqual(replay.replay.position, 1)
        self.assertIsNone(replay.session.active)

    def test_normal_routine_status_native_failure_consumes_actual_release(self):
        document = self.document("routine")
        event = document["native"]["transactions"][2]
        event.pop("response")
        event.update(status=77, partial_response="7103")
        replay = ActiveReplay(document, self.profile)
        with self.assertRaises(NativeStatus) as failure:
            replay.run_test(3, arguments())
        self.assertEqual(failure.exception.code, 77)
        self.assertEqual(replay.replay.remaining, 0)
        self.assertEqual(replay.report()["state"], "failed-cleaned-up")
        document = self.document("routine")
        document["context"]["routine_info"] = None
        with self.assertRaisesRegex(ValueError, "must be boolean"):
            ActiveReplay(document, self.profile)

    def test_special_routine_status_expands_actual_selected_child_rids(self):
        for version12, signal in (
            (False, 0x9C42),
            (False, 0x9C46),
            (False, 0x9C49),
            (True, 0x9C42),
            (True, 0x9C49),
        ):
            with self.subTest(version12=version12, signal=signal):
                profile = self.version12_profile() if version12 else self.profile
                reference = struct.unpack_from(
                    "<H", profile.database.sections[72].payload, 2
                )[0]
                profile = self.variable(profile, reference, b"\x03")
                sections = {
                    key: (section.count, section.payload)
                    for key, section in profile.database.sections.items()
                }
                source = profile.database.sections[71].payload
                keys = (
                    (signal - 2, signal - 1)
                    if not (version12 and signal == 0x9C49)
                    else ()
                )
                rows = []
                for index, key in enumerate((*keys, signal)):
                    row = bytearray(source)
                    struct.pack_into(
                        "<HH", row, 28, 0x5100 + index if key != signal else 0x5000, key
                    )
                    struct.pack_into("<H", row, 46 if version12 else 48, 1)
                    rows.append(bytes(row))
                sections[71] = (
                    len(rows),
                    b"".join(
                        sorted(
                            rows, key=lambda row: struct.unpack_from("<H", row, 30)[0]
                        )
                    ),
                )
                raw = bytearray(_ddb(2, sections))
                struct.pack_into("<I", raw, 28, profile.database.version)
                profile = replace(profile, database=parse_database(bytes(raw)))
                document = self.document("routine")
                initial, start, status, stop = document["native"]["transactions"]
                initial.update(request="31035000", response="7103500003")
                start.update(request="31015000a5", response="7101")
                stop.update(request="31025000", response="7102")
                status_events = []
                for index, _ in enumerate(keys or (signal,)):
                    rid = 0x5100 + index if keys else 0x5000
                    status_events.append(
                        dict(
                            status,
                            request=f"3103{rid:04x}",
                            response=f"7103{rid:04x}03",
                        )
                    )
                document["native"]["transactions"] = [
                    initial,
                    start,
                    *status_events,
                    stop,
                ]
                replay = self.for_profile(document, profile)
                report = replay.run_test(signal, arguments())
                states = next(
                    event["routine_status"]
                    for event in report["events"]
                    if "routine_status" in event
                )
                self.assertEqual(len(states), len(keys) or 1)
                self.assertEqual(states[0]["stop_pattern"], bool(keys))
                if keys:
                    self.assertFalse(states[0]["normal"])
                    self.assertFalse(states[1]["stop_pattern"])

    def test_close_racing_running_exchange_cancels_and_consumes_actual_stop(self):
        replay = self.replay()
        entered, release, closing = (
            threading.Event(),
            threading.Event(),
            threading.Event(),
        )
        exchange = replay.session.exchange
        failures = []

        def blocked(ecu, request):
            if request != b"\x30":
                entered.set()
                if not release.wait(2):
                    raise TimeoutError("Authored replay synchronization timeout")
            return exchange(ecu, request)

        def execute():
            try:
                replay.run_test(1, arguments())
            except Cancelled as error:
                failures.append(error)

        def close():
            closing.set()
            replay.close()

        replay.session.exchange = blocked
        runner = threading.Thread(target=execute)
        closer = threading.Thread(target=close)
        runner.start()
        self.assertTrue(entered.wait(2))
        closer.start()
        self.assertTrue(closing.wait(2))
        self.assertTrue(replay._closing.wait(2))
        release.set()
        runner.join(2)
        closer.join(2)
        self.assertFalse(runner.is_alive())
        self.assertFalse(closer.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertEqual(replay.replay.remaining, 0)
        self.assertTrue(replay._closed)


if __name__ == "__main__":
    unittest.main()
