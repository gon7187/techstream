"""Authored text pools, malformed sources and source-bound lookup controls."""

import hashlib
import os
import struct
import tempfile
import unittest
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from scripts.demo import _ddb, _language
from scripts.diagnostic_db import parse_database
from scripts.text_resources import TextResources


class TextResourcesTests(unittest.TestCase):
    def test_order_duplicates_unicode_and_source_provenance(self):
        data = _language(["Authored caution\nStop first", "Клапан 日本語", ""])
        table = TextResources(data, namespace="management")
        values = table.translate([2, 1, 2, 3])
        self.assertEqual(
            [v.text for v in values],
            ["Клапан 日本語", "Authored caution\nStop first", "Клапан 日本語", ""],
        )
        report = values[0].report()
        self.assertEqual(report["source_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(report["encoding"], "utf-16le")
        self.assertEqual(report["namespace"], "management")
        report["text"] = "forged"
        self.assertEqual(table.resolve(2).text, "Клапан 日本語")

    def test_wide_c_string_ends_at_first_nul(self):
        self.assertEqual(
            TextResources(_language(["First\0Hidden"]), namespace="management")
            .resolve(1)
            .text,
            "First",
        )

    def test_empty_pool_and_native_zero_id_rejection(self):
        table = TextResources(_language([]), namespace="management")
        self.assertEqual(table.translate([]), ())
        for value in (0, 1, -1, True, 1.0, "1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                table.resolve(cast(Any, value))

    def test_namespace_and_source_sha_are_explicit(self):
        data = _language(["Authored"])
        for namespace in ("viewer", "utility", "M_English", ""):
            with self.assertRaises(ValueError):
                TextResources(data, namespace=namespace)
        for expected in ("0" * 64, "G" * 64, "A" * 64, "short", 3):
            with self.assertRaises(ValueError):
                TextResources(
                    data, namespace="management", expected_sha256=cast(Any, expected)
                )
        digest = hashlib.sha256(data).hexdigest()
        self.assertEqual(
            TextResources(
                data, namespace="legacy", expected_sha256=digest
            ).source_sha256,
            digest,
        )

    def test_wrong_kind_and_extra_sections_rejected(self):
        for data in (
            _ddb(5, {0: (0, b"")}),
            _ddb(6, {0: (0, b"")}),
            _ddb(4, {0: (0, b""), 1: (0, b"")}),
        ):
            with self.assertRaises(ValueError):
                TextResources(data, namespace="management")

    def test_index_pool_and_encoding_faults(self):
        cases = [
            (1, b""),
            (1, struct.pack("<IH", 1, 2) + b"\0\0"),
            (1, struct.pack("<IH", 0, 3) + b"x\0\0"),
            (1, struct.pack("<IH", 0, 4) + b"\0\0"),
            (1, struct.pack("<IH", 0, 2) + b"x\0"),
            (1, struct.pack("<IH", 0, 4) + b"\x00\xd8\0\0"),
            (0, b"trailing"),
        ]
        for count, payload in cases:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                TextResources(_ddb(4, {0: (count, payload)}), namespace="management")

    def test_inputs_and_aggregate_list_bound(self):
        with self.assertRaises(ValueError):
            TextResources(cast(Any, bytearray()), namespace="management")
        table = TextResources(_language(["Text"]), namespace="management")
        for ids in ([1] * 4097, "1", [1, 0]):
            with self.assertRaises(ValueError):
                table.translate(cast(Any, ids))

    def test_record_count_guard_precedes_materialization(self):
        with (
            patch("scripts.text_resources.MAX_RECORDS", 1),
            self.assertRaises(ValueError),
        ):
            TextResources(_language(["One", "Two"]), namespace="management")

    def test_aggregate_output_budget_counts_duplicate_references(self):
        table = TextResources(_language(["Authored"]), namespace="management")
        with patch("scripts.text_resources.MAX_TRANSLATION_BYTES", 10):
            self.assertEqual(len(table.translate([1])), 1)
            with self.assertRaises(ValueError):
                table.translate([1, 1])

    def test_cancellation_before_read_during_parse_and_lookup(self):
        with self.assertRaises(InterruptedError):
            TextResources.load("absent", namespace="management", cancelled=lambda: True)
        calls = 0

        def cancelled():
            nonlocal calls
            calls += 1
            return calls >= 3

        with self.assertRaises(InterruptedError):
            TextResources(
                _language(["One", "Two"]), namespace="management", cancelled=cancelled
            )
        stopped = False
        table = TextResources(
            _language(["One"]), namespace="management", cancelled=lambda: stopped
        )
        stopped = True
        with self.assertRaises(InterruptedError):
            table.resolve(1)

    def test_regular_symlink_source_preserved_and_fifo_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = _language(["Authored file"])
            source = root / "language.ddb"
            source.write_bytes(data)
            alias = root / "alias.ddb"
            alias.symlink_to(source)
            self.assertEqual(
                TextResources.load(alias, namespace="management").resolve(1).text,
                "Authored file",
            )
            self.assertEqual(source.read_bytes(), data)
            fifo = root / "fifo"
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                TextResources.load(fifo, namespace="management")


class ViewerHelpTests(unittest.TestCase):
    @staticmethod
    def language():
        data = bytearray(
            _language(
                ["Authored help", "Replacement", "Caution", "Info", "Prohibition"]
            )
        )
        data[8] = 5
        return TextResources(bytes(data), namespace="viewer")

    @staticmethod
    def viewer():
        rows = b"".join(
            struct.pack("<IIHH", text, key, kind, 0)
            for text, key, kind in [
                (1, 99, 1),
                (3, 99, 2),
                (2, 99, 1),
                (4, 99, 3),
                (5, 99, 4),
            ]
        )
        return _ddb(3, {2: (5, rows)})

    def test_authored_active_profiles_join_actual_init_ids_and_captured_workflow(self):
        import json

        from scripts.active_replay import ActiveReplay
        from scripts.profiles import VehicleCatalog
        from scripts.text_resources import (
            ViewerHelpResources,
            create_active_text_examples,
        )

        files = create_active_text_examples()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, payload in files.items():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
            source = root / "Techstream_DB_NA"
            profile = VehicleCatalog(source).build_profile(1)
            broker = ViewerHelpResources.load(
                source / "Viewer.ddb", source / "V_Example.ddb"
            )
            for family, signal in (("p3", 1), ("p5", 2), ("routine", 3)):
                replay = ActiveReplay(
                    json.loads(files[f"active-{family}.json"]), profile
                )
                initial = replay.initialize(signal)
                texts = broker.instruction_texts(initial["text_ids"])
                self.assertEqual(texts["caution"]["status"], "resolved")
                self.assertEqual(texts["help"]["id"], 2)
                details = broker.active_details(initial["control_value"])
                self.assertEqual(details["help_id"], 2)
                self.assertTrue(
                    all(part["resource"] is not None for part in details["outputs"])
                )
                self.assertEqual(
                    texts["comment"]["status"],
                    "resolved" if family == "p3" else "absent",
                )
                result = replay.run_test(
                    signal,
                    {
                        "value": 5,
                        "auxiliary": 0,
                        "display_index": None,
                        "input_hex": "",
                        "button_index": None,
                    },
                )
                self.assertEqual(
                    (result["state"], result["remaining_exchanges"]), ("stopped", 0)
                )
                replay.close()

    def test_production_authored_example_composes_all_five_roles(self):
        from scripts.text_resources import ViewerHelpResources, create_text_examples

        files = create_text_examples()
        table = ViewerHelpResources(
            files["Viewer.ddb"],
            TextResources(files["V_Example.ddb"], namespace="viewer"),
        )
        result = table.instruction_texts(
            {"caution": 1, "help": 2, "prohibition": 3, "info": 4, "comment": 5}
        )
        self.assertEqual({row["status"] for row in result.values()}, {"resolved"})
        self.assertEqual(result["help"]["presentation_policy"], "host-init-kind1")
        self.assertEqual(result["help"]["native_dialog_dispatch"], "unresolved")
        self.assertIn("Клапан 日本語", result["comment"]["resource"]["text"])

    def test_actual_help_key_and_type_join_with_last_row_override(self):
        from scripts.text_resources import ViewerHelpResources

        help = ViewerHelpResources(self.viewer(), self.language())
        self.assertEqual(cast(dict, help.resolve(99))["text"], "Replacement")
        self.assertEqual(cast(dict, help.resolve(99, kind=2))["text"], "Caution")
        self.assertEqual(cast(dict, help.resolve(99, kind=3))["text"], "Info")
        self.assertEqual(cast(dict, help.resolve(99, kind=4))["text"], "Prohibition")
        self.assertIsNone(help.resolve(100))
        result = help.resolve(99)
        assert result is not None
        self.assertEqual(result["viewer_row"], 2)
        self.assertEqual(
            result["viewer_sha256"], hashlib.sha256(self.viewer()).hexdigest()
        )
        result["text"] = "forged"
        self.assertEqual(cast(dict, help.resolve(99))["text"], "Replacement")

    def test_native_active_details_preserve_three_output_kinds_and_last_match(self):
        from scripts.text_resources import ViewerHelpResources

        payload = bytearray(_language(["A", "B", "C", "D"]))
        payload[8] = 5
        language = TextResources(bytes(payload), namespace="viewer")
        rows = b"".join(
            struct.pack("<IIHH", index, 99, kind, 0)
            for index, kind in ((1, 2), (2, 3), (3, 4), (4, 2))
        )
        table = ViewerHelpResources(_ddb(3, {2: (4, rows)}), language)
        result = table.active_details(99)
        self.assertEqual([row["kind"] for row in result["outputs"]], [2, 4, 3])
        self.assertEqual(
            [row["resource"]["text"] for row in result["outputs"]], ["D", "C", "B"]
        )
        result["outputs"][0]["resource"]["text"] = "forged"
        self.assertEqual(
            table.active_details(99)["outputs"][0]["resource"]["text"], "D"
        )
        self.assertTrue(
            all(row["resource"] is None for row in table.active_details(100)["outputs"])
        )
        with self.assertRaises(ValueError):
            table.active_details(True)

    def test_instruction_composition_preserves_absent_missing_and_actual_text(self):
        from scripts.text_resources import ViewerHelpResources

        help = ViewerHelpResources(self.viewer(), self.language())
        ids = {"caution": 99, "help": 100, "prohibition": 0, "info": 99, "comment": 0}
        result = help.instruction_texts(ids)
        self.assertEqual(result["caution"]["resource"]["text"], "Replacement")
        self.assertEqual(result["help"]["status"], "missing")
        self.assertEqual(result["prohibition"]["status"], "absent")
        result["info"]["resource"]["text"] = "forged"
        self.assertEqual(
            help.instruction_texts(ids)["info"]["resource"]["text"], "Replacement"
        )
        with self.assertRaises(ValueError):
            help.instruction_texts({"help": 99})
        with self.assertRaises(ValueError):
            help.instruction_texts(ids | {"help": True})

    def test_namespace_missing_dependency_and_bad_row_shape(self):
        from scripts.text_resources import ViewerHelpResources

        with self.assertRaises(ValueError):
            ViewerHelpResources(
                self.viewer(),
                TextResources(_language(["Wrong pool"]), namespace="management"),
            )
        with self.assertRaises(ValueError):
            ViewerHelpResources(self.viewer(), cast(Any, None))
        for expected in (True, "short", "A" * 64):
            with self.assertRaises(ValueError):
                ViewerHelpResources(
                    self.viewer(), self.language(), expected_sha256=cast(Any, expected)
                )
        for data in (
            _ddb(3, {0: (0, b"")}),
            _ddb(2, {2: (0, b"")}),
            _ddb(3, {2: (1, b"short")}),
            _ddb(3, {2: (1, struct.pack("<IIHH", 999, 99, 1, 0))}),
        ):
            with self.assertRaises(ValueError):
                ViewerHelpResources(data, self.language())
        help = ViewerHelpResources(self.viewer(), self.language())
        for value in (True, -1, 0x100000000):
            with self.assertRaises(ValueError):
                help.resolve(value)
        for kind in (True, 0, 5):
            with self.assertRaises(ValueError):
                help.resolve(99, kind=kind)

    def test_help_group_count_cannot_wrap_native_signed_short(self):
        from scripts.text_resources import ViewerHelpResources

        row = struct.pack("<IIHH", 1, 99, 1, 0)
        with self.assertRaisesRegex(ValueError, "signed count"):
            ViewerHelpResources(_ddb(3, {2: (32768, row * 32768)}), self.language())

    def test_noncontiguous_help_keys_rejected_before_lookup(self):
        from scripts.text_resources import ViewerHelpResources

        rows = b"".join(struct.pack("<IIHH", 1, key, 1, 0) for key in (99, 100, 99))
        with self.assertRaises(ValueError):
            ViewerHelpResources(_ddb(3, {2: (3, rows)}), self.language())

    def test_load_sha_cancellation_and_original_aliases(self):
        from scripts.text_resources import ViewerHelpResources

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            viewer = root / "viewer.ddb"
            language = root / "language.ddb"
            raw = bytearray(
                _language(
                    ["Authored help", "Replacement", "Caution", "Info", "Prohibition"]
                )
            )
            raw[8] = 5
            language.write_bytes(raw)
            viewer.write_bytes(self.viewer())
            help = ViewerHelpResources.load(
                viewer,
                language,
                viewer_sha256=hashlib.sha256(self.viewer()).hexdigest(),
                language_sha256=hashlib.sha256(raw).hexdigest(),
            )
            self.assertEqual(cast(dict, help.resolve(99))["text"], "Replacement")
            with self.assertRaises(ValueError):
                ViewerHelpResources.load(viewer, viewer)
            with self.assertRaises(ValueError):
                ViewerHelpResources.load(viewer, language, viewer_sha256="0" * 64)
            with self.assertRaises(InterruptedError):
                ViewerHelpResources.load(viewer, language, cancelled=lambda: True)
            self.assertEqual(viewer.read_bytes(), self.viewer())


class UtilityTextResourcesTests(unittest.TestCase):
    @staticmethod
    def source(rows=None):
        rows = rows or [("IDS_AUTHORED", "", 1)]
        pool = parse_database(_language(["Authored utility", "Second"])).sections[0]

        def field(value):
            return (value + "\0").encode("utf-16le").ljust(80, b"\0")

        records = b"".join(
            field(a) + field(b) + struct.pack("<I", i) for a, b, i in rows
        )
        return _ddb(6, {0: (pool.count, pool.payload), 1: (len(rows), records)})

    @staticmethod
    def symbols(rows=None):
        result = b""
        for group, identifier, key in rows or [(20000, 7, "IDS_AUTHORED")]:
            value = key.encode("utf-16le")
            result += struct.pack("<IIH", group, identifier, len(value)) + value
        return result

    def test_actual_symbol_to_first_primary_key_and_provenance(self):
        from scripts.text_resources import UtilityTextResources

        data = self.source([("IDS_AUTHORED", "A", 1), ("IDS_AUTHORED", "B", 2)])
        broker = UtilityTextResources(data, self.symbols(), utility_group=123)
        report = broker.resolve(7)
        self.assertEqual(report["text"], "Authored utility")
        self.assertEqual(report["status"], "resolved")
        self.assertEqual(
            report["resource"]["source_sha256"], hashlib.sha256(data).hexdigest()
        )
        self.assertEqual(report["resource"]["namespace"], "utility")
        self.assertEqual(report["row_index"], 0)
        report["resource"]["text"] = "forged"
        self.assertEqual(broker.resolve(7)["text"], "Authored utility")

    def test_selected_groups_file_order_overwrite_and_missing(self):
        from scripts.text_resources import UtilityTextResources

        rows = [
            (20000, 7, "IDS_AUTHORED"),
            (123, 7, "IDS_SECOND"),
            (999, 8, "IDS_AUTHORED"),
        ]
        broker = UtilityTextResources(
            self.source([("IDS_SECOND", "", 2)]), self.symbols(rows), utility_group=123
        )
        self.assertEqual(broker.resolve(7)["text"], "Second")
        self.assertEqual(broker.resolve(7)["symbol_group"], 123)
        self.assertEqual(broker.resolve(8)["status"], "missing_symbol")
        missing = UtilityTextResources(
            self.source(), self.symbols([(123, 7, "IDS_MISSING")]), utility_group=123
        )
        self.assertEqual(missing.resolve(7)["status"], "missing_key")
        self.assertEqual(missing.resolve(7)["text"], "")

    def test_validation_cancellation_hashes_and_regular_load(self):
        from scripts.text_resources import UtilityTextResources

        for invalid in (
            b"x",
            struct.pack("<IIH", 20000, 7, 3) + b"abc",
            self.symbols() + b"x",
        ):
            with self.assertRaises(ValueError):
                UtilityTextResources(self.source(), invalid, utility_group=123)
        with self.assertRaises(ValueError):
            UtilityTextResources(self.source(), self.symbols(), utility_group=True)
        with self.assertRaises(ValueError):
            UtilityTextResources(
                self.source(), self.symbols(), utility_group=1, symbols_sha256="0" * 64
            )
        with self.assertRaises(InterruptedError):
            UtilityTextResources(
                self.source(), self.symbols(), utility_group=1, cancelled=lambda: True
            )
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory) / "U.ddb"
            symbols = Path(directory) / "ids.rsd"
            data.write_bytes(self.source())
            symbols.write_bytes(self.symbols())
            self.assertEqual(
                UtilityTextResources.load(data, symbols, utility_group=123).resolve(7)[
                    "status"
                ],
                "resolved",
            )
        broker = UtilityTextResources(self.source(), self.symbols(), utility_group=1)
        for invalid in (True, -1, 2**32, "7"):
            with self.assertRaises(ValueError):
                broker.resolve(cast(Any, invalid))

    def test_source_key_and_symbol_native_cstring_semantics(self):
        from scripts.text_resources import UtilityTextResources

        # TY2 uses the UTF16 low bytes; U-language keys end at the first wide NUL.
        symbols = self.symbols([(123, 7, "IDS_AUTHORED\0IGNORED")])
        broker = UtilityTextResources(self.source(), symbols, utility_group=123)
        self.assertEqual(broker.resolve(7)["status"], "resolved")
        lower = UtilityTextResources(
            self.source(), self.symbols([(123, 7, "ids_authored")]), utility_group=123
        )
        self.assertEqual(lower.resolve(7)["status"], "missing_key")
        reverse = UtilityTextResources(
            self.source([("IDS_COMMON", "", 1)]),
            self.symbols([(123, 7, "IDS_OTHER"), (20000, 7, "IDS_COMMON")]),
            utility_group=123,
        )
        self.assertEqual(reverse.resolve(7)["symbol_group"], 20000)
        for data in (
            self.source([("IDS_КЛЮЧ", "", 1)]),
            self.source([("IDS_AUTHORED", "", 99)]),
            self.source([("A", "", 1), ("B", "", 1), ("A", "", 1)]),
        ):
            with self.assertRaises(ValueError):
                UtilityTextResources(data, self.symbols(), utility_group=123)

    def test_owned_authored_examples_and_lookup_cancellation(self):
        from scripts.text_resources import (
            UtilityTextResources,
            create_utility_text_examples,
        )

        files = create_utility_text_examples()
        cancel = [False]
        broker = UtilityTextResources(
            files["U_Example.ddb"],
            files["UtilityResID_NK.rsd"],
            utility_group=4934,
            cancelled=lambda: cancel[0],
        )
        self.assertEqual(
            [broker.resolve(i)["status"] for i in range(0x94B5, 0x94BD)],
            ["resolved"] * 8,
        )
        self.assertEqual(broker.resolve(0x1043)["text"], "Authored acknowledge")
        self.assertEqual(broker.resolve(0x1043)["symbol_group"], 20000)
        cancel[0] = True
        with self.assertRaises(InterruptedError):
            broker.resolve(0x94B5)
        with (
            patch("scripts.text_resources.MAX_RECORDS", 1),
            self.assertRaises(ValueError),
        ):
            UtilityTextResources(
                files["U_Example.ddb"], files["UtilityResID_NK.rsd"], utility_group=4934
            )
