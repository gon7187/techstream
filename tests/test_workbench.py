import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_pid_catalog import catalog_bytes

from scripts.workbench import (
    CatalogIndex,
    catalog_roots,
    export_csv,
    load_saved,
    measurement_text,
    save_saved,
    usb_devices,
)


class WorkbenchTests(unittest.TestCase):
    def test_measurement_display_preserves_zero_and_rounds_only_for_ui(self):
        self.assertEqual(
            measurement_text({"name": "engine_speed", "value": 800.0, "unit": "rpm"}),
            ("Частота вращения двигателя", "800 об/мин"),
        )
        self.assertEqual(
            measurement_text(
                {"name": "throttle_position", "value": 12.549019607843137, "unit": "%"}
            )[1],
            "12.55 %",
        )
        self.assertEqual(
            measurement_text({"name": "unknown_signal", "value": 0.0, "unit": ""}),
            ("unknown signal", "0"),
        )

    def test_region_discovery_does_not_require_north_america(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            eu = root / "Techstream_Data_EU" / "PIDGroup"
            jp = root / "Techstream_Data_JP" / "PIDGroup"
            eu.mkdir(parents=True)
            jp.mkdir(parents=True)
            self.assertEqual(catalog_roots(root), {"EU": eu, "JP": jp})
            self.assertEqual(catalog_roots(jp), {"EU": eu, "JP": jp})
            custom = root / "custom"
            custom.mkdir()
            self.assertEqual(catalog_roots(custom), {"custom": custom})

    def test_index_search_and_bad_group(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Air.CT").write_bytes(catalog_bytes())
            (root / "Broken.CT").write_bytes(b"bad source")
            index = CatalogIndex(root)
            self.assertEqual(index.record_count, 1)
            self.assertEqual(index.search("RPM engine")[0]["name"], "Engine SPD")
            self.assertEqual(index.search("missing"), [])
            self.assertEqual(index.search("", "Air.CT")[0]["group"], "Air.CT")
            self.assertEqual(index.search("engine", "missing.CT"), [])
            self.assertIn("Broken.CT", index.errors)
            self.assertEqual(len(index.groups["Air.CT"]["sha256"]), 64)
            with self.assertRaises(OSError):
                CatalogIndex(root / "missing")

    def test_saved_roundtrip_and_corruption_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "state" / "saved.json"
            self.assertEqual(load_saved(path), {})
            saved = {"/source/NA": ["Brand/1/Air.CT"], "/source/EU": ["Other.CT"]}
            save_saved(path, saved)
            self.assertEqual(load_saved(path), saved)
            for invalid in ("{", "[]", '{"root": [12]}', '{"root": ["../escape.CT"]}'):
                path.write_text(invalid)
                with self.assertRaises(ValueError):
                    load_saved(path)
                self.assertEqual(path.read_text(), invalid)

    def test_failed_atomic_save_keeps_existing_state(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "saved.json"
            save_saved(path, {"root": ["Air.CT"]})
            with (
                patch("scripts.workbench.os.replace", side_effect=OSError("disk full")),
                self.assertRaises(OSError),
            ):
                save_saved(path, {})
            self.assertEqual(load_saved(path), {"root": ["Air.CT"]})
            self.assertEqual(list(Path(temp).iterdir()), [path])

    def test_csv_is_real_data_with_spreadsheet_formula_protection(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "records.csv"
            records = [
                {
                    "group": "A, B.CT",
                    "name": "=1+2",
                    "unit": "rpm",
                    "short_name": "a\nb",
                    "metadata_hex": "00",
                    "sha256": "abc",
                }
            ]
            export_csv(path, records)
            with path.open(encoding="utf-8-sig", newline="") as source:
                rows = list(csv.DictReader(source))
            self.assertEqual(rows[0]["group"], "A, B.CT")
            self.assertEqual(rows[0]["name"], "'=1+2")
            self.assertEqual(rows[0]["short_name"], "a\nb")
            self.assertEqual(rows[0]["sha256"], "abc")

    def test_passive_usb_inventory_does_not_identify_unknown_adapter(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            device = root / "1-2"
            device.mkdir()
            for name, value in {
                "idVendor": "18e1",
                "idProduct": "0100",
                "manufacturer": "Drew Technologies",
                "product": "Mongoose",
            }.items():
                (device / name).write_text(value)
            (root / "1-2:1.0").mkdir()
            result = usb_devices(root)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["id"], "18e1:0100")
            self.assertTrue(result[0]["candidate"])
            (device / "idProduct").write_text("0104")
            self.assertEqual(usb_devices(root)[0]["model"], "MongoosePro JLR")
            (device / "idProduct").write_text("018b")
            self.assertFalse(usb_devices(root)[0]["candidate"])
            self.assertEqual(usb_devices(root / "missing"), [])


if __name__ == "__main__":
    unittest.main()
