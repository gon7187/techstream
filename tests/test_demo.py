import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.demo import create_demo
from scripts.diagnostic_db import DiagnosticCatalog
from scripts.workbench import CatalogIndex, catalog_roots


class DemoTests(unittest.TestCase):
    def test_source_only_demo_roundtrip_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = create_demo(Path(temporary) / "demo")
            manifest = json.loads((root / "demo-manifest.json").read_text())
            self.assertTrue(manifest["synthetic"])
            for name, digest in manifest["files"].items():
                self.assertEqual(
                    hashlib.sha256((root / name).read_bytes()).hexdigest(), digest
                )
            regions = catalog_roots(root)
            self.assertEqual(set(regions), {"NA", "EU", "JP"})
            for code, path in regions.items():
                index = CatalogIndex(path)
                self.assertEqual(index.record_count, 6)
                self.assertEqual(len(index.search("engine rpm")), 2)
                catalog = DiagnosticCatalog(root / f"Techstream_DB_{code}")
                self.assertEqual(len(catalog.systems), 1)
                db = catalog.read_system("DemoEngine.ddb")
                self.assertEqual(
                    db.named_records(5, catalog.language)[0]["code"], "P0300"
                )
                self.assertEqual(db.signal_variants(0)[0]["divisor"], 4)
            before = (root / "demo-manifest.json").read_bytes()
            with self.assertRaises(FileExistsError):
                create_demo(root)
            self.assertEqual((root / "demo-manifest.json").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
