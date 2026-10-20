import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.demo import create_demo
from scripts.diagnostic_db import DiagnosticCatalog
from scripts.profiles import VehicleCatalog
from scripts.support import check_pid_support
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
                vehicles = VehicleCatalog(root / f"Techstream_DB_{code}")
                self.assertEqual(
                    [
                        definition["categories"][2]["name"]
                        for definition in vehicles.vehicle_definitions
                    ],
                    ["2024", "2025"],
                )
                pending = vehicles.resolve_vehicle(0)
                self.assertEqual(pending["status"], "needs_option")
                self.assertEqual(
                    [choice["name"] for choice in pending["choices"]],
                    ["Automatic", "Manual"],
                )
                selected = vehicles.resolve_vehicle(0, (1,))
                self.assertEqual(selected["vehicle_name_key"], 10001)
                systems = vehicles.vehicle_systems(selected["vehicle_name_key"])
                self.assertEqual(systems[0]["file"], "DemoEngine.ddb")
                profile = vehicles.build_profile(
                    systems[0]["category"],
                    vehicle_name_key=selected["vehicle_name_key"],
                )
                self.assertEqual(profile.command_frames(0x10)[0].request, b"\x21\0")
                self.assertEqual(profile.command_frames(0x6B)[0].request, b"\x01\x00")
                freeze = profile.records(10)[0]
                self.assertTrue(freeze[78] & 0x20)
                self.assertEqual(freeze[76], 2)
                requests = []

                def exchange(request, requests=requests):
                    requests.append(request)
                    return b"\x61\x0c\x80"

                self.assertTrue(
                    check_pid_support(
                        freeze,
                        {12: 2},
                        profile.pid_bits(),
                        profile.command_frames,
                        exchange,
                    )
                )
                self.assertEqual(requests, [b"\x21\x0c"])
            before = (root / "demo-manifest.json").read_bytes()
            with self.assertRaises(FileExistsError):
                create_demo(root)
            self.assertEqual((root / "demo-manifest.json").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
