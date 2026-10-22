import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from scripts import native_inventory, offline_verify
from scripts.offline_verify import OBSERVATIONS, SOFTWARE, validate_coverage


def document():
    return {
        "schema": "techstream-no-car-coverage-v1",
        "unresolved_software": [],
        "operations": [
            {
                "id": key,
                "status": "PHYSICAL_UNCONFIRMED"
                if key in OBSERVATIONS
                else "implemented",
                "implementation": [{"path": "implementation.py", "symbol": "execute"}],
                "tests": ["test_control.Control.test_executes"],
                "evidence": ["evidence.md"],
                "remaining": "Requires hardware observation"
                if key in OBSERVATIONS
                else "",
            }
            for key in sorted(SOFTWARE | OBSERVATIONS)
        ],
    }


class OfflineGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "tests").mkdir()
        (self.root / "implementation.py").write_text("def execute():\n    return 42\n")
        (self.root / "tests/test_control.py").write_text(
            "class Control:\n    def test_executes(self):\n        assert True\n"
        )
        (self.root / "evidence.md").write_text("Reviewed synthetic positive control\n")

    def test_positive_control_and_every_pending_operation_fails(self):
        self.assertEqual(
            validate_coverage(document(), self.root),
            ["test_control.Control.test_executes"],
        )
        for key in SOFTWARE:
            candidate = document()
            next(row for row in candidate["operations"] if row["id"] == key)[
                "status"
            ] = "open"
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "gate OPEN"):
                validate_coverage(candidate, self.root)

    def test_cannot_drop_relabel_or_hide_unknown_software(self):
        candidate = document()
        candidate["operations"].pop()
        with self.assertRaises(ValueError):
            validate_coverage(candidate, self.root)
        candidate = document()
        candidate["operations"][0]["id"] = "hardware.software_problem"
        with self.assertRaises(ValueError):
            validate_coverage(candidate, self.root)
        candidate = document()
        candidate["unresolved_software"] = ["Unresolved native action"]
        with self.assertRaisesRegex(ValueError, "gate OPEN"):
            validate_coverage(candidate, self.root)

    def test_completion_runs_canonical_native_claims_and_their_exact_tests(self):
        registry = self.root / "coverage.json"
        registry.write_text("{}")
        with (
            patch.object(offline_verify, "REGISTRY", registry),
            patch.object(
                offline_verify, "validate_coverage", return_value=["coarse.test"]
            ),
            patch.object(
                native_inventory, "load_manifest", return_value={"source": "pinned"}
            ),
            patch.object(
                native_inventory,
                "validate_manifest",
                return_value={"tests": ["native.test", "coarse.test"]},
            ) as validate,
            patch.object(offline_verify, "_suite") as suite,
            patch("sys.argv", ["offline_verify", "coverage"]),
            redirect_stdout(StringIO()) as output,
        ):
            self.assertEqual(offline_verify.main(), 0)
        validate.assert_called_once_with(
            {"source": "pinned"},
            root=offline_verify.ROOT,
            required_contracts=native_inventory.CANONICAL_REQUIRED_CONTRACTS,
            require_complete=True,
        )
        suite.assert_called_once_with(["coarse.test", "native.test"])
        self.assertIn("OFFLINE_COVERAGE_PASSED", output.getvalue())

    def test_native_open_claims_block_even_a_complete_coarse_registry(self):
        registry = self.root / "coverage.json"
        registry.write_text("{}")
        with (
            patch.object(offline_verify, "REGISTRY", registry),
            patch.object(
                offline_verify, "validate_coverage", return_value=["coarse.test"]
            ),
            patch.object(offline_verify, "_suite") as suite,
            patch("sys.argv", ["offline_verify", "coverage"]),
            redirect_stdout(StringIO()) as output,
            redirect_stderr(StringIO()) as errors,
        ):
            self.assertEqual(offline_verify.main(), 1)
        suite.assert_not_called()
        self.assertNotIn("OFFLINE_COVERAGE_PASSED", output.getvalue())
        self.assertIn("OPEN", errors.getvalue())

    def test_claim_requires_real_symbols_tests_and_no_path_escape(self):
        for field, value in (
            ("implementation", []),
            ("tests", []),
            ("evidence", []),
            ("remaining", "Still unknown"),
        ):
            candidate = document()
            row = next(row for row in candidate["operations"] if row["id"] in SOFTWARE)
            row[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_coverage(candidate, self.root)
        (self.root / "implementation.py").write_text("def execute():\n    ...\n")
        with self.assertRaisesRegex(ValueError, "placeholder"):
            validate_coverage(document(), self.root)
        for body in (
            "raise NotImplementedError('unknown native behavior')",
            "return NotImplemented",
        ):
            (self.root / "implementation.py").write_text(
                f"def execute():\n    {body}\n"
            )
            with (
                self.subTest(body=body),
                self.assertRaisesRegex(ValueError, "unimplemented"),
            ):
                validate_coverage(document(), self.root)
        (self.root / "implementation.py").write_text("def execute():\n    return 1\n")
        candidate = document()
        next(row for row in candidate["operations"] if row["id"] in SOFTWARE)[
            "implementation"
        ][0]["path"] = "../escape.py"
        with self.assertRaises(ValueError):
            validate_coverage(candidate, self.root)


if __name__ == "__main__":
    unittest.main()
