"""Controls for the explicit private-evidence skip boundary."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import private_evidence
from tests.private_evidence import (
    read_private_bytes,
    read_private_json,
    read_private_text,
    require_private,
)


class PrivateEvidenceTests(unittest.TestCase):
    def test_missing_private_path_skips_with_precise_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "analysis/evidence/no-car-999/absent.json"
            with patch.object(private_evidence, "_REPO_ROOT", root, create=True):
                with self.assertRaises(unittest.SkipTest) as caught:
                    require_private(missing)
                self.assertIn("Private OEM evidence unavailable", str(caught.exception))
                self.assertIn("no-car-999", str(caught.exception))

    def test_non_private_path_is_rejected_instead_of_silently_skipped(self):
        with self.assertRaises(AssertionError):
            require_private("README.md")

    def test_readers_return_exact_private_bytes_text_and_json(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            evidence = repo / "analysis/evidence/no-car-999"
            evidence.mkdir(parents=True)
            binary = evidence / "sample.bin"
            binary.write_bytes(b"\x00\xffprivate")
            text = evidence / "sample.json"
            text.write_text(json.dumps({"value": 7}), encoding="utf-8")

            with patch.object(private_evidence, "_REPO_ROOT", repo, create=True):
                self.assertEqual(read_private_bytes(binary), b"\x00\xffprivate")
                self.assertEqual(read_private_text(text), '{"value": 7}')
                self.assertEqual(read_private_json(text), {"value": 7})


class PrivateEvidenceBoundaryTests(unittest.TestCase):
    def assert_rejected_without_skip(self, path: Path) -> None:
        try:
            require_private(path)
        except unittest.SkipTest as error:
            self.fail(f"public path was converted into a skip: {error}")
        except AssertionError:
            return
        self.fail("public path was accepted as private evidence")

    def test_accepts_only_repository_private_roots(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(private_evidence, "_REPO_ROOT", root, create=True):
                for path in (
                    root / "analysis/evidence/missing.json",
                    root / "artifacts/vendor/missing.bin",
                    root / ".unlazy/state/missing.json",
                    root / "runtime/no-car-42/recovered/missing.dll",
                ):
                    with self.subTest(path=path):
                        self.assertTrue(private_evidence._is_private(path))

    def test_public_component_names_do_not_make_paths_private(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = (
                root / "fixtures/analysis/missing.json",
                root / "tests/analysis/missing.json",
                root / "runtime/unrelated/no-car-fake/missing.json",
                root / "public/missing.json",
            )
            with patch.object(private_evidence, "_REPO_ROOT", root, create=True):
                for path in paths:
                    with self.subTest(path=path):
                        self.assert_rejected_without_skip(path)

    def test_traversal_that_normalizes_to_public_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public = root / "tests/fixtures/missing.json"
            traversed = root / "analysis/../tests/fixtures/missing.json"
            with patch.object(private_evidence, "_REPO_ROOT", root, create=True):
                self.assert_rejected_without_skip(traversed)
                self.assertFalse(private_evidence._is_private(public))

    def test_external_private_named_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            external = root.parent / "analysis/evidence/missing.json"
            with patch.object(private_evidence, "_REPO_ROOT", root, create=True):
                self.assert_rejected_without_skip(external)

    def test_relative_read_uses_repo_path_outside_repository_cwd(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            external_cwd = Path(directory) / "external"
            repo_evidence = root / "analysis/evidence/sample.txt"
            external_evidence = external_cwd / "analysis/evidence/sample.txt"
            repo_evidence.parent.mkdir(parents=True)
            external_evidence.parent.mkdir(parents=True)
            repo_evidence.write_text("repository", encoding="utf-8")
            external_evidence.write_text("external", encoding="utf-8")
            original_cwd = Path.cwd()
            try:
                os.chdir(external_cwd)
                with patch.object(private_evidence, "_REPO_ROOT", root, create=True):
                    require_private("analysis/evidence/sample.txt")
                    self.assertEqual(
                        read_private_text("analysis/evidence/sample.txt"), "repository"
                    )
            finally:
                os.chdir(original_cwd)

    def test_symlink_escape_from_private_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            outside = Path(directory) / "outside"
            (root / "analysis").mkdir(parents=True)
            outside.mkdir()
            (root / "analysis/escape").symlink_to(outside, target_is_directory=True)
            with patch.object(private_evidence, "_REPO_ROOT", root, create=True):
                self.assert_rejected_without_skip(root / "analysis/escape/missing.json")


if __name__ == "__main__":
    unittest.main()
