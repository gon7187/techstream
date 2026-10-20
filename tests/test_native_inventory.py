import copy
import hashlib
import tempfile
import unittest
from pathlib import Path

from scripts.native_inventory import (
    CANONICAL_COUNTS,
    CANONICAL_REQUIRED_CONTRACTS,
    CANONICAL_SHA256,
    MANIFEST,
    MAX_BYTES,
    MAX_EXPORTS,
    SCHEMA,
    digest,
    export_target,
    load_manifest,
    module_target,
    source_digest,
    validate_manifest,
)


class NativeInventoryTests(unittest.TestCase):
    def test_full_supplied_app_scope_retains_dependencies_and_parse_budget(self):
        document = load_manifest()
        bypath = {
            alias["path"]: row
            for row in document["universe"]
            for alias in row["aliases"]
        }
        prefix = "artifacts/extracted/gtsplus-application/CUWPlusPF/CUWDLL/"
        for name, sha, count in (
            (
                "CalculationHmacAPI.dll",
                "e1e6cc8a531e8a3f3c899e3f11a48d4e0556e0903bc15cb944ef289c2f79eeef",
                1,
            ),
            (
                "Newtonsoft.Json.dll",
                "b624949df8b0e3a6153fdfb730a7c6f4990b6592ee0d922e1788433d276610f3",
                0,
            ),
            (
                "msvcp140.dll",
                "97e71a3c697fb1ab3af777db39009e4602525e8c3aff0837ecc7031cba188165",
                1515,
            ),
            (
                "vcruntime140.dll",
                "a9d7732a3c3de09f0601a7fa2555093dcb49f08e2fc62a86091461f0f38393ed",
                81,
            ),
        ):
            row = bypath[prefix + name]
            self.assertEqual(row["sha256"], sha)
            self.assertEqual(len(row["exports"]), count)
        inventories = [
            alias["inventory"]
            for row in document["universe"]
            for alias in row["aliases"]
        ]
        self.assertEqual(inventories.count("supplied18-application"), 610)
        self.assertEqual(inventories.count("supplied2026-application"), 1435)
        self.assertGreater(MANIFEST.stat().st_size, 32 * 1024 * 1024)
        self.assertLess(MANIFEST.stat().st_size, MAX_BYTES)
        self.assertEqual(MAX_BYTES, 64 * 1024 * 1024)
        self.assertEqual(MAX_EXPORTS, 200000)

    def test_ast_bindings_ignore_comments_but_reject_code_and_fixture_changes(self):
        claim = self.document["claims"][0]
        for binding in claim["implementation"]:
            binding["hash_kind"] = "module-ast"
            binding["sha256"] = source_digest(
                self.root / binding["path"], hash_kind="module-ast"
            )
        binding = claim["tests"][0]
        binding["hash_kind"] = "module-ast"
        path = self.root / "tests/test_example.py"
        binding["sha256"] = source_digest(path, hash_kind="module-ast")
        (self.root / "impl.py").write_text(
            "# authored comment\ndef run(value):\n    return value + 1\n"
        )
        self.assertEqual(self.validate()["resolved_targets"], 3)
        path.write_text(path.read_text().replace("run(1), 2", "run(1), 3"))
        with self.assertRaisesRegex(ValueError, "regression source hash changed"):
            self.validate()
        path.write_text(path.read_text().replace("run(1), 3", "run(1), 2"))
        (self.root / "impl.py").write_text("def run(value):\n    return value + 2\n")
        with self.assertRaisesRegex(ValueError, "implementation source hash changed"):
            self.validate()
        with self.assertRaisesRegex(ValueError, "hash kind"):
            source_digest(path, hash_kind="invented")

    def test_supplied12_entire_pe_scope_and_non_pe_obligation_are_retained(self):
        document = load_manifest()
        aliases = [
            (row, alias)
            for row in document["universe"]
            for alias in row["aliases"]
            if alias["inventory"] == "supplied12-application"
        ]
        self.assertEqual(len(aliases), 525)
        self.assertEqual(len({row["sha256"] for row, _ in aliases}), 502)
        kgp = [
            row
            for row, alias in aliases
            if alias["path"].endswith("/Techstream_Bin/KgpDataCtrl.dll")
        ]
        self.assertEqual(
            [row["sha256"] for row in kgp],
            ["ac93400c60a22878827ca38f028a0a724a6baae068cd0ec8041496997eda6749"],
        )
        self.assertIn("native12:wdreg16_installer", document["contracts"])
        self.assertIn("native12:wdreg16_installer", CANONICAL_REQUIRED_CONTRACTS)

    def test_production_known_business_contract_cannot_be_omitted(self):
        document = load_manifest()
        document["contracts"].remove(min(CANONICAL_REQUIRED_CONTRACTS))
        with self.assertRaisesRegex(ValueError, "contracts were omitted"):
            validate_manifest(document, require_complete=False)
        with self.assertRaisesRegex(ValueError, "contracts were omitted"):
            validate_manifest(
                document, required_contracts=frozenset(), require_complete=False
            )

    def test_nonplaceholder_implementation_edit_invalidates_review(self):
        (self.root / "impl.py").write_text("def run(value):\n    return value + 2\n")
        with self.assertRaisesRegex(ValueError, "implementation source hash changed"):
            self.validate()

    def test_changed_regression_body_invalidates_review(self):
        path = self.root / "tests/test_example.py"
        path.write_text(path.read_text().replace("run(1), 2", "run(1), 3"))
        with self.assertRaisesRegex(ValueError, "regression source hash changed"):
            self.validate()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "tests").mkdir()
        (self.root / "docs").mkdir()
        (self.root / "impl.py").write_text("def run(value):\n    return value + 1\n")
        (self.root / "tests/test_example.py").write_text(
            "import unittest\nfrom impl import run\n"
            "class Example(unittest.TestCase):\n"
            "    def test_run(self):\n        self.assertEqual(run(1), 2)\n"
        )
        self.sha = "a" * 64
        self.universe = [
            {
                "sha256": self.sha,
                "size": 128,
                "entrypoint_rva": 4096,
                "aliases": [
                    {
                        "path": "original/example.dll",
                        "build": "authored",
                        "inventory": "independent-authored-control",
                    }
                ],
                "carriers": [],
                "managed": False,
                "exports": [
                    {
                        "name": "Run",
                        "ordinal": 1,
                        "rva": 4112,
                        "forwarder": None,
                        "storage": "executable",
                    },
                    {
                        "name": "data",
                        "ordinal": 2,
                        "rva": 8192,
                        "forwarder": None,
                        "storage": "data",
                    },
                ],
            }
        ]
        self.expected = digest(self.universe)
        self.counts = {
            "artifacts": 1,
            "aliases": 1,
            "exports": 2,
            "executable": 1,
            "data": 1,
        }
        self.targets = [
            module_target(self.sha),
            export_target(self.sha, 1),
            export_target(self.sha, 2),
        ]
        self.document = {
            "schema": SCHEMA,
            "universe_sha256": self.expected,
            "universe": copy.deepcopy(self.universe),
            "operations": [
                {
                    "target": target,
                    "owner": 1,
                    "status": "implemented",
                    "claim": "authored.run",
                }
                for target in self.targets
            ],
            "contracts": ["authored.run"],
            "claims": [
                {
                    "id": "authored.run",
                    "owner": 1,
                    "status": "implemented",
                    "targets": self.targets.copy(),
                    "implementation": [
                        {
                            "path": "impl.py",
                            "symbol": "run",
                            "sha256": hashlib.sha256(
                                (self.root / "impl.py").read_bytes()
                            ).hexdigest(),
                        }
                    ],
                    "tests": [
                        {
                            "name": "test_example.Example.test_run",
                            "sha256": hashlib.sha256(
                                (self.root / "tests/test_example.py").read_bytes()
                            ).hexdigest(),
                        }
                    ],
                    "native_evidence": [
                        {
                            "source_sha256": self.sha,
                            "rvas": [4096, 4112, 8192],
                            "document": self.reference(
                                "source.md", "authored native control"
                            ),
                        }
                    ],
                    "review": self.reference(
                        "review.md", "independent authored control review"
                    ),
                    "reason": "Synthetic schema test, never a claim about original operation coverage.",
                }
            ],
        }

    def reference(self, name, text):
        path = self.root / "docs" / name
        path.write_text(text)
        return {
            "path": f"docs/{name}",
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "anchor": text,
        }

    def validate(self, document=None, **kwargs):
        kwargs.setdefault("required_contracts", frozenset())
        return validate_manifest(
            self.document if document is None else document,
            self.root,
            expected_digest=self.expected,
            expected_counts=self.counts,
            **kwargs,
        )

    def test_positive_source_bound_claim_and_exact_regressions(self):
        report = self.validate(required_contracts=frozenset({"authored.run"}))
        self.assertEqual(report["resolved_targets"], 3)
        self.assertEqual(report["tests"], ["test_example.Example.test_run"])
        self.assertEqual(report["open_targets"], 0)

    def test_original_inventory_remains_open_and_cannot_assert_completion(self):
        document = load_manifest()
        report = validate_manifest(document, require_complete=False)
        self.assertEqual(report["universe_sha256"], CANONICAL_SHA256)
        self.assertEqual(report["counts"], CANONICAL_COUNTS)
        document["claims"] = []
        for row in document["operations"]:
            row.update(status="OPEN", claim=None)
        report = validate_manifest(document, require_complete=False)
        self.assertGreater(report["open_targets"], 40000)
        with self.assertRaisesRegex(ValueError, "gate OPEN"):
            validate_manifest(document)

    def test_omitted_and_invented_exports_cannot_repin_the_universe(self):
        for mutate in (
            lambda d: d["universe"][0]["exports"].pop(),
            lambda d: d["universe"][0]["exports"].append(
                {
                    "name": "Invented",
                    "ordinal": 3,
                    "rva": 5000,
                    "forwarder": None,
                    "storage": "executable",
                }
            ),
        ):
            with self.subTest(mutation=mutate):
                document = copy.deepcopy(self.document)
                mutate(document)
                document["universe_sha256"] = digest(document["universe"])
                with self.assertRaisesRegex(ValueError, "independently frozen digest"):
                    self.validate(document)

    def test_remove_extra_duplicate_and_unknown_targets_fail(self):
        variants = []
        removed = copy.deepcopy(self.document)
        removed["operations"].pop()
        variants.append(removed)
        extra = copy.deepcopy(self.document)
        extra["operations"].append(copy.deepcopy(extra["operations"][0]))
        variants.append(extra)
        duplicate = copy.deepcopy(self.document)
        duplicate["operations"][1] = duplicate["operations"][0]
        variants.append(duplicate)
        unknown = copy.deepcopy(self.document)
        unknown["operations"][0]["target"] = "invented"
        variants.append(unknown)
        for document in variants:
            with self.assertRaises(ValueError):
                self.validate(document)

    def test_open_unowned_and_unresolved_contracts_block_completion(self):
        document = copy.deepcopy(self.document)
        document["claims"] = []
        for row in document["operations"]:
            row.update(status="OPEN", owner=None, claim=None)
        report = self.validate(document, require_complete=False)
        self.assertEqual(report["open_targets"], 3)
        self.assertEqual(report["unowned_targets"], 3)
        self.assertEqual(report["open_contracts"], ["authored.run"])
        with self.assertRaisesRegex(ValueError, "gate OPEN"):
            self.validate(document)
        with self.assertRaisesRegex(ValueError, "contracts were omitted"):
            self.validate(required_contracts=frozenset({"missing.native.family"}))

    def test_claim_cannot_cover_other_source_or_address(self):
        for key, value in (("source_sha256", "b" * 64), ("rvas", [4096, 4113, 8192])):
            document = copy.deepcopy(self.document)
            document["claims"][0]["native_evidence"][0][key] = value
            with self.assertRaisesRegex(ValueError, "exact target identity/address"):
                self.validate(document)

    def test_owner_alias_and_claim_disposition_must_match(self):
        for key, value in (("owner", 2), ("status", "platform"), ("claim", "another")):
            document = copy.deepcopy(self.document)
            document["operations"][0][key] = value
            with self.assertRaises(ValueError):
                self.validate(document)
        document = copy.deepcopy(self.document)
        document["universe"][0]["aliases"].append(document["universe"][0]["aliases"][0])
        with self.assertRaisesRegex(ValueError, "unique and canonical"):
            self.validate(document)

    def test_placeholders_and_constant_tests_do_not_close_targets(self):
        for body in (
            "pass",
            "return None",
            "return True",
            "raise ValueError('unsupported')",
            "raise NotImplementedError",
        ):
            with self.subTest(body=body):
                (self.root / "impl.py").write_text(f"def run(value):\n    {body}\n")
                with self.assertRaises(ValueError):
                    self.validate()
        (self.root / "impl.py").write_text("def run(value):\n    return value + 1\n")
        (self.root / "tests/test_example.py").write_text(
            "class Example:\n    def test_run(self):\n        self.assertTrue(True)\n"
        )
        with self.assertRaisesRegex(ValueError, "constant or assertion-free"):
            self.validate()

    def test_changed_evidence_missing_symbol_and_escaped_paths_fail(self):
        (self.root / "docs/source.md").write_text("changed")
        with self.assertRaisesRegex(ValueError, "hash changed"):
            self.validate()
        self.document["claims"][0]["native_evidence"][0]["document"] = self.reference(
            "source.md", "authored native control"
        )
        self.document["claims"][0]["implementation"][0]["symbol"] = "absent"
        with self.assertRaisesRegex(ValueError, "does not exist"):
            self.validate()
        self.document["claims"][0]["implementation"][0].update(
            path="../impl.py", symbol="run"
        )
        with self.assertRaisesRegex(ValueError, "stay inside"):
            self.validate()

    def test_duplicate_json_keys_and_symbolic_link_evidence_fail(self):
        path = self.root / "manifest.json"
        path.write_text('{"schema":1,"schema":2}')
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            load_manifest(path)
        linked = self.root / "docs/link.md"
        linked.symlink_to(self.root / "docs/source.md")
        self.document["claims"][0]["native_evidence"][0]["document"]["path"] = (
            "docs/link.md"
        )
        with self.assertRaisesRegex(ValueError, "symlinks"):
            self.validate()

    def test_cancellation_during_operation_walk_never_returns_partial_success(self):
        calls = 0

        def cancel():
            nonlocal calls
            calls += 1
            return calls == 5

        with self.assertRaises(InterruptedError):
            self.validate(cancel=cancel)
        self.assertEqual(calls, 5)

    def test_malformed_shapes_and_claimless_resolved_targets_fail(self):
        for field, value in (
            ("schema", "unknown"),
            ("claims", {}),
            ("operations", None),
            ("contracts", ["authored.run", "authored.run"]),
        ):
            document = copy.deepcopy(self.document)
            document[field] = value
            with self.assertRaises(ValueError):
                self.validate(document)
        document = copy.deepcopy(self.document)
        document["claims"] = []
        with self.assertRaisesRegex(ValueError, "no exact reviewed claim"):
            self.validate(document)
