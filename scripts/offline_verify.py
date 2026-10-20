"""Fail-closed acceptance checks for software completion without a vehicle.

Coverage is a reviewed claim ledger, not a substitute for native evidence or
behavioral tests. Unknown software always prevents the completion marker.
"""

from __future__ import annotations

import argparse
import ast
import importlib
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "docs/offline-coverage.json"
SOFTWARE = {
    "vehicle.catalog",
    "vehicle.options",
    "vehicle.exceptions",
    "vehicle.pid_support",
    "vehicle.command_selection",
    "toyota.dtc",
    "toyota.freeze",
    "toyota.live",
    "toyota.health",
    "toyota.active_tests",
    "utility.xml",
    "utility.bindings",
    "utility.csdf",
    "utility.libraries",
    "session.communication_logs",
    "snapshot.native_read",
    "snapshot.native_write",
    "snapshot.playback",
    "snapshot.report_views",
    "calibration.containers",
    "calibration.compatibility",
    "programming.native_plan",
    "programming.recovery",
    "calibration.module_recovery",
    "recorder.commands",
    "recorder.native_records",
    "recorder.lifecycle",
    "transport.raw_can",
    "transport.host_iso",
    "transport.firmware_iso",
    "transport.kline",
    "transport.firmware_maintenance",
    "toyota.monitor_runtime",
    "obd.enhanced_readiness",
    "obd.support",
    "obd.monitors",
    "obd.compound_values",
    "obd.vehicle_information",
    "application.integration",
    "application.source_only",
    "application.export_preservation",
    "application.service_replay",
    "application.programming_replay",
    "application.active_replay",
    "application.recorder_replay",
}
OBSERVATIONS = {
    "hardware.usb_identity",
    "hardware.bus_timing",
    "hardware.vehicle_compatibility",
    "hardware.programming_recovery",
}


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate coverage key: {key}")
        result[key] = value
    return result


def _relative_file(root: Path, relative: str) -> Path:
    if not isinstance(relative, str):
        raise ValueError("Coverage path must be a string")  # noqa: TRY004 - Invalid JSON schema is a data error.
    path = Path(relative)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise ValueError("Coverage path must stay inside the repository")
    target = root / path
    if any(
        part.is_symlink()
        for part in [target, *target.parents]
        if part.is_relative_to(root)
    ):
        raise ValueError("Coverage cannot point through symlinks")
    if not target.is_file() or not target.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"Missing coverage artifact: {relative}")
    return target


def _function(path: Path, qualified: str) -> None:
    parts = qualified.split(".")
    if not all(part.isidentifier() for part in parts):
        raise ValueError("Invalid implementation symbol")
    body = ast.parse(path.read_text(encoding="utf-8")).body
    selected = None
    for part in parts:
        selected = next(
            (
                node
                for node in body
                if isinstance(
                    node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
                )
                and node.name == part
            ),
            None,
        )
        if selected is None:
            raise ValueError(
                f"Implementation symbol does not exist: {path.name}:{qualified}"
            )
        body = selected.body
    if not isinstance(selected, (ast.FunctionDef, ast.AsyncFunctionDef)):
        raise ValueError("Coverage must name an executable function")  # noqa: TRY004 - Invalid JSON schema is a data error.
    meaningful = [
        node
        for node in body
        if not (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        )
    ]
    if not meaningful or all(
        isinstance(node, ast.Pass)
        or (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and node.value.value is Ellipsis
        )
        for node in meaningful
    ):
        raise ValueError("A placeholder cannot satisfy software coverage")
    if any(
        (
            isinstance(node, ast.Name)
            and node.id in {"NotImplemented", "NotImplementedError"}
        )
        or (
            isinstance(node, ast.Attribute)
            and node.attr in {"NotImplemented", "NotImplementedError"}
        )
        for statement in meaningful
        for node in ast.walk(statement)
    ):
        raise ValueError("An unimplemented branch cannot satisfy software coverage")


def validate_coverage(document: dict, root: Path = ROOT) -> list[str]:
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "operations", "unresolved_software"}
        or document["schema"] != "techstream-no-car-coverage-v1"
    ):
        raise ValueError("Invalid offline coverage document")
    rows = document["operations"]
    if not isinstance(rows, list) or len(rows) != len(SOFTWARE | OBSERVATIONS):
        raise ValueError("Offline operation inventory is incomplete")
    seen, tests, pending = set(), set(), []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "id",
            "status",
            "implementation",
            "tests",
            "evidence",
            "remaining",
        }:
            raise ValueError("Invalid coverage operation fields")
        key = row["id"]
        if (
            not isinstance(key, str)
            or key not in SOFTWARE | OBSERVATIONS
            or key in seen
        ):
            raise ValueError("Unknown or duplicate offline operation")
        seen.add(key)
        if not isinstance(row["remaining"], str):
            raise ValueError("Coverage remaining reason must be text")  # noqa: TRY004 - Invalid JSON schema is a data error.
        if key in OBSERVATIONS:
            if row["status"] != "PHYSICAL_UNCONFIRMED" or not row["remaining"]:
                raise ValueError(
                    "Hardware observations must remain explicitly unconfirmed"
                )
            continue
        if row["status"] != "implemented":
            pending.append(key)
            continue
        if (
            row["remaining"]
            or not row["implementation"]
            or not row["tests"]
            or not row["evidence"]
        ):
            raise ValueError(f"Incomplete completion claim: {key}")
        for item in row["implementation"]:
            if not isinstance(item, dict) or set(item) != {"path", "symbol"}:
                raise ValueError("Invalid implementation reference")
            _function(_relative_file(root, item["path"]), item["symbol"])
        for test in row["tests"]:
            if (
                not isinstance(test, str)
                or re.fullmatch(r"test_\w+\.\w+\.test_\w+", test) is None
            ):
                raise ValueError("Coverage must name exact regression test methods")
            module, test_class, method = test.split(".")
            _function(
                _relative_file(root, f"tests/{module}.py"), f"{test_class}.{method}"
            )
            tests.add(test)
        for evidence in row["evidence"]:
            if not isinstance(evidence, str):
                raise ValueError("Coverage evidence must name a reviewed document")  # noqa: TRY004 - Invalid JSON schema is a data error.
            _relative_file(root, evidence)
    if seen != SOFTWARE | OBSERVATIONS:
        raise ValueError("Offline operation inventory does not match the contract")
    unresolved = document["unresolved_software"]
    if not isinstance(unresolved, list) or any(
        not isinstance(item, str) or not item.strip() for item in unresolved
    ):
        raise ValueError("Invalid unresolved-software list")
    if pending or unresolved:
        raise ValueError(
            f"Offline gate OPEN: pending={','.join(sorted(pending))}; unresolved={'; '.join(unresolved)}"
        )
    return sorted(tests)


def _suite(names: list[str] | None = None) -> None:
    sys.path.insert(0, str(ROOT / "tests"))
    loader = unittest.TestLoader()
    suite = (
        loader.loadTestsFromNames(names)
        if names
        else loader.discover(str(ROOT / "tests"))
    )
    if suite.countTestCases() == 0:
        raise ValueError("No regression checks were discovered")
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    if not result.wasSuccessful() or result.skipped:
        raise ValueError("Offline regression suite failed or skipped a required check")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("coverage", "workflows", "checks"))
    args = parser.parse_args()
    try:
        if args.command == "checks":
            _suite()
            marker = "OFFLINE_CHECKS_PASSED"
        elif args.command == "coverage":
            with REGISTRY.open(encoding="utf-8") as stream:
                document = json.load(stream, object_pairs_hook=_pairs)
            tests = validate_coverage(document)
            from scripts.native_inventory import (
                CANONICAL_REQUIRED_CONTRACTS,
                load_manifest,
                validate_manifest,
            )

            native = validate_manifest(
                load_manifest(),
                root=ROOT,
                required_contracts=CANONICAL_REQUIRED_CONTRACTS,
                require_complete=True,
            )
            _suite(sorted(set(tests) | set(native["tests"])))
            marker = "OFFLINE_COVERAGE_PASSED"
        else:
            runner = importlib.import_module("scripts.offline_tools")
            runner.verify_workflows()
            marker = "OFFLINE_WORKFLOWS_PASSED"
    except (OSError, ValueError, ImportError, AttributeError) as exc:
        print(f"offline gate: {exc}", file=sys.stderr)
        return 1
    print(marker)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
