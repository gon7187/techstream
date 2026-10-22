"""Source-only, fail-closed reconciliation of the independently frozen PE universe.

The inventory contains identities and addresses, never original code or resources.
Ownership routes work; only reviewed operation claims can close native targets.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from collections import Counter
from collections.abc import Callable
from pathlib import Path

from scripts.local_files import read_regular
from scripts.offline_verify import ROOT, _function, _pairs, _relative_file

MANIFEST = ROOT / "docs/native-operations.json"
SCHEMA = "techstream-native-operations-v1"
# Recomputed from original files and independent inventories by the private
# static inventory audit, not from owner claims or the completion document.
CANONICAL_SHA256 = "9baf36c9aa71df6f24b504b82d5a3e004b07f83059882dd6018fa82ef25b09c6"
CANONICAL_COUNTS = {
    "artifacts": 2454,
    "aliases": 3407,
    "exports": 146011,
    "executable": 132513,
    "data": 13498,
}
# Known semantic contracts come from separate owner/native coverage inventories.
CANONICAL_REQUIRED_CONTRACTS = frozenset(
    [
        "native12:wdreg16_installer",
        "application:application.export_preservation",
        "application:application.integration",
        "application:application.source_only",
        "application:calibration.compatibility",
        "application:calibration.containers",
        "application:obd.compound_values",
        "application:obd.enhanced_readiness",
        "application:obd.monitors",
        "application:obd.support",
        "application:obd.vehicle_information",
        "application:programming.native_plan",
        "application:programming.recovery",
        "application:recorder.commands",
        "application:recorder.lifecycle",
        "application:recorder.native_records",
        "application:session.communication_logs",
        "application:snapshot.native_read",
        "application:snapshot.native_write",
        "application:snapshot.playback",
        "application:toyota.active_tests",
        "application:toyota.dtc",
        "application:toyota.freeze",
        "application:toyota.health",
        "application:toyota.live",
        "application:transport.firmware_iso",
        "application:transport.host_iso",
        "application:transport.kline",
        "application:transport.raw_can",
        "application:utility.bindings",
        "application:utility.csdf",
        "application:utility.libraries",
        "application:utility.xml",
        "application:vehicle.catalog",
        "application:vehicle.command_selection",
        "application:vehicle.exceptions",
        "application:vehicle.options",
        "application:vehicle.pid_support",
        "ddb.selected.CDbActTestCommModeTable",
        "ddb.selected.CDbCommDidDataTable",
        "ddb.selected.CDbCommPidDataTable",
        "ddb.selected.CDbCommRidDataTable",
        "ddb.selected.CDbMultiPIDIDTable",
        "ddb.selected.CDbProtInfoTable",
        "leaf25:Complete live ring metadata phase/allocation construction",
        "leaf25:KWP/Fuel literal NULL initialization provider calls",
        "leaf25:KgpDataMonitorCtrl b0a0 mode/provider dispatch",
        "leaf25:Native DMCI111 IDMap parameter normalization",
        "leaf25:Native109/10a/119/10b/11c neutral setup commands",
        "leaf25:Normal provider lifecycle and scheduler integration",
        "leaf25:P4 5010/5120 observed-support modes and native A1/pair setup",
        "leaf25:P4 a3d0 selected metadata and explicit LSB observation gate",
        "leaf25:P4 composite pickup and trigger setup",
        "leaf25:P4 d040 selectedFreeze/MultiPID prepacking",
        "leaf25:P4 phase4/6 full length and bit remap differences",
        "leaf25:P4/P5 mixed packet events and phase-specific buffer clearing",
        "leaf25:P4/P5 native LSB wire observation producer",
        "leaf25:P5 6220 dynamic DID packing and19cb0 D4 clear patching",
        "leaf25:P5 selected normal/ActTest monitor definitions and metadata",
        "leaf2:ActiveTest.lifecycle",
        "leaf2:CAN.DK.extended.dtcs_can",
        "leaf2:CommDidData.SendDidData",
        "leaf2:CommPidData.CommRidData.SetData",
        "leaf2:CommPidData.read",
        "leaf2:CommandSpec.execute.sequence",
        "leaf2:DK.ISO.freeze_and_transport",
        "leaf2:DK.ISO9141.parse_dk_iso_dtcs",
        "leaf2:DiagnosticMode.sequence",
        "leaf2:FFD.CGW",
        "leaf2:FFD.DK.ABS",
        "leaf2:FFD.DK.Roof",
        "leaf2:FFD.DK.grouped",
        "leaf2:FFD.MultiRcv",
        "leaf2:FFD.NoFrmNo",
        "leaf2:FFD.PSA",
        "leaf2:KWP.dtcs",
        "leaf2:Native.SID.specialized",
        "leaf2:Native.signalDisplay",
        "leaf2:NativeFrameSend.send_only",
        "leaf2:P3.P4.DK.DLC12.PSA.active_request",
        "leaf2:P3.P4.initialValue.GetValue",
        "leaf2:P4.pidExpansion.freeze",
        "leaf2:P5.FFD.timeIndex",
        "leaf2:P5.absoluteBCD.SubaruType",
        "leaf2:P5.active.mask_ordinal_zero",
        "leaf2:P5.activeInitialReads",
        "leaf2:P5.active_requests.active_reply.native_states",
        "leaf2:P5.dualQueueClock",
        "leaf2:P5.nativeActiveQueue",
        "leaf2:P5.parse_p5_dtcs.StatusRule",
        "leaf2:P5.routineInitialStatus",
        "leaf2:P5.selectedArgumentAssembly",
        "leaf2:P5.selectedDID.sampleDecode",
        "leaf2:P5.storedFFD.DIDrecords",
        "leaf2:PSA.AddHt.dtcs_psa_add_ht",
        "leaf2:PSA.Audio.dtcs_psa_audio",
        "leaf2:PSA.standard.V2.NoStatus.dtcs_psa",
        "leaf2:PostIO.cancel.deadline.native_and_host_errors",
        "leaf2:RoutineID.GetDataNoEnableList",
        "leaf2:RoutineID.read",
        "leaf2:RoutineID.support.signal",
        "leaf2:SiennaDoor.CAN.framing.receive",
        "leaf2:Subaru.FFD.stored.snapshot",
        "leaf2:Tesla.dtcs",
        "leaf2:absolute.saved_log.PID.read",
        "leaf2:absolute.saved_log.components",
        "leaf2:absolute.saved_log.routine.read.BCD",
        "leaf2:active_request_p3",
        "leaf2:data_list.scale_signal",
        "leaf2:dtc_information",
        "leaf2:ffd_type.ffd_existence_flag.compare_timestamp.order_freeze_samples",
        "leaf2:freeze_p3.freeze_p5.vin",
        "leaf2:freeze_support.associate_freeze",
        "leaf2:legacy.active.events",
        "leaf2:native.fallback.format_dtc",
        "leaf2:poll.health_check",
        "leaf2:routine_request_p5.routine_status_p5.single_routine",
        "leaf2:vin_multi",
        "leaf6:change_check_mode",
        "leaf6:check_car_info",
        "leaf6:confirm_check_mode",
        "leaf6:connect",
        "leaf6:default_session",
        "leaf6:diag_comm_end",
        "leaf6:diag_comm_setting",
        "leaf6:disconnect",
        "leaf6:extended_session",
        "leaf6:fast_init",
        "leaf6:five_baud_init",
        "leaf6:monitor_buffer_info",
        "leaf6:monitor_setting_info",
        "leaf6:monitor_signal_info",
        "leaf6:monitor_stop_info",
        "leaf6:read_messages",
        "leaf6:receive_frame_info",
        "leaf6:set_config",
        "leaf6:start_message_filter",
        "leaf6:system_information",
        "leaf6:trigger_info",
        "leaf6:trigger_parameters",
        "leaf6:vehicle_selection",
        "leaf6:write_messages",
        "leaf8:all_92_uasids",
        "leaf8:all_standard_pids_00_to_87",
        "leaf8:compound_parameters_and_support",
        "leaf8:configuration_scaling",
        "leaf8:enhanced_native_readiness",
        "leaf8:health_fixture",
        "leaf8:information_records",
        "leaf8:legacy_mode05",
        "leaf8:monitor_results",
        "leaf8:native_signal_display",
        "leaf8:optional_trim_fields",
        "leaf8:strict_replay_recording",
        "leaf8:support_chain",
        "leaf9:ScriptLibCommunication:1",
        "leaf9:ScriptLibCommunication:10",
        "leaf9:ScriptLibCommunication:11",
        "leaf9:ScriptLibCommunication:2",
        "leaf9:ScriptLibCommunication:3",
        "leaf9:ScriptLibCommunication:4",
        "leaf9:ScriptLibCommunication:5",
        "leaf9:ScriptLibCommunication:6",
        "leaf9:ScriptLibCommunication:7",
        "leaf9:ScriptLibCommunication:8",
        "leaf9:ScriptLibCommunication:9",
        "leaf9:ScriptLibDebug:1",
        "leaf9:ScriptLibLang:1",
        "leaf9:ScriptLibLang:2",
        "leaf9:ScriptLibRMLib:1",
        "leaf9:ScriptLibSystem:1",
    ]
)
MAX_BYTES = 64 * 1024 * 1024
MAX_ARTIFACTS = 4096
MAX_EXPORTS = 200000
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _check(cancel: Callable[[], bool] | None) -> None:
    if cancel is not None and cancel():
        raise InterruptedError("Native inventory validation cancelled")


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    ).hexdigest()


def _fields(value: object, fields: set[str], description: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"Invalid {description} fields")
    return value


def _text(value: object, description: str, limit: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > limit
        or "\0" in value
    ):
        raise ValueError(f"Invalid {description}")
    return value


def _sha(value: object) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise ValueError("Invalid source SHA-256")
    return value


def _integer(value: object, limit: int = 0xFFFFFFFF) -> int:
    if type(value) is not int or not 0 <= value <= limit:
        raise ValueError("Invalid native integer")
    return value


def export_target(sha256: str, ordinal: int) -> str:
    return f"{sha256}:export:{ordinal}"


def module_target(sha256: str) -> str:
    return f"{sha256}:module"


def universe_metadata(
    universe: object, *, cancel: Callable[[], bool] | None = None
) -> tuple[dict[str, dict], dict[str, int]]:
    """Validate identities independently of mutable coverage/owner claims."""
    if not isinstance(universe, list) or not 1 <= len(universe) <= MAX_ARTIFACTS:
        raise ValueError("Invalid native artifact universe")
    targets = {}
    hashes = []
    count = Counter(artifacts=len(universe))
    for artifact in universe:
        _check(cancel)
        row = _fields(
            artifact,
            {
                "sha256",
                "size",
                "aliases",
                "entrypoint_rva",
                "exports",
                "carriers",
                "managed",
            },
            "artifact",
        )
        sha = _sha(row["sha256"])
        if sha in hashes:
            raise ValueError("Duplicate native identity")
        hashes.append(sha)
        _integer(row["size"])
        entry = _integer(row["entrypoint_rva"])
        if type(row["managed"]) is not bool:
            raise ValueError("Invalid CLR metadata flag")
        if not isinstance(row["aliases"], list) or not row["aliases"]:
            raise ValueError("Missing source artifact aliases")
        aliases = []
        for alias in row["aliases"]:
            _fields(alias, {"path", "build", "inventory"}, "source alias")
            path = _text(alias["path"], "artifact path")
            if Path(path).is_absolute() or ".." in Path(path).parts:
                raise ValueError("Invalid source artifact path")
            aliases.append(
                (
                    path,
                    _text(alias["build"], "source build"),
                    _text(alias["inventory"], "inventory provenance"),
                )
            )
        if aliases != sorted(set(aliases)):
            raise ValueError("Source aliases must be unique and canonical")
        count["aliases"] += len(aliases)
        if not isinstance(row["carriers"], list):
            raise ValueError("Invalid reconstructed-engine carriers")  # noqa: TRY004 - Invalid manifest data is reported uniformly.
        for carrier in row["carriers"]:
            _fields(
                carrier,
                {"source_sha256", "companion_sha256", "source_path", "companion_path"},
                "engine carrier",
            )
            _sha(carrier["source_sha256"])
            _sha(carrier["companion_sha256"])
            for key in ("source_path", "companion_path"):
                path = _text(carrier[key], "carrier path")
                if Path(path).is_absolute() or ".." in Path(path).parts:
                    raise ValueError("Invalid carrier path")
        targets[module_target(sha)] = {"sha256": sha, "rva": entry, "kind": "module"}
        exports = row["exports"]
        if not isinstance(exports, list) or len(exports) > MAX_EXPORTS:
            raise ValueError("Invalid exported target list")
        if count["exports"] + len(exports) > MAX_EXPORTS:
            raise ValueError("Native export universe exceeds its bound")
        ordinals = []
        for index, export in enumerate(exports):
            if index % 256 == 0:
                _check(cancel)
            _fields(
                export,
                {"name", "ordinal", "rva", "forwarder", "storage"},
                "native export",
            )
            ordinal = _integer(export["ordinal"])
            ordinals.append(ordinal)
            if export["name"] is not None:
                _text(export["name"], "export name")
            if export["forwarder"] is not None:
                _text(export["forwarder"], "export forwarder")
            if not isinstance(export["storage"], str) or export["storage"] not in {
                "executable",
                "data",
                "forwarder",
                "unmapped",
            }:
                raise ValueError("Invalid export storage classification")
            rva = _integer(export["rva"])
            if not rva or (export["storage"] == "forwarder") != (
                export["forwarder"] is not None
            ):
                raise ValueError("Inconsistent export RVA/forwarder")
            targets[export_target(sha, ordinal)] = {
                "sha256": sha,
                "rva": rva,
                "kind": export["storage"],
            }
            count["exports"] += 1
            count[export["storage"]] += 1
        if ordinals != sorted(set(ordinals)):
            raise ValueError("Export ordinals must be unique and canonical")
    if hashes != sorted(hashes) or count["exports"] > MAX_EXPORTS:
        raise ValueError("Native universe is not canonical or exceeds its bound")
    return targets, dict(count)


def _document_reference(reference: object, root: Path) -> dict:
    row = _fields(reference, {"path", "sha256", "anchor"}, "evidence reference")
    path = _relative_file(root, row["path"])
    if path.suffix not in {".md", ".json", ".txt"}:
        raise ValueError("Evidence must be reviewable metadata or documentation")
    data = read_regular(path, limit=MAX_BYTES)
    if hashlib.sha256(data).hexdigest() != _sha(row["sha256"]):
        raise ValueError("Evidence document hash changed")
    if _text(row["anchor"], "evidence anchor") not in data.decode("utf-8"):
        raise ValueError("Evidence anchor does not exist")
    return row


def _literal(node: ast.AST) -> bool:
    try:
        ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return False
    return True


def source_digest(path: Path, *, hash_kind: str = "file", symbol: str = "") -> str:
    """Pin reviewed code; AST mode ignores only source formatting and comments."""
    data = read_regular(path, limit=MAX_BYTES)
    if hash_kind == "file":
        return hashlib.sha256(data).hexdigest()
    if not isinstance(hash_kind, str) or hash_kind not in {"module-ast", "symbol-ast"}:
        raise ValueError("Unknown reviewed source hash kind")
    selected: ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef = (
        ast.parse(data)
    )
    if hash_kind == "symbol-ast":
        for part in symbol.split("."):
            matches = [
                node
                for node in selected.body
                if isinstance(
                    node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
                )
                and node.name == part
            ]
            if len(matches) != 1:
                raise ValueError("Reviewed source symbol is missing or ambiguous")
            selected = matches[0]
    return hashlib.sha256(
        ast.dump(selected, include_attributes=False).encode()
    ).hexdigest()


def _source_binding(value: object, fields: set[str], description: str) -> dict:
    if isinstance(value, dict) and "hash_kind" in value:
        fields = fields | {"hash_kind"}
    return _fields(value, fields, description)


def _source_symbol(root: Path, path: str, symbol: str, *, test: bool = False) -> None:
    source = _relative_file(root, path)
    _function(source, symbol)
    body = ast.parse(source.read_text(encoding="utf-8")).body
    selected = None
    for part in symbol.split("."):
        selected = next(
            node
            for node in body
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == part
        )
        body = selected.body
    meaningful = [
        node
        for node in body
        if not (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        )
    ]
    if len(meaningful) == 1 and (
        isinstance(meaningful[0], ast.Raise)
        or isinstance(meaningful[0], ast.Return)
        and (meaningful[0].value is None or _literal(meaningful[0].value))
    ):
        raise ValueError(
            "Constant/error-only placeholder cannot close a native operation"
        )
    if test:
        assertions = [
            node
            for statement in meaningful
            for node in ast.walk(statement)
            if isinstance(node, ast.Assert)
            and not _literal(node.test)
            or isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr.startswith("assert")
            and any(not _literal(arg) for arg in node.args)
        ]
        if not assertions:
            raise ValueError(
                "A constant or assertion-free test cannot close a native operation"
            )


def validate_manifest(
    document: object,
    root: Path = ROOT,
    *,
    expected_digest: str = CANONICAL_SHA256,
    expected_counts: dict[str, int] | None = None,
    required_contracts: frozenset[str] | None = None,
    require_complete: bool = True,
    cancel: Callable[[], bool] | None = None,
) -> dict:
    """Check the fixed universe, exact target mapping and source-bound claims.

    Optional expected values support independently authored small test universes.
    Production callers use the frozen constants, never values from the document.
    Inspection may report OPEN targets; completion validation always rejects them.
    """
    doc = _fields(
        document,
        {"schema", "universe_sha256", "universe", "operations", "claims", "contracts"},
        "native manifest",
    )
    if doc["schema"] != SCHEMA:
        raise ValueError("Unknown native manifest schema")
    _check(cancel)
    targets, counts = universe_metadata(doc["universe"], cancel=cancel)
    if (
        digest(doc["universe"]) != expected_digest
        or doc["universe_sha256"] != expected_digest
    ):
        raise ValueError("Native universe differs from independently frozen digest")
    fixed_counts = CANONICAL_COUNTS if expected_counts is None else expected_counts
    if counts != fixed_counts:
        raise ValueError("Native universe counts differ from independent inventory")
    rows = doc["operations"]
    if not isinstance(rows, list) or len(rows) != len(targets):
        raise ValueError("Native operation target inventory is incomplete")
    seen = set()
    operations = {}
    pending = []
    for row in rows:
        _check(cancel)
        _fields(row, {"target", "owner", "status", "claim"}, "operation mapping")
        target = row["target"]
        if not isinstance(target, str) or target not in targets or target in seen:
            raise ValueError("Unknown or duplicate native operation target")
        seen.add(target)
        owner = row["owner"]
        if owner is not None and (type(owner) is not int or not 1 <= owner <= 10000):
            raise ValueError("Invalid native operation owner")
        if row["status"] == "OPEN":
            if row["claim"] is not None:
                raise ValueError("OPEN operation cannot reference a completion claim")
            pending.append(target)
        elif (
            not isinstance(row["status"], str)
            or row["status"] not in {"implemented", "platform", "unreachable"}
            or owner is None
        ):
            raise ValueError("Invalid native operation disposition")
        operations[target] = row
    claims = doc["claims"]
    contracts = doc["contracts"]
    if (
        not isinstance(claims, list)
        or len(claims) > len(targets)
        or not isinstance(contracts, list)
    ):
        raise ValueError("Invalid native contract claim inventory")
    if any(not isinstance(key, str) or not key.strip() for key in contracts) or len(
        contracts
    ) != len(set(contracts)):
        raise ValueError("Invalid/duplicate required native business contract")
    known_contracts = required_contracts or frozenset()
    if expected_digest == CANONICAL_SHA256:
        known_contracts |= CANONICAL_REQUIRED_CONTRACTS
    if not known_contracts <= set(contracts):
        raise ValueError("Known native business contracts were omitted")
    claim_ids = set()
    covered = set()
    tests = set()
    for claim in claims:
        _check(cancel)
        _fields(
            claim,
            {
                "id",
                "owner",
                "status",
                "targets",
                "implementation",
                "tests",
                "native_evidence",
                "review",
                "reason",
            },
            "native claim",
        )
        key = _text(claim["id"], "native contract ID")
        if key in claim_ids or key not in contracts:
            raise ValueError("Unknown or duplicate native contract claim")
        claim_ids.add(key)
        if (
            type(claim["owner"]) is not int
            or not 1 <= claim["owner"] <= 10000
            or not isinstance(claim["status"], str)
            or claim["status"] not in {"implemented", "platform", "unreachable"}
        ):
            raise ValueError("Unresolved claims must remain OPEN operation rows")
        if (
            not claim["targets"]
            or not isinstance(claim["targets"], list)
            or any(not isinstance(target, str) for target in claim["targets"])
            or len(set(claim["targets"])) != len(claim["targets"])
        ):
            raise ValueError("Native claim requires unique exact targets")
        if any(
            not isinstance(claim[field], list) or not claim[field]
            for field in ("implementation", "tests", "native_evidence")
        ):
            raise ValueError(
                "Native claim lacks implementation, tests or original evidence"
            )
        _text(claim["reason"], "native disposition rationale")
        for target in claim["targets"]:
            if target not in targets or target in covered:
                raise ValueError("Unknown or multiply claimed native target")
            row = operations[target]
            if (
                row["owner"] != claim["owner"]
                or row["status"] != claim["status"]
                or row["claim"] != key
            ):
                raise ValueError("Native operation does not match its owner claim")
            covered.add(target)
        for implementation in claim["implementation"]:
            _source_binding(
                implementation, {"path", "symbol", "sha256"}, "source binding"
            )
            _source_symbol(root, implementation["path"], implementation["symbol"])
            path = _relative_file(root, implementation["path"])
            if source_digest(
                path,
                hash_kind=implementation.get("hash_kind", "file"),
                symbol=implementation["symbol"],
            ) != _sha(implementation["sha256"]):
                raise ValueError("Reviewed implementation source hash changed")
        for binding in claim["tests"]:
            _source_binding(binding, {"name", "sha256"}, "regression binding")
            test = binding["name"]
            if (
                not isinstance(test, str)
                or re.fullmatch(r"test_\w+\.\w+\.test_\w+", test) is None
            ):
                raise ValueError(
                    "Native claim needs exact executable regression methods"
                )
            module, cls, method = test.split(".")
            _source_symbol(root, f"tests/{module}.py", f"{cls}.{method}", test=True)
            path = _relative_file(root, f"tests/{module}.py")
            if source_digest(
                path,
                hash_kind=binding.get("hash_kind", "file"),
                symbol=f"{cls}.{method}",
            ) != _sha(binding["sha256"]):
                raise ValueError("Reviewed regression source hash changed")
            tests.add(test)
        anchors = set()
        for evidence in claim["native_evidence"]:
            _fields(evidence, {"source_sha256", "rvas", "document"}, "native evidence")
            sha = _sha(evidence["source_sha256"])
            if not isinstance(evidence["rvas"], list) or not evidence["rvas"]:
                raise ValueError("Native evidence needs exact source addresses")
            for rva in evidence["rvas"]:
                anchors.add((sha, _integer(rva)))
            _document_reference(evidence["document"], root)
        for target in claim["targets"]:
            if (targets[target]["sha256"], targets[target]["rva"]) not in anchors:
                raise ValueError(
                    "Native proof does not bind the exact target identity/address"
                )
        _document_reference(claim["review"], root)
    unresolved = set(contracts) - claim_ids
    if covered != {key for key, row in operations.items() if row["status"] != "OPEN"}:
        raise ValueError("Resolved native target has no exact reviewed claim")
    if require_complete and (pending or unresolved):
        raise ValueError(
            f"Native gate OPEN: {len(pending)} targets, {len(unresolved)} business contracts"
        )
    return {
        "universe_sha256": expected_digest,
        "counts": counts,
        "open_targets": len(pending),
        "open_contracts": sorted(unresolved),
        "resolved_targets": len(covered),
        "tests": sorted(tests),
        "unowned_targets": sum(row["owner"] is None for row in rows),
    }


def load_manifest(path: Path = MANIFEST) -> dict:
    return json.loads(read_regular(path, limit=MAX_BYTES), object_pairs_hook=_pairs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("inspect", "validate"))
    args = parser.parse_args()
    try:
        report = validate_manifest(
            load_manifest(),
            required_contracts=CANONICAL_REQUIRED_CONTRACTS,
            require_complete=args.command == "validate",
        )
    except (ValueError, OSError, UnicodeError, SyntaxError) as exc:
        print(f"native inventory: {exc}")
        return 1
    report["open_contract_count"] = len(report.pop("open_contracts"))
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
