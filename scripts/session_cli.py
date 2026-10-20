"""Run a deterministic diagnostic session without an adapter or original data."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path

from scripts.diagnostics import Session
from scripts.replay import Replay
from scripts.workbench import _atomic_text


def replay_session(
    path: Path,
    cancelled: Callable[[], bool] | None = None,
    *,
    operation: str = "replay",
    ecu: str | None = None,
    samples: int = 1,
) -> dict:
    replay = Replay.load(path)
    session = Session(replay.exchange, cancelled=cancelled)
    selected = ecu or replay.ecus[0]
    if operation == "replay":
        report = session.health_check(replay.ecus)
    elif operation == "calibration":
        report = session.calibration(selected)
    elif operation == "poll":
        report = {
            "physical_status": "PHYSICAL_UNCONFIRMED",
            "scope": "standard_obd_can_subset",
            "ecu_source": "configured_not_discovered",
            "ecu": selected,
            "samples": session.poll(selected, samples=samples),
        }
    else:
        raise ValueError("Unknown recording operation")
    replay.assert_complete()
    return {"source": replay.source, **report}


def save_report(path: Path, report: dict, *, source: Path | None = None) -> None:
    if source is not None and (
        path.resolve() == source.resolve() or (path.exists() and source.samefile(path))
    ):
        raise ValueError("Report destination must differ from the source recording")
    _atomic_text(path, json.dumps(report, ensure_ascii=False, indent=2) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    replay = commands.add_parser("replay", help="Decode a complete read-only session")
    replay.add_argument("path", type=Path)
    replay.add_argument("--output", type=Path)
    for name in ("calibration", "poll"):
        command = commands.add_parser(name, help=f"Decode a {name} recording")
        command.add_argument("path", type=Path)
        command.add_argument(
            "--ecu", help="Configured ECU label (default: first in recording)"
        )
        command.add_argument("--output", type=Path)
        if name == "poll":
            command.add_argument("--samples", type=int, default=1)
    args = parser.parse_args()
    try:
        report = replay_session(
            args.path,
            operation=args.command,
            ecu=getattr(args, "ecu", None),
            samples=getattr(args, "samples", 1),
        )
        if args.output:
            save_report(args.output, report, source=args.path)
        else:
            print(json.dumps(report, ensure_ascii=False, indent=2))
    except (OSError, ValueError) as exc:
        print(f"session: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
