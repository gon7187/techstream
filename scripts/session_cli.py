"""Run a deterministic diagnostic session without an adapter or original data."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
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
    service: int = 1,
    sensor: int = 1,
    pids: Sequence[int] | None = None,
    freeze: bool = False,
) -> dict:
    if not path.is_file():
        raise ValueError("Choose an ordinary local recording file")
    replay = Replay.load(path)
    session = Session(replay.exchange, cancelled=cancelled)
    selected = ecu or replay.ecus[0]
    if selected not in replay.ecus:
        raise ValueError("Selected ECU is not present in this recording")
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
    elif operation == "monitors":
        report = session.monitors(selected)
    elif operation == "support":
        report = {
            "ecu": selected,
            "physical_status": "PHYSICAL_UNCONFIRMED",
            "service": service,
            "sensor": sensor if service == 5 else None,
            "supported_pids": session.support(selected, service, sensor=sensor),
        }
    elif operation == "parameters":
        report = session.parameters(selected, pids=pids, freeze=freeze)
    elif operation == "vehicle_info":
        report = session.information(selected)
    else:
        raise ValueError("Unknown recording operation")
    replay.assert_complete()
    return {"source": replay.source, **report}


def parse_pids(text: str) -> list[int] | None:
    """A shared hexadecimal PID list for CLI and desktop, empty means advertised."""
    try:
        pids = [int(item, 16) for item in text.replace(",", " ").split()]
    except ValueError as exc:
        raise ValueError(
            "PIDs must be hexadecimal bytes separated by commas or spaces"
        ) from exc
    if any(not 0 <= pid <= 255 for pid in pids) or len(set(pids)) != len(pids):
        raise ValueError("PIDs must be unique hexadecimal bytes")
    return pids or None


def save_report(
    path: Path,
    report: dict,
    *,
    source: Path | None = None,
    sources: Sequence[Path] = (),
) -> None:
    for original in (*sources, *((source,) if source is not None else ())):
        original.stat()
        if path.resolve() == original.resolve() or (
            path.exists() and original.samefile(path)
        ):
            raise ValueError("Report destination must differ from every source file")
    _atomic_text(path, json.dumps(report, ensure_ascii=False, indent=2) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    replay = commands.add_parser("replay", help="Decode a complete read-only session")
    replay.add_argument("path", type=Path)
    replay.add_argument("--output", type=Path)
    for name in (
        "calibration",
        "poll",
        "monitors",
        "support",
        "parameters",
        "vehicle_info",
    ):
        command = commands.add_parser(name, help=f"Decode a {name} recording")
        command.add_argument("path", type=Path)
        command.add_argument(
            "--ecu", help="Configured ECU label (default: first in recording)"
        )
        command.add_argument("--output", type=Path)
        if name == "poll":
            command.add_argument("--samples", type=int, default=1)
        if name == "support":
            command.add_argument(
                "--service", type=int, choices=(1, 2, 5, 6, 9), default=1
            )
            command.add_argument(
                "--sensor",
                type=int,
                default=1,
                help="Legacy service 05 one-bit sensor mask",
            )
        if name == "parameters":
            command.add_argument(
                "--pids",
                default="",
                help="Hex PID list, e.g. '0C,0D'; default: all advertised defined PIDs",
            )
            command.add_argument(
                "--freeze", action="store_true", help="Read service 02 frame zero"
            )
    args = parser.parse_args()
    try:
        report = replay_session(
            args.path,
            operation=args.command,
            ecu=getattr(args, "ecu", None),
            samples=getattr(args, "samples", 1),
            service=getattr(args, "service", 1),
            sensor=getattr(args, "sensor", 1),
            pids=parse_pids(getattr(args, "pids", "")),
            freeze=getattr(args, "freeze", False),
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
