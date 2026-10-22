"""Selected native active-test lists and initialization metadata.

No transport is opened and no support is inferred from the existence of a row.
"""

from __future__ import annotations

import struct
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, field
from typing import Any

from scripts.local_files import read_regular
from scripts.profiles import VehicleProfile
from scripts.signal_conversion import i32
from scripts.support import (
    check_active_support,
    check_active_support_p4,
    check_did_bit_support,
    check_p5_active_support,
    check_panel_support,
    check_routine_support,
    check_subaru_active_support,
    check_subaru_routine_support,
    correspondence_rows,
    word,
)
from scripts.toyota import ToyotaCodecError, VariableTable
from scripts.toyota_session import CommandSpec, ToyotaSession

MISSING = 0xC0040101
INVALID = 0xC0040102
LEGACY = frozenset(("p3", "dk", "p4", "old_body", "sa"))
FAMILIES = LEGACY | {"p5", "routine"}


def dword(row: bytes, offset: int) -> int:
    return struct.unpack_from("<I", row, offset)[0]


def _u32(value: int) -> int:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("Native active value must be uint32")
    return value


def _bool(value: bool) -> bool:
    if type(value) is not bool:
        raise ValueError("Support provider must return bool")
    return value


@dataclass(frozen=True)
class ActiveTest:
    family: str
    signal_id: int
    name: str
    short_name: str | None
    record: bytes = field(repr=False)
    provenance: str
    routine: bool = False
    control_value: int = 0
    order: int = 0
    short_name_bytes: bytes = field(default=b"", repr=False)

    def report(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "signal_id": self.signal_id,
            "name": self.name,
            "short_name": self.short_name,
            "short_name_hex": self.short_name_bytes.hex()
            if self.short_name is None
            else None,
            "routine": self.routine,
            "control_value": self.control_value,
            "order": self.order,
            "provenance": self.provenance,
            "physical_status": "PHYSICAL_UNCONFIRMED",
        }


@dataclass(frozen=True)
class ActiveDisplay:
    identifier: int
    text: str
    press: int | bytes
    release: int | bytes
    enabled: bool


@dataclass(frozen=True)
class ActiveTestInitialization:
    test: ActiveTest
    initial_value: int
    minimum: int
    maximum: int
    pattern: bytes | None = field(repr=False)
    physical: bytes | None = field(repr=False)
    unit: str
    unit_function: int
    controls: dict[str, int]
    displays: tuple[ActiveDisplay, ...]
    text_ids: dict[str, int]
    current_value_pid: int = 0
    current_value_supported: bool = False
    bit_length: int = 0
    graph_minimum: int = 0
    graph_maximum: int = 0
    routine_labels: tuple[ActiveDisplay, ...] = ()
    routine_inputs: tuple[ActiveDisplay, ...] = ()
    routine_buttons: tuple[ActiveDisplay, ...] = ()
    completion_patterns: tuple[bytes, ...] = ()
    failure_patterns: tuple[bytes, ...] = ()
    display_data_length: int = 0
    routine_status_supported: bool = False
    routine_spec_id: int = 0
    command: bytes = field(default=b"", repr=False)
    output_mask: bytes = field(default=b"", repr=False)
    button_mask: bytes = field(default=b"", repr=False)

    def report(self) -> dict[str, Any]:
        def display(item: ActiveDisplay) -> dict[str, Any]:
            return {
                "id": item.identifier,
                "text": item.text,
                "press": item.press.hex()
                if isinstance(item.press, bytes)
                else item.press,
                "release": item.release.hex()
                if isinstance(item.release, bytes)
                else item.release,
                "enabled": item.enabled,
            }

        return {
            **self.test.report(),
            "initial_value": self.initial_value,
            "minimum": self.minimum,
            "maximum": self.maximum,
            "bit_length": self.bit_length,
            "graph_minimum": self.graph_minimum,
            "graph_maximum": self.graph_maximum,
            "unit": self.unit,
            "unit_function": self.unit_function,
            "controls": self.controls,
            "displays": [display(item) for item in self.displays],
            "text_ids": self.text_ids,
            "current_value_pid": self.current_value_pid,
            "current_value_supported": self.current_value_supported,
            "routine_labels": [display(item) for item in self.routine_labels],
            "routine_inputs": [display(item) for item in self.routine_inputs],
            "routine_buttons": [display(item) for item in self.routine_buttons],
            "completion_patterns": [item.hex() for item in self.completion_patterns],
            "failure_patterns": [item.hex() for item in self.failure_patterns],
            "display_data_length": self.display_data_length,
            "routine_status_supported": self.routine_status_supported,
            "routine_spec_id": self.routine_spec_id,
            "physical": None
            if self.physical is None
            else {
                "multiplier": struct.unpack_from("<i", self.physical, 0)[0],
                "divisor": struct.unpack_from("<i", self.physical, 4)[0],
                "offset": struct.unpack_from("<i", self.physical, 8)[0],
                "sign_mode": self.physical[20],
                "precision": self.physical[21],
            },
        }


@dataclass(frozen=True)
class ActiveSupport:
    """Explicit observed gates; adapters must retain their native error policy."""

    legacy: Callable[[str, bytes], bool] | None = None
    did: Callable[[int], bool] | None = None
    rid: Callable[[int], bool] | None = None
    panel: Callable[[int, int], bool] | None = None
    pid: Callable[[int], bool] | None = None
    did_subaru: Callable[[int], bool] | None = None
    rid_subaru: Callable[[int], bool] | None = None
    bit: Callable[[int, int, int], bool] | None = None
    routine_probe: Callable[[int, int], bool] | None = None
    sa_finalize: Callable[[], None] | None = None


def _gate(provider: Callable[..., bool] | None, *args: object) -> bool:
    if provider is None:
        raise ValueError("Required native active support provider is missing")
    return _bool(provider(*args))


class ActiveTestCatalog:
    def __init__(self, profile: VehicleProfile):
        if profile.database.version not in (0x0100030C, 0x0100032F):
            raise ValueError(
                "Native active metadata is recovered for v12/v18 DDB layouts only"
            )
        self.profile = profile
        self._selected_rows: dict[int, tuple[bytes, ...]] = {}

    def _rows(self, slot: int) -> tuple[bytes, ...]:
        if slot not in self._selected_rows:
            self._selected_rows[slot] = self.profile.records(slot)
        return self._selected_rows[slot]

    def _lookup_rows(self, slot: int) -> tuple[bytes, ...]:
        if slot not in self.profile.database.sections:
            raise ToyotaCodecError(
                f"Selected active table {slot:#x} is absent", 0xA0030107
            )
        return self._rows(slot)

    def _first(
        self, slot: int, key: int, offset: int, *, required: bool = True
    ) -> bytes | None:
        # GetDbRecord selects a group; Init consumes its FIRST selected row.
        result = next(
            (row for row in self._lookup_rows(slot) if word(row, offset) == key), None
        )
        if result is None and required:
            raise ToyotaCodecError(
                f"Missing selected active dependency {slot:#x}:{key:#x}", MISSING
            )
        return result

    def _test(self, family: str, row: bytes, *, routine: bool = False) -> ActiveTest:
        modern = family in ("p5", "routine")
        name_offset, signal_offset = (
            ((8, 30) if routine else (12, 32)) if modern else (32, 56)
        )
        old_routine = routine and self.profile.database.version == 0x0100030C
        width = (60 if old_routine else 64) if modern else 92
        if len(row) != width:
            raise ToyotaCodecError("Active record has incorrect native width", INVALID)
        short_bytes = b""
        short_name: str | None = ""
        if not modern:
            end = row.find(b"\0", 0, 20)
            if end < 0:
                raise ToyotaCodecError("Unterminated native active short name", INVALID)
            short_bytes = row[:end]
            try:
                short_name = short_bytes.decode("ascii")
            except UnicodeDecodeError:
                short_name = None  # original ACP/locale remains caller-owned
        return ActiveTest(
            family,
            word(row, signal_offset),
            self.profile.catalog.language.resolve(dword(row, name_offset)),
            short_name,
            row,
            f"DDB:{self.profile.database.sha256}:2/{71 if routine else 68 if modern else 11}:category={self.profile.category}:signal={word(row, signal_offset)}",
            routine,
            dword(row, 12 if routine else 16 if modern else 40),
            word(row, (54 if old_routine else 56) if routine else 44) if modern else 0,
            short_bytes,
        )

    def initial_value_reader(
        self,
        session: ToyotaSession,
        *,
        positions: Mapping[int, bytes],
    ) -> Callable[[str, bytes], int | None]:
        """Bind native 6B/CA reads to selected frames, physical metadata and cache.

        Each read gets its own bounded session budget, matching the native
        independent GetEcuData calls. Native read failures return unavailable;
        host cancellation/deadline and missing selected inputs stay errors.
        """
        commands: dict[str, CommandSpec] = {}
        bound = ToyotaSession(
            session.exchange,
            session.ecu,
            commands,
            limits=session.limits,
            cancelled=session.cancelled,
            clock=session.clock,
        )
        bound.trace = session.trace

        def read(kind: str, row: bytes) -> int | None:
            if kind not in ("p3", "p4", "p5-active", "p5-monitor"):
                raise ValueError("Unknown native initial-value reader")
            function = 0xCA if kind.startswith("p5-") else 0x6B
            if kind not in bound.commands:
                try:
                    selected = self.profile.frame_records(function)
                except ValueError:
                    # The profile raises for an absent function. Distinguish
                    # native unavailability from corrupt selected dependencies.
                    functions = correspondence_rows(
                        self.profile.catalog.management, 18, self.profile.exception_ids
                    )
                    if any(
                        word(item, 0) == self.profile.category
                        and word(item, 2) == function
                        for item in functions
                    ):
                        raise
                    return None
                if len(selected) != 1:
                    # Native read fails before I/O; Init keeps its constant.
                    return None
                try:
                    bound.commands[kind] = CommandSpec(
                        selected[0].frame, provenance=selected[0].provenance
                    )
                except ToyotaCodecError:
                    return None
            if kind in ("p3", "p4"):
                physical = self._first(13, word(row, 60), 12)
                assert physical is not None
                if kind == "p4" and row[79] not in positions:
                    raise ValueError(
                        "P4 initial-value support-position cache is missing"
                    )
            try:
                if kind == "p5-active":
                    return bound.read_active_initial_p5(kind, row)
                if kind == "p5-monitor":
                    return bound.read_monitor_initial_p5(kind, row)
                if kind == "p3":
                    return bound.read_initial_p3(kind, row, physical)
                return bound.read_initial_p4(kind, row, physical, positions[row[79]])
            except ToyotaCodecError:
                return None

        return read

    def observed_support(
        self,
        family: str,
        *,
        protocol: int,
        pid_lengths: Mapping[int, int],
        did_lengths: Mapping[int, int],
        enabled_dids: Collection[int],
        enabled_rids: Collection[int],
        check_bits: Callable[[int, int, int], bool],
        exchange: Callable[[bytes], bytes],
        pid_support: Callable[[int], bool] | None = None,
        routine_probe: Callable[[int, int], bool] | None = None,
        sa_finalize: Callable[[], None] | None = None,
    ) -> ActiveSupport:
        """Bind recovered support algorithms to this profile and observed inputs.

        The exchange callback must enforce I/O timeout, cancellation and deadline.
        Caches belong to this binding; construct a fresh binding after context or
        observed support changes. No global cache or implicit available values.
        """
        if (
            family not in FAMILIES
            or type(protocol) is not int
            or not 0 <= protocol <= 255
        ):
            raise ValueError("Selected native family and uint8 protocol required")
        section = self.profile.catalog.management.sections.get(0)
        if section is None:
            raise ToyotaCodecError("Missing management variables", MISSING)
        variables = VariableTable(section.payload, section.count)
        did_cache: dict[int, bool] = {}
        subaru_did_cache: dict[int, bool] = {}
        rid_cache: dict[int, bool] = {}
        subaru_rid_cache: dict[int, bool] = {}
        lengths: dict[int, int] = dict(did_lengths)
        frames = self.profile.command_frames

        def bits(reference: int):
            return self.profile.did_bits((reference,)) if reference else {}

        def legacy(selected_family: str, row: bytes) -> bool:
            if selected_family == "p4":
                return check_active_support_p4(row, pid_lengths, check_bits)
            return check_active_support(
                row,
                pid_lengths,
                did_lengths,
                bits(word(row, 60))
                if row[83] == 0
                and (did_lengths.get(row[82], 0) & 255) * 8 > word(row, 68)
                else {},
                frames,
                exchange,
                old_body=selected_family == "old_body",
            )

        def panel(reference: int, mode: int) -> bool:
            if family in LEGACY:
                return check_did_bit_support(
                    reference,
                    mode,
                    bits(reference) if mode == 0 else {},
                    pid_lengths,
                    did_lengths,
                    frames,
                    exchange,
                    old_body=family != "p4",
                )
            return check_panel_support(
                reference,
                mode,
                {word(row, 0): row for row in self._rows(70)} if mode == 0 else {},
                variables,
                frames,
                exchange,
            )

        def did(key: int) -> bool:
            row = self._first(68, key, 32)
            assert row is not None
            return check_p5_active_support(
                row,
                protocol,
                enabled_dids,
                tuple(item for item in self._rows(67) if word(item, 2) == word(row, 52))
                if word(row, 52) in enabled_dids
                else (),
                did_cache,
                lengths,
                {word(item, 0): item for item in self._rows(69)}
                if word(row, 34)
                else {},
                variables,
                frames,
                exchange,
            )

        def did_subaru(key: int) -> bool:
            row = self._first(68, key, 32)
            assert row is not None
            return check_subaru_active_support(
                row,
                subaru_did_cache,
                {word(item, 0): item for item in self._rows(69)}
                if word(row, 34)
                else {},
                variables,
                frames,
                exchange,
            )

        def rid(key: int) -> bool:
            row = self._first(71, key, 30)
            assert row is not None
            return check_routine_support(
                row,
                enabled_rids,
                rid_cache,
                database_version=self.profile.database.version,
            )

        def rid_subaru(key: int) -> bool:
            row = self._first(71, key, 30)
            assert row is not None
            return check_subaru_routine_support(
                row,
                enabled_dids,
                subaru_rid_cache,
                {word(item, 0): item for item in self._rows(142)}
                if word(row, 32)
                else {},
                variables,
                frames,
                exchange,
            )

        return ActiveSupport(
            legacy=legacy,
            did=did,
            rid=rid,
            panel=panel,
            pid=pid_support,
            did_subaru=did_subaru,
            rid_subaru=rid_subaru,
            bit=check_bits,
            routine_probe=routine_probe,
            sa_finalize=sa_finalize,
        )

    def list(self, family: str, *, support: ActiveSupport) -> tuple[ActiveTest, ...]:
        """Native List variants; p5 includes ordinary and routine entries."""
        if family not in FAMILIES:
            raise ValueError("Unknown native active family")
        if family in ("p5", "routine"):
            subaru = (
                self.profile.database.version == 0x0100032F
                and self.profile.category_record[72] & 0xE0 == 0x20
            )
            did_gate = support.did_subaru if subaru else support.did
            rid_gate = support.rid_subaru if subaru else support.rid
            selected = []
            if family == "p5":
                multi = self._rows(33)
                for row in self._rows(68):
                    key = word(row, 32)
                    parent = None
                    child = False
                    # Native scans source order and stops at the FIRST child
                    # or parent match. A later child match does not override it.
                    for item in multi:
                        if word(item, 2) == key:
                            child = True
                            break
                        if word(item, 0) == key:
                            parent = key
                            break
                    if child or not _gate(did_gate, key):
                        continue
                    if parent is not None and not all(
                        _gate(did_gate, word(item, 2))
                        for item in multi
                        if word(item, 0) == parent
                    ):
                        continue
                    selected.append(self._test(family, row))
            for row in self._rows(71):
                if _gate(rid_gate, word(row, 30)):
                    selected.append(self._test("routine", row, routine=True))
            # Native exchanges each outer node with any later smaller node.
            # A stable sort changes equal-order results after a distant swap.
            for first in range(len(selected)):
                for second in range(first + 1, len(selected)):
                    if selected[first].order > selected[second].order:
                        selected[first], selected[second] = (
                            selected[second],
                            selected[first],
                        )
            return tuple(selected)
        rows = self._rows(11)
        if family in ("p3", "dk", "old_body"):
            return tuple(
                self._test(family, row)
                for row in rows
                if _gate(support.legacy, family, row)
            )
        multi = self._rows(33)
        selected = []
        for row in rows:
            key = word(row, 56)
            children = tuple(item for item in multi if word(item, 0) == key)
            available = _gate(support.legacy, "p4", row)
            if not available and not any(item[11] & 1 for item in children):
                continue
            if children:
                optional_failures, accepted = 0, True
                for child in children:
                    child_row = self._first(11, word(child, 2), 56)
                    assert child_row is not None
                    if not _gate(support.legacy, "p4", child_row):
                        if child[11] & 1:
                            optional_failures += 1
                        else:
                            accepted = False
                            break
                if optional_failures == len(children) or not accepted:
                    continue
            elif any(word(item, 2) == key for item in multi):
                continue
            pattern = row[85]
            if pattern in (20, 21, 22, 23):
                start = word(row, 66) & 0xFFF8
                first = _gate(support.bit, row[82], start, start + 7)
                second = _gate(
                    support.bit, row[82], (start + 8) & 65535, (start + 15) & 65535
                )
                if (first and second) == (pattern in (20, 21)):
                    continue
            selected.append(self._test(family, row))
        if family == "sa" and selected:
            if support.sa_finalize is None:
                raise ValueError("Native SA finalization provider is missing")
            support.sa_finalize()
        return tuple(selected)

    def initialize(
        self,
        family: str,
        signal_id: int,
        *,
        support: ActiveSupport,
        read_value: Callable[[str, bytes], int | None] | None = None,
    ) -> ActiveTestInitialization:
        """GetActTstInit variants; I/O is explicit, cancellation stays visible.

        read_value returns None for a completed native read failure. It must
        propagate cancellation/deadline errors; no host policy is suppressed.
        """
        if family not in FAMILIES or family in ("old_body", "sa"):
            raise ValueError("No separate native Init export for this family")
        if type(signal_id) is not int or not 0 <= signal_id <= 65535:
            raise ValueError("Active signal ID must be uint16")
        modern, routine = family in ("p5", "routine"), family == "routine"
        row = self._first(
            71 if routine else 68 if modern else 11,
            signal_id,
            30 if routine else 32 if modern else 56,
        )
        assert row is not None
        test = self._test(family, row, routine=routine)
        initial, minimum, maximum = (
            (0, dword(row, 4), dword(row, 0))
            if routine
            else tuple(dword(row, i) for i in ((0, 8, 4) if modern else (20, 28, 24)))
        )
        if not routine:
            init_mode, bound_mode = row[57 if modern else 84], row[60 if modern else 89]
            if init_mode not in (0, 1) or bound_mode not in (0, 1, 2, 3):
                raise ToyotaCodecError("Invalid active initialization mode", INVALID)

            def read(slot: int, key: int, offset: int, current: int, kind: str) -> int:
                if key == 0:
                    return current
                selected = self._first(slot, key, offset)
                assert selected is not None
                if read_value is None:
                    raise ValueError(
                        "Native active initialization read provider is missing"
                    )
                value = read_value(kind, selected)
                return current if value is None else _u32(value)

            if modern:
                if init_mode == 0:
                    initial = read(68, word(row, 32), 32, initial, "p5-active")
            elif init_mode == 1:
                initial = read(
                    10, word(row, 58), 56, initial, "p4" if family == "p4" else "p3"
                )
            else:
                initial = 0
            if bound_mode in (1, 3):
                maximum = read(
                    62 if modern else 10,
                    word(row, 48 if modern else 76),
                    36 if modern else 56,
                    maximum,
                    "p5-monitor" if modern else "p4" if family == "p4" else "p3",
                )
            if bound_mode in (2, 3):
                minimum = read(
                    62 if modern else 10,
                    word(row, 50 if modern else 78),
                    36 if modern else 56,
                    minimum,
                    "p5-monitor" if modern else "p4" if family == "p4" else "p3",
                )
        routine_shift = (
            2 if routine and self.profile.database.version == 0x0100030C else 0
        )
        pattern_key = word(row, 36 - routine_shift if routine else 38 if modern else 64)
        physical_key = word(
            row, 34 - routine_shift if routine else 36 if modern else 62
        )
        pattern = self._first(12, pattern_key, 0, required=False)
        physical = self._first(13, physical_key, 12, required=False)
        unit_row = (
            None
            if physical is None
            else self._first(15, word(physical, 14), 4, required=False)
        )
        unit = (
            ""
            if unit_row is None
            else self.profile.catalog.language.resolve(dword(unit_row, 0))
        )
        controls = {}
        if pattern is not None:
            controls = {
                "pattern": 0 if routine else row[58 if modern else 85],
                "key_operation_pattern": pattern[19],
                "key_invalid_flag": pattern[18],
                "maintenance_time": word(pattern, 4),
                "auto_continue_time": word(pattern, 6),
                "button_size": pattern[21],
                "lock_time": word(pattern, 12),
            }
        displays: tuple[ActiveDisplay, ...] = ()
        if pattern is not None and not routine:
            old_display = self.profile.database.version == 0x0100030C
            group_offset = 4 if old_display else 12
            displays = tuple(
                ActiveDisplay(
                    word(display, group_offset),
                    self.profile.catalog.language.resolve(dword(display, 0)),
                    i32(word(display, 10) if old_display else dword(display, 4)),
                    i32(word(display, 12) if old_display else dword(display, 8)),
                    _gate(
                        support.panel,
                        word(display, 14 if old_display else 18),
                        display[18 if old_display else 22],
                    ),
                )
                for display in self._lookup_rows(14)
                if word(display, group_offset) == word(pattern, 10)
            )
        texts: dict[str, int] = dict(
            zip(
                ("caution", "help", "prohibition", "info", "comment"),
                (
                    dword(row, i)
                    for i in (
                        (20, 12, 24, 16, 0)
                        if routine
                        else (24, 16, 28, 20, 0)
                        if modern
                        else (48, 40, 52, 44, 36)
                    )
                ),
                strict=True,
            )
        )
        if modern:
            texts["comment"] = 0
        current_pid, current_supported = 0, False
        if modern and not routine:
            if row[61] == 1:
                current_pid = word(row, 54)
            else:
                monitors = self._rows(62)
                if not monitors:
                    raise ToyotaCodecError("No selected P5 monitor rows", 0xC0050101)
                current_pid = next(
                    (
                        word(monitor, 36)
                        for monitor in monitors
                        if dword(monitor, 32) & 0x40
                        and word(row, 52) == word(monitor, 54)
                        and word(row, 40) == word(monitor, 44)
                        and word(row, 42) == word(monitor, 46)
                        and not 7000 <= word(monitor, 36) <= 9999
                    ),
                    0,
                )
            current_supported = _gate(support.pid, current_pid)
        result = ActiveTestInitialization(
            test,
            i32(initial),
            i32(minimum),
            i32(maximum),
            pattern,
            physical,
            unit,
            0 if unit_row is None else word(unit_row, 6),
            controls,
            displays,
            texts,
            current_pid,
            current_supported,
        )
        return self._routine_initialization(result, support) if routine else result

    def _routine_initialization(
        self, result: ActiveTestInitialization, support: ActiveSupport
    ) -> ActiveTestInitialization:
        from dataclasses import replace

        section = self.profile.catalog.management.sections.get(0)
        if section is None:
            raise ToyotaCodecError("Missing management variables", MISSING)
        variables = VariableTable(section.payload, section.count)
        row = result.test.record
        last_length = 0

        def group(key: int, check_support: bool) -> tuple[ActiveDisplay, ...]:
            nonlocal last_length
            selected = tuple(
                item for item in self._lookup_rows(73) if word(item, 4) == key
            )
            if not selected:
                last_length = 0
                return ()
            # Native helper overwrites its shared data length on EVERY group,
            # including the final scalar-buttons group.
            last_length = len(variables.get(word(selected[0], 10)))
            return tuple(
                ActiveDisplay(
                    word(item, 4),
                    self.profile.catalog.language.resolve(dword(item, 0)),
                    variables.get(word(item, 10)),
                    variables.get(word(item, 12)),
                    _gate(support.panel, word(item, 14), item[18])
                    if check_support
                    else False,
                )
                for item in selected
            )

        shift = 2 if self.profile.database.version == 0x0100030C else 0
        labels = group(word(row, 50 - shift), False)
        inputs = group(word(row, 52 - shift), True)
        buttons = group(word(row, 54 - shift), False)

        def statuses(key: int) -> tuple[bytes, ...]:
            return tuple(
                variables.get(word(item, 2))
                for item in self._rows(72)
                if word(item, 0) == key
            )

        def scalar(data: bytes) -> int:
            value = 0
            for index, byte in enumerate(data):
                value |= (byte << (((len(data) - index - 1) * 8) & 31)) & 0xFFFFFFFF
            return i32(value)

        return replace(
            result,
            displays=tuple(
                ActiveDisplay(
                    item.identifier,
                    item.text,
                    scalar(item.press),
                    scalar(item.release),
                    item.enabled,
                )
                for item in buttons
                if isinstance(item.press, bytes) and isinstance(item.release, bytes)
            ),
            routine_labels=labels,
            routine_inputs=inputs,
            routine_buttons=buttons,
            completion_patterns=statuses(word(row, 46 - shift)),
            failure_patterns=statuses(word(row, 48 - shift)),
            display_data_length=last_length,
            routine_status_supported=_gate(
                support.routine_probe, word(row, 28), last_length
            ),
            routine_spec_id=word(row, 38 - shift),
            command=variables.get(word(row, 40 - shift)),
            output_mask=variables.get(word(row, 42 - shift)),
            button_mask=variables.get(word(row, 44 - shift)),
        )


@dataclass(frozen=True, repr=False)
class SAKeyMaterial:
    """Local-only operands. Never include this object in reports or logs."""

    xor_operand: int = field(repr=False)
    subtract_operand: int = field(repr=False)

    def __post_init__(self) -> None:
        _u32(self.xor_operand)
        _u32(self.subtract_operand)

    @classmethod
    def from_library(cls, path: str) -> SAKeyMaterial:
        """Read operands from the SHA-verified original 12/18 SA library; no PE execution."""
        import hashlib

        image = read_regular(path, limit=57344)
        if len(image) != 57344 or hashlib.sha256(image).hexdigest() not in {
            "8fd695da0971cd5d97b18c4a9d6798ebb3bcb94ff9aa8e02399068b2d43ebe72",
            "4ce2078572a6dfc21a449e32095e4f806ea90434f097e40c1f3c7df6a9631955",
        }:
            raise ValueError(
                "SA library identity does not match the recovered native build"
            )
        # .text has matching file offset/RVA in both verified builds. Immediate
        # operands: XOR at RVA1b0b+1; signed LEA displacement at RVA1b28+2.
        return cls(dword(image, 0x1B0C), (-dword(image, 0x1B2A)) & 0xFFFFFFFF)

    def derive(self, seed: int) -> int:
        if type(seed) is not int or not 0 <= seed <= 65535:
            raise ValueError("SA seed must fit uint16")
        first = (((seed ^ self.xor_operand) >> 2) & 65535) + ((~seed & 3) << 14)
        return ((((first - self.subtract_operand) & 0xFFFFFFFF) >> 3) & 0x1FFF) + (
            ((first - 1) << 13) & 65535
        )


class SAFinalizer:
    """Actual native EB/EC finalization, with bounded injected I/O and no key trace."""

    def __init__(
        self, profile: VehicleProfile, session: ToyotaSession, material: SAKeyMaterial
    ):
        if not isinstance(material, SAKeyMaterial):
            raise TypeError("Explicit local SA key material is required")
        self.profile, self.session, self._material = profile, session, material

    def __call__(self) -> None:
        from scripts.toyota_session import Cancelled, SessionError

        first = self.profile.command_frames(0xEB)
        if len(first) != 1:
            raise ToyotaCodecError(
                "SA finalization requires one selected EB frame", MISSING
            )
        session = self.session
        deadline, remaining = (
            session.clock() + session.limits.seconds,
            session.limits.exchanges,
        )

        def check() -> None:
            if session.cancelled():
                raise Cancelled("SA finalization cancelled")
            if session.clock() >= deadline:
                raise SessionError("SA finalization deadline exceeded")

        def exchange(request: bytes) -> bytes:
            nonlocal remaining
            check()
            if remaining <= 0:
                raise SessionError("SA exchange budget exhausted")
            remaining -= 1
            try:
                reply = session.exchange(session.ecu, request)
            except BaseException:
                check()
                raise
            check()
            if not isinstance(reply, bytes):
                raise TypeError("SA exchange must return bytes")
            return reply

        try:
            reply = exchange(first[0].request)
            first[0].check_reply(reply)
        except ToyotaCodecError:
            return  # native seed transport failure is non-fatal
        if len(reply) < 4:
            return
        seed = int.from_bytes(reply[2:4], "big")
        if seed:
            second = self.profile.command_frames(0xEC)
            if len(second) != 1 or len(second[0].request) < 4:
                raise ToyotaCodecError(
                    "SA finalization requires one selected EC frame", MISSING
                )
            key = self._material.derive(seed) & 65535
            request = (
                second[0].request[:2] + key.to_bytes(2, "big") + second[0].request[4:]
            )
            try:
                second[0].check_reply(exchange(request))
            except ToyotaCodecError:
                pass  # native ignores the final communication result
