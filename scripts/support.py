"""Evidence-backed DDB correspondence indexes and PID support evaluation.

No device is opened. All dynamic support data is supplied by the caller.
"""

from __future__ import annotations

import struct
from collections.abc import Callable, Collection, Mapping, MutableMapping, Sequence
from dataclasses import dataclass

from scripts.diagnostic_db import Database
from scripts.signal_conversion import extract_bits
from scripts.toyota import (
    INVALID_RECORD,
    MISSING_RECORD,
    SHORT_REPLY,
    CommandFrame,
    ToyotaCodecError,
    VariableTable,
    pid_support_p3,
)


def word(row: bytes, offset: int) -> int:
    return struct.unpack_from("<H", row, offset)[0]


@dataclass(frozen=True)
class TableSchema:
    width: int
    key_offsets: tuple[int, ...]
    exception_offset: int
    flag_offset: int
    key_formats: tuple[str, ...] = ()
    ordered_defaults: bool = True

    def key(self, row: bytes) -> tuple[int, ...]:
        if len(row) != self.width:
            raise ValueError("Incorrect correspondence row width")
        return tuple(
            struct.unpack_from("<" + fmt, row, offset)[0]
            for offset, fmt in zip(
                self.key_offsets,
                self.key_formats or ("H",) * len(self.key_offsets),
                strict=True,
            )
        )


# Fields follow the corresponding named GetExceptahand*/ComparativeKey methods.
SCHEMAS = {
    (1, 5): TableSchema(12, (4,), 8, 10),
    (1, 44): TableSchema(24, (4, 22, 6), 14, 20),
    (1, 13): TableSchema(28, (0, 24), 12, 25, ("H", "B")),
    (1, 16): TableSchema(76, (68,), 70, 73),
    (1, 18): TableSchema(16, (0, 2, 10), 8, 14),
    (1, 19): TableSchema(88, (86, 80), 82, 87, ("B", "H")),
    (1, 20): TableSchema(12, (8, 4), 6, 10, ("B", "H")),
    (1, 21): TableSchema(52, (8, 10), 36, 51),
    (1, 25): TableSchema(12, (4, 6), 8, 10),
    (1, 26): TableSchema(24, (8, 20), 18, 23),
    (1, 27): TableSchema(24, (4, 6, 8), 16, 22),
    (1, 29): TableSchema(16, (10,), 8, 15),
    (1, 48): TableSchema(24, (0, 12), 14, 22),
    (1, 54): TableSchema(44, (16, 30), 32, 42),
    (1, 62): TableSchema(24, (0, 16), 18, 22),
    (1, 73): TableSchema(12, (6, 7), 4, 10, ("B", "B")),
    (1, 88): TableSchema(36, (16, 26), 28, 35),
    (2, 0): TableSchema(12, (8,), 6, 9, ("B",)),
    (2, 1): TableSchema(8, (0,), 4, 6),
    # Original ABS defaults are unsorted; native MakeIndex preserves their order.
    (2, 2): TableSchema(4, (2,), 0, 3, ("B",), False),
    (2, 3): TableSchema(8, (4,), 0, 6, ("B",)),
    (2, 4): TableSchema(8, (4,), 0, 6, ("B",)),
    (2, 7): TableSchema(8, (4,), 0, 6, ("B",)),
    (2, 5): TableSchema(28, (20,), 22, 27, ordered_defaults=False),
    (2, 6): TableSchema(8, (2,), 0, 6, ("B",)),
    (2, 32): TableSchema(10, (0,), 4, 6),
    (2, 8): TableSchema(12, (0,), 4, 10),
    (2, 9): TableSchema(12, (0,), 4, 11),
    (2, 10): TableSchema(84, (79, 56), 72, 82, ("B", "H")),
    (2, 11): TableSchema(92, (82, 56), 72, 87, ("B", "H")),
    (2, 12): TableSchema(24, (0,), 14, 22),
    (2, 13): TableSchema(24, (12,), 16, 22),
    (2, 14): TableSchema(24, (12, 4), 16, 23, ("H", "I"), False),
    (2, 15): TableSchema(12, (4,), 8, 10),
    (2, 19): TableSchema(8, (0,), 4, 7),
    (2, 20): TableSchema(8, (4,), 0, 6, ("B",)),
    (2, 26): TableSchema(12, (0, 2), 6, 8),
    (2, 33): TableSchema(12, (0, 6), 8, 10),
    (2, 38): TableSchema(12, (0,), 6, 9),
    (2, 80): TableSchema(12, (0,), 4, 10),
    (2, 81): TableSchema(8, (0,), 4, 6),
    (2, 89): TableSchema(12, (0,), 4, 10),
    (2, 90): TableSchema(8, (2,), 0, 7),
    (2, 39): TableSchema(20, (8,), 14, 16),
    (2, 41): TableSchema(92, (80, 56), 72, 85, ("B", "H")),
    (2, 47): TableSchema(20, (8, 0), 14, 18, ("H", "I")),
    (2, 65): TableSchema(68, (44,), 60, 66, ("I",)),
    (2, 54): TableSchema(8, (2,), 0, 6),
    (2, 55): TableSchema(8, (4,), 2, 5, ("B",)),
    (2, 61): TableSchema(8, (2,), 0, 7),
    (2, 62): TableSchema(64, (36,), 52, 62),
    (2, 63): TableSchema(16, (0,), 4, 12),
    (2, 64): TableSchema(20, (10,), 16, 18),
    (2, 60): TableSchema(8, (0,), 4, 6),
    (2, 66): TableSchema(12, (0, 4), 6, 10, ("I", "H")),
    # Original MMC mode-4 default rows have unsorted mask values. MakeIndex
    # copies their source order; sorting or rejecting them changes native behavior.
    (2, 67): TableSchema(12, (2, 10, 4), 0, 11, ("H", "B", "H"), False),
    (2, 68): TableSchema(64, (32,), 46, 59),
    (2, 69): TableSchema(12, (0,), 4, 10),
    (2, 70): TableSchema(16, (0,), 10, 14),
    (2, 71): TableSchema(64, (30,), 58, 61),
    (2, 72): TableSchema(12, (0, 4), 6, 8),
    (2, 73): TableSchema(20, (4, 6), 8, 19),
    (2, 142): TableSchema(12, (0,), 4, 10),
}

# Exact factory registrations reuse these four native record classes. Additional
# DDR banks are distinct table IDs, not inferred filename/model associations.
DDR_TABLE_GROUPS = (
    (
        (50, 82, 92, 96, 100, 104, 110, 119, 123, 129, 138, 147),
        TableSchema(48, (24,), 40, 45),
    ),
    (
        (51, 83, 93, 97, 101, 105, 111, 120, 124, 130, 139, 148),
        TableSchema(36, (30, 31), 28, 32, ("B", "B")),
    ),
    (
        (52, 84, 94, 98, 102, 106, 112, 121, 125, 131, 140, 149),
        TableSchema(16, (10, 11, 4), 8, 12, ("B", "B", "H")),
    ),
    (
        (53, 85, 95, 99, 103, 107, 113, 122, 126, 132, 141, 150),
        TableSchema(16, (4, 8), 10, 14),
    ),
)
DDR_SLOTS = frozenset(slot for slots, _ in DDR_TABLE_GROUPS for slot in slots)
DDR_V12_SLOTS = frozenset(
    (50, 51, 52, 53, 82, 83, 84, 85, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103)
)
SCHEMAS.update(
    {(2, slot): schema for slots, schema in DDR_TABLE_GROUPS for slot in slots}
)


# These P5 DDR resource classes are present only in the recovered v18 factory.
DDR_P5_SCHEMAS = {
    133: TableSchema(44, (32, 40, 41), 34, 43, ("H", "B", "B")),
    134: TableSchema(60, (36,), 50, 58),
    135: TableSchema(24, (8, 12), 14, 18),
    **{slot: TableSchema(8, (0,), 4, 6) for slot in (108, 127, 136, 145)},
    **{
        slot: TableSchema(12, (0, 8, 9), 6, 10, ("H", "B", "B"))
        for slot in (109, 128, 137, 146)
    },
}
SCHEMAS.update({(2, slot): schema for slot, schema in DDR_P5_SCHEMAS.items()})

# P4 lists and Pattern are registered in both factories; the four P5 lists are v18-only.
WORK_FACTOR_SCHEMAS = {
    35: TableSchema(28, (4,), 16, 26),
    36: TableSchema(40, (20, 34), 32, 35, ("H", "B")),
    37: TableSchema(20, (8, 10), 14, 16),
    114: TableSchema(24, (16,), 20, 22),
    115: TableSchema(20, (4, 18), 14, 19, ("H", "B")),
    116: TableSchema(16, (8, 10), 12, 14),
    117: TableSchema(16, (14,), 10, 15, ("B",)),
}
SCHEMAS.update({(2, slot): schema for slot, schema in WORK_FACTOR_SCHEMAS.items()})


VERSION_SCHEMAS = {
    (0x0100030C, 2, 90): TableSchema(8, (2,), 0, 5),
    (0x0100030C, 2, 63): TableSchema(12, (0,), 4, 10),
    (0x0100030C, 1, 20): TableSchema(12, (8, 4), 6, 9, ("B", "H")),
    (0x0100030C, 1, 13): TableSchema(24, (0, 22), 12, 23, ("H", "B")),
    (0x0100030C, 2, 14): TableSchema(20, (4, 10), 8, 19, ordered_defaults=False),
    (0x0100030C, 2, 71): TableSchema(60, (30,), 56, 59),
}
VERSION_SCHEMAS.update(
    {
        (0x0100030C, 2, slot): TableSchema(32, (26, 27), 24, 28, ("B", "B"))
        for slot in (51, 83, 93, 97, 101)
    }
)


def correspondence_rows(
    database: Database, slot: int, exception_ids: Sequence[int] = ()
) -> tuple[bytes, ...]:
    """Native MakeIndex/SubstituteRecord: defaults, then ordered overlays.

    Exception order is meaningful. Flag 1 deletes a key, flag 2 replaces or
    inserts it. Other flags leave the index unchanged, as the native switch does.
    """
    if database.kind == 2 and slot in WORK_FACTOR_SCHEMAS:
        if database.version not in (0x0100030C, 0x0100032F):
            raise ValueError("No recovered WorkFactor schema for this database version")
        if slot not in (35, 36, 37) and database.version != 0x0100032F:
            raise ValueError(
                "P5 WorkFactor resource is absent from the version 12 factory"
            )
    if database.kind == 2 and slot in DDR_P5_SCHEMAS and database.version != 0x0100032F:
        raise ValueError(
            "P5 DDR resource is absent from the recovered version 12 factory"
        )
    if database.kind == 2 and slot in DDR_SLOTS:
        if database.version not in (0x0100030C, 0x0100032F):
            raise ValueError("No recovered DDR schema for this database version")
        if database.version == 0x0100030C and slot not in DDR_V12_SLOTS:
            raise ValueError("DDR table is absent from the version 12 factory")
    if (database.kind, slot) in {
        (1, 5),
        (1, 13),
        (1, 19),
        (1, 20),
        (1, 21),
        (1, 25),
        (1, 26),
        (1, 27),
        (1, 48),
        (1, 54),
        (1, 62),
        (1, 73),
        (1, 88),
        (2, 26),
        (2, 2),
        (2, 3),
        (2, 4),
        (2, 7),
        (2, 8),
        (2, 5),
        (2, 6),
        (2, 19),
        (2, 20),
        (2, 38),
        (2, 80),
        (2, 81),
        (2, 89),
        (2, 90),
        (2, 39),
        (2, 41),
        (2, 47),
        (2, 65),
        (2, 54),
        (2, 55),
        (2, 63),
        (2, 64),
        (2, 60),
        (2, 61),
    } and database.version not in (0x0100030C, 0x0100032F):
        raise ValueError("No recovered selection schema for this database version")
    schema = VERSION_SCHEMAS.get(
        (database.version, database.kind, slot), SCHEMAS.get((database.kind, slot))
    )
    if database.version == 0x0100030C and (database.kind, slot) == (1, 88):
        raise ValueError("CommRidData is absent from the recovered version 12 schema")
    if schema is None:
        raise ValueError("No recovered correspondence schema for this table")
    section = database.sections.get(slot)
    rows = section.rows(schema.width) if section else []
    exceptions = [word(row, schema.exception_offset) for row in rows]
    if exceptions != sorted(exceptions):
        raise ValueError("Native correspondence rows must be ordered by exception ID")
    selected = [row for row, ident in zip(rows, exceptions, strict=True) if ident == 0]
    keys = [schema.key(row) for row in selected]
    if schema.ordered_defaults and keys != sorted(keys):
        raise ValueError("Native default correspondence index is not sorted")
    for exception_id in exception_ids:
        if type(exception_id) is not int or not 1 <= exception_id <= 0xFFFF:
            raise ValueError("Exception ID must be a nonzero u16")
        for row, ident in zip(rows, exceptions, strict=True):
            if ident != exception_id:
                continue
            key = schema.key(row)
            flag = row[schema.flag_offset]
            if flag == 1:
                # Native reuses the scan index while shifting the tail, so the
                # outer scan ends after its first deletion (RVA 0x4cd9f).
                for position, old in enumerate(selected):
                    if schema.key(old) == key:
                        del selected[position]
                        break
            elif flag == 2:
                position = next(
                    (i for i, old in enumerate(selected) if schema.key(old) >= key),
                    len(selected),
                )
                if position < len(selected) and schema.key(selected[position]) == key:
                    selected[position] = row
                else:
                    selected.insert(position, row)
    return tuple(selected)


@dataclass(frozen=True)
class ExceptionContext:
    """Pointer-free SExceptionIdFindKeyItem, retaining uncertain field names."""

    category: int
    variant: int
    identifier: bytes = b""
    subidentifier: bytes = b""
    key_0c: int = 0
    key_14: int = 0
    key_15: int = 0
    key_16: int = 0
    key_17: int = 0
    key_18: int = 0
    key_19: int = 0
    key_1a: int = 0

    def __post_init__(self) -> None:
        if type(self.category) is not int or not 0 <= self.category <= 0xFFFF:
            raise ValueError("Category must be u16")
        values = (
            self.variant,
            self.key_0c,
            self.key_14,
            self.key_15,
            self.key_16,
            self.key_17,
            self.key_18,
            self.key_19,
            self.key_1a,
        )
        if any(type(value) is not int or not 0 <= value <= 255 for value in values):
            raise ValueError("Exception context scalar fields must be u8")
        if not isinstance(self.identifier, bytes) or not isinstance(
            self.subidentifier, bytes
        ):
            raise TypeError("Exception identifiers must be bytes")
        if max(len(self.identifier), len(self.subidentifier)) > 0x7FFF:
            raise ValueError("Exception identifier exceeds native signed length")


def exception_matches(row: bytes, context: ExceptionContext) -> bool:
    """CDbExceptionFindIdTable::DecisionKey, VA 0x100357ea."""
    if len(row) != 36:
        raise ValueError("ExceptionFindId row must be 36 bytes")
    if word(row, 14) != context.category or row[34] != context.variant:
        return False
    mask = struct.unpack_from("<I", row, 16)[0]
    for bit, offset, width, identifier in (
        (1, 0, 7, context.identifier),
        (2, 8, 6, context.subidentifier),
    ):
        if not mask & bit:
            prefix = row[offset : offset + width].split(b"\0", 1)[0]
            if not prefix or not identifier.startswith(prefix):
                return False
    for bit, offset, value in (
        (4, 7, context.key_0c),
        (8, 24, context.key_14),
        (128, 31, context.key_18),
        (256, 32, context.key_19),
        (512, 33, context.key_1a),
    ):
        if not mask & bit and row[offset] != value:
            return False
    return all(
        mask & bit or row[offset + 1] <= value <= row[offset]
        for bit, offset, value in (
            (16, 25, context.key_15),
            (32, 27, context.key_16),
            (64, 29, context.key_17),
        )
    )


class ExceptionResolver:
    def __init__(self, management: Database):
        if management.kind != 1:
            raise ValueError("Exception resolver needs a management database")
        self.management = management

    def matching_rules(self, context: ExceptionContext) -> tuple[bytes, ...]:
        section = self.management.sections.get(3)
        return (
            tuple(row for row in section.rows(36) if exception_matches(row, context))
            if section
            else ()
        )

    def processes(
        self, key: int, *, second_key: int | None = None
    ) -> tuple[bytes, ...]:
        """The proven +4 then +6 lookups, without naming unknown process fields."""
        for value in (key, second_key):
            if value is not None and (
                type(value) is not int or not 0 <= value <= 0xFFFF
            ):
                raise ValueError("Process lookup key must be u16")
        section = self.management.sections.get(4)
        rows = section.rows(20) if section else []
        return tuple(
            row
            for row in rows
            if word(row, 4) == key
            and (second_key is None or word(row, 6) == second_key)
        )

    def find_ids(self, context: ExceptionContext) -> tuple[int, ...]:
        """GetCarInfoExcept_DT copies matching ExceptionFindId rows at +0x16."""
        return tuple(word(row, 22) for row in self.matching_rules(context))

    def resolve_processes(
        self,
        category: int,
        find_ids: Sequence[int],
        *,
        support_bit: Callable[[int], bool] | None = None,
        frame_check: Callable[[int, int, int], bool] | None = None,
    ) -> tuple[int, ...]:
        """GetException.dll process dispatch, preserving list order and duplicates.

        Conditional native communication errors skip that process. Missing host
        callbacks are explicit failures, not fabricated negative ECU observations.
        """
        selected = []
        for find_id in find_ids:
            for row in self.processes(category, second_key=find_id):
                mode = row[18]
                if mode == 0:
                    selected.append(word(row, 14))
                elif mode == 1:
                    bit = word(row, 10)
                    if bit and support_bit is None:
                        raise ValueError(
                            "Conditional exception requires support-bit evaluator"
                        )
                    if not bit and frame_check is None:
                        raise ValueError(
                            "Conditional exception requires communication-frame evaluator"
                        )
                    try:
                        supported = (
                            support_bit(bit)
                            if bit and support_bit
                            else frame_check(word(row, 8), word(row, 12), row[19])
                            if frame_check
                            else False
                        )
                    except ToyotaCodecError:
                        continue
                    if supported:
                        selected.append(word(row, 14))
                else:
                    raise ToyotaCodecError(
                        "Invalid exception process mode", INVALID_RECORD
                    )
        return tuple(selected)

    def default_processes(
        self,
        vehicle_name_key: int,
        category: int,
        evaluate: Callable[[DefaultExceptionProbe], bool] | None = None,
    ) -> tuple[tuple[int, int], ...]:
        """GetDefaultExcept_DT 0x139/0x13a lookup and modes 0/1/3.

        Output pairs are (ECU category, exception ID); each ID also overlays the
        management index. An injected evaluator owns support/connection replies.
        """
        for value in (vehicle_name_key, category):
            if type(value) is not int or not 0 <= value <= 0xFFFF:
                raise ValueError("Default-exception keys must be u16")
        installations = self.management.sections.get(57)
        retrieval = self.management.sections.get(58)
        if installations is None or retrieval is None:
            return ()
        rules = retrieval.rows(20)
        selected = []
        for installing in installations.rows(8):
            if word(installing, 0) != vehicle_name_key:
                continue
            for row in rules:
                if (word(row, 4), row[16], word(row, 6)) != (
                    word(installing, 2),
                    installing[4],
                    category,
                ):
                    continue
                mode = row[17]
                if mode not in (0, 1, 3):
                    raise ToyotaCodecError(
                        "Invalid default exception process mode", INVALID_RECORD
                    )
                apply = mode == 0
                if mode in (1, 3):
                    bit = word(row, 10)
                    if mode == 3 and bit == 0:
                        continue
                    if evaluate is None:
                        raise ValueError(
                            "Default exception requires an injected observation evaluator"
                        )
                    probe = DefaultExceptionProbe(
                        mode,
                        word(row, 4),
                        row[16],
                        bit,
                        word(row, 8),
                        word(row, 12),
                        row[18],
                    )
                    try:
                        apply = evaluate(probe)
                    except ToyotaCodecError:
                        continue
                if apply:
                    selected.append((word(row, 4), word(row, 14)))
        return tuple(selected)


@dataclass(frozen=True)
class DefaultExceptionProbe:
    mode: int
    category: int
    protocol: int
    support_bit: int
    frame_key: int
    settings_key: int
    reply_length: int


def evaluate_default_probe(
    probe: DefaultExceptionProbe,
    *,
    support_bit: Callable[[int, int, int], bool],
    frame_check: Callable[[int, int, int], bool],
    read_mode: Callable[[], bytes],
    write_mode: Callable[[bytes], None],
    build_mode: Callable[[int, int, bytes], bytes],
) -> bool:
    """Native default-exception dispatch, including saved diagnostic context.

    support_bit receives the exact two native trailing flags. Transport replies
    and mode storage are injected; context switching/restoration is implemented
    here and therefore testable without a connection.
    """
    if probe.mode == 0:
        return True
    if probe.mode == 1:
        return (
            support_bit(probe.support_bit, 1, 0)
            if probe.support_bit
            else frame_check(probe.frame_key, probe.settings_key, probe.reply_length)
        )
    if probe.mode != 3:
        raise ToyotaCodecError("Invalid default exception process mode", INVALID_RECORD)
    if not probe.support_bit:
        return False
    original = read_mode()
    if len(original) != 16:
        raise ValueError("DIAGNOSTIC_INFO must be sixteen bytes")
    alternate = build_mode(probe.category, probe.protocol, original)
    if len(alternate) != 16:
        raise ValueError("Alternate DIAGNOSTIC_INFO must be sixteen bytes")
    try:
        write_mode(alternate)
        result = support_bit(probe.support_bit, 0, 0)
    except BaseException as error:
        try:
            write_mode(original)
        except BaseException as restore_error:  # noqa: BLE001 - preserve cancellation plus restoration failure
            raise BaseExceptionGroup(
                "Default probe and diagnostic-mode restoration failed",
                [error, restore_error],
            ) from None
        raise
    write_mode(original)
    return result


@dataclass(frozen=True)
class PidBit:
    start_bit: int
    end_bit: int
    selector: int
    identifier: bytes

    @classmethod
    def from_record(cls, row: bytes, variables: VariableTable) -> PidBit:
        if len(row) != 12:
            raise ToyotaCodecError("PidBit record must be 12 bytes", INVALID_RECORD)
        return cls(word(row, 6), word(row, 8), row[11], variables.get(word(row, 2)))

    def __post_init__(self) -> None:
        if self.selector not in (2, 3, 4) or len(self.identifier) != (
            2 if self.selector == 4 else 1
        ):
            raise ToyotaCodecError("Invalid PidBit selector/identifier", INVALID_RECORD)
        if not 0 <= self.start_bit <= self.end_bit <= 0xFFFF:
            raise ToyotaCodecError("Invalid PidBit range", INVALID_RECORD)

    @property
    def function_id(self) -> int:
        return {2: 0x10, 3: 0x69, 4: 0x6A}[self.selector]

    def request(self, template: CommandFrame) -> CommandFrame:
        offset = 2 if self.selector == 4 else 1
        end = offset + len(self.identifier)
        if len(template.request) < end:
            raise ToyotaCodecError("Short PidBit request template", INVALID_RECORD)
        request = template.request[:offset] + self.identifier + template.request[end:]
        return CommandFrame(request, template.receive_mask, template.receive_check)

    def evaluate(self, reply: bytes) -> bool:
        offset = 4 if self.selector == 4 else 2
        if len(reply) <= offset:
            raise ToyotaCodecError("Short PidBit response", SHORT_REPLY)
        return extract_bits(reply[offset:], self.start_bit, self.end_bit) != 0


def check_pid_support(
    freeze_record: bytes,
    pid_lengths: Mapping[int, int],
    pid_bits: Mapping[int, PidBit],
    frames: Callable[[int], Sequence[CommandFrame]],
    exchange: Callable[[bytes], bytes],
    *,
    did_lengths: Mapping[int, int] | None = None,
) -> bool:
    """Complete P3 Freeze gate using caller-selected definitions and fake/live I/O.

    This evaluates one row and never opens a device. The caller owns deadlines,
    cancellation and transport status translation, and resolves exception indexes.
    """
    if len(freeze_record) != 84:
        raise ToyotaCodecError("Freeze row must be 84 bytes", INVALID_RECORD)
    available = pid_lengths.get(freeze_record[79], 0)
    early = pid_support_p3(freeze_record, available)
    if early is not None:
        return early
    reference = word(freeze_record, 58)
    bit = pid_bits.get(reference)
    if bit is None:
        return False
    return check_bit_support(
        bit, pid_lengths, frames, exchange, did_lengths=did_lengths
    )


def check_active_support(
    record: bytes,
    pid_lengths: Mapping[int, int],
    did_lengths: Mapping[int, int],
    did_bits: Mapping[int, PidBit],
    frames: Callable[[int], Sequence[CommandFrame]],
    exchange: Callable[[bytes], bytes],
    *,
    old_body: bool = False,
) -> bool:
    """P3/DK CheckSupportDid ActTest92 gate, native RVA 0x5ea70."""
    if len(record) != 92:
        raise ToyotaCodecError("ActTest record must be 92 bytes", INVALID_RECORD)
    mode = record[83]
    if mode == 1:
        return True
    if mode == 2:
        return False
    if mode != 0:
        raise ToyotaCodecError("Invalid active support mode", 0xA0040004)
    if (did_lengths.get(record[82], 0) & 0xFF) * 8 <= word(record, 68):
        return False
    reference = word(record, 60)
    if not reference:
        return True
    bit = did_bits.get(reference)
    return bit is not None and check_bit_support(
        bit,
        pid_lengths,
        frames,
        exchange,
        did_lengths=did_lengths,
        require_membership=not old_body,
    )


def check_bit_support(
    bit: PidBit,
    pid_lengths: Mapping[int, int],
    frames: Callable[[int], Sequence[CommandFrame]],
    exchange: Callable[[bytes], bytes],
    *,
    did_lengths: Mapping[int, int] | None = None,
    require_membership: bool = True,
) -> bool:
    """Shared native CheckSupportBit request/reply operation."""
    selected = frames(bit.function_id)
    if not selected:
        raise ToyotaCodecError("Missing support communication frame", MISSING_RECORD)
    lengths = did_lengths if bit.selector == 3 else pid_lengths
    if (
        require_membership
        and bit.selector in (2, 3)
        and (lengths is None or bit.identifier[0] not in lengths)
    ):
        return False
    frame = bit.request(selected[0])
    try:
        reply = exchange(frame.request)
        frame.check_reply(reply)
        return bit.evaluate(reply)
    except ToyotaCodecError as error:
        if error.code in (0x91010009, 0x90020323):
            return False
        raise


@dataclass(frozen=True)
class ProtocolCandidate:
    category: int
    variant: int
    protocol: int

    def __post_init__(self) -> None:
        for value, limit in (
            (self.category, 0xFFFF),
            (self.variant, 255),
            (self.protocol, 255),
        ):
            if type(value) is not int or not 0 <= value <= limit:
                raise ValueError("Protocol candidate field out of native range")


@dataclass(frozen=True)
class ProtocolSelection:
    category: int
    variant: int
    protocol: int
    index: int


def check_protocol_cache(
    candidates: Sequence[ProtocolCandidate],
    *,
    lookup: Callable[[int, int], tuple[int, int]],
    probe: Callable[[int, int, int, int, int], None],
    remember_failure: Callable[[int, int, int, int], None],
    start: int = 0,
) -> ProtocolSelection | None:
    """CEcuConnectCheck::CheckCommProtocolCache RVA 0x72a60.

    lookup returns (supported, found) from native CheckBuffer. A cache miss
    sends the native empty SendInt probe with timeout 1000 and flags (1,1).
    Failed probes are recorded by ConnectSet(category,0,variant,protocol).
    No observation is manufactured: callers inject an actual or replay cache.
    """
    if not candidates:
        raise ToyotaCodecError("Missing protocol judge candidates", MISSING_RECORD)
    if type(start) is not int or not 0 <= start <= len(candidates):
        raise ValueError("Protocol resume index outside candidate list")
    # Native local protocol starts at zero and changes only on cache misses.
    protocol = 0
    for index in range(start, len(candidates)):
        candidate = candidates[index]
        supported, found = lookup(candidate.category, candidate.variant)
        if found:
            if supported != 1:
                continue
        else:
            protocol = candidate.protocol
            try:
                probe(candidate.category, candidate.variant, 1000, 1, 1)
            except ToyotaCodecError:
                remember_failure(candidate.category, 0, candidate.variant, protocol)
                continue
        return ProtocolSelection(candidate.category, candidate.variant, protocol, index)
    return None


@dataclass(frozen=True)
class ConnectionCacheEntry:
    """Pointer-free CEcuConnectBuffer value; bytes come from observed/replay I/O."""

    category: int
    variant: int
    supported: int
    request: bytes = b""
    reply: bytes = b""


def lookup_connection_cache(
    entries: Sequence[ConnectionCacheEntry],
    category: int,
    variant: int,
    frame: CommandFrame,
) -> tuple[int, int]:
    """CEcuConnectCheck::CheckBuffer RVA 0x71010 -> (supported, found).

    An empty template returns the stored result without comparing frame bytes.
    A nonempty template matches exact sent bytes, then receive mask/check bytes.
    Native out-of-range list access is rejected explicitly.
    """
    for entry in entries:
        if (entry.category, entry.variant) != (category, variant):
            continue
        if not frame.request:
            return entry.supported, 1
        if entry.request != frame.request:
            continue
        if not entry.reply:
            return 0, 1
        if not frame.receive_mask:
            return 0, 0
        if len(entry.reply) < len(frame.receive_mask) or len(frame.receive_check) > len(
            frame.receive_mask
        ):
            raise ToyotaCodecError(
                "Cached reply shorter than native mask/check", SHORT_REPLY
            )
        masked = bytes(
            value & mask for value, mask in zip(entry.reply, frame.receive_mask)
        )
        return int(masked[: len(frame.receive_check)] == frame.receive_check), 1
    return 0, 0


def check_panel_support(
    reference: int,
    mode: int,
    records: Mapping[int, bytes],
    variables: VariableTable,
    frames: Callable[[int], Sequence[CommandFrame]],
    exchange: Callable[[bytes], bytes],
) -> bool:
    """P5 CheckSupportPanel RVA64e80; caller's exchange owns communication status."""
    if mode == 1:
        return True
    if mode == 2:
        return False
    if mode != 0:
        raise ToyotaCodecError("Invalid panel support mode", 0xA0040004)
    if not reference:
        raise ToyotaCodecError("Panel support reference is zero", INVALID_RECORD)
    row = records.get(reference)
    if row is None:
        raise ToyotaCodecError("Missing panel support record", MISSING_RECORD)
    if len(row) != 16:
        raise ToyotaCodecError(
            "Panel support record must be sixteen bytes", INVALID_RECORD
        )
    comparison = row[13]
    if comparison == 0:
        return True
    selected = frames(0xCA)
    if not selected or len(selected[0].request) < 3:
        raise ToyotaCodecError(
            "Missing or short panel request template", MISSING_RECORD
        )
    request = selected[0].request
    request = request[:1] + bytes((row[3], row[2])) + request[3:]
    try:
        reply = exchange(request)
    except ToyotaCodecError:
        return False
    mask, expected = variables.get(word(row, 6)), variables.get(word(row, 8))
    if len(expected) < len(mask):
        raise ToyotaCodecError("Panel receive data shorter than mask", INVALID_RECORD)
    offset = word(row, 4) + 3
    if len(reply) < offset + len(mask):
        return False
    actual = bytes(value & keep for value, keep in zip(reply[offset:], mask))
    target = bytes(value & keep for value, keep in zip(expected, mask))
    if comparison == 1:
        return actual == target
    if comparison == 2:
        return actual != target
    if comparison == 3:
        return actual >= target
    if comparison == 4:
        return actual <= target
    if comparison == 5:
        return actual > target
    if comparison == 6:
        return actual < target
    raise ToyotaCodecError("Invalid panel comparison", INVALID_RECORD)


def check_did_bit_support(
    reference: int,
    mode: int,
    did_bits: Mapping[int, PidBit],
    pid_lengths: Mapping[int, int],
    did_lengths: Mapping[int, int],
    frames: Callable[[int], Sequence[CommandFrame]],
    exchange: Callable[[bytes], bytes],
    *,
    old_body: bool = True,
) -> bool:
    """CheckDidBitSupport(60f40)/CheckSupportDidP4(610d0) modes and selected bit."""
    if mode == 1:
        return True
    if mode == 2:
        return False
    if mode != 0:
        raise ToyotaCodecError("Invalid DID-bit support mode", 0xA0040004)
    if not reference:
        raise ToyotaCodecError("DID-bit support reference is zero", INVALID_RECORD)
    bit = did_bits.get(reference)
    if bit is None:
        raise ToyotaCodecError("Missing DID-bit support definition", MISSING_RECORD)
    return check_bit_support(
        bit,
        pid_lengths,
        frames,
        exchange,
        did_lengths=did_lengths,
        require_membership=not old_body,
    )


def check_p5_bit_support(
    row: bytes,
    variables: VariableTable,
    frames: Callable[[int], Sequence[CommandFrame]],
    exchange: Callable[[bytes], bytes],
) -> bool:
    """DataIdBitForAct selector7, CheckSupportBit RVA64920."""
    if len(row) != 12 or row[11] != 7:
        raise ToyotaCodecError("Invalid P5 support-bit record/selector", INVALID_RECORD)
    identifier = variables.get(word(row, 2))
    if len(identifier) != 2:
        raise ToyotaCodecError(
            "P5 support identifier must be two bytes", INVALID_RECORD
        )
    selected = frames(0xC9)
    if not selected or len(selected[0].request) < 3:
        raise ToyotaCodecError("Missing P5 support request template", INVALID_RECORD)
    template = selected[0].request
    try:
        reply = exchange(template[:1] + identifier + template[3:])
    except ToyotaCodecError:
        return False
    if len(reply) <= 3:
        return False
    return extract_bits(reply[3:], word(row, 6), word(row, 8)) != 0


def check_p5_active_support(
    row: bytes,
    protocol: int,
    enabled_dids: Collection[int],
    data_id_records: Sequence[bytes],
    support_cache: MutableMapping[int, bool],
    length_cache: MutableMapping[int, int],
    bit_records: Mapping[int, bytes],
    variables: VariableTable,
    frames: Callable[[int], Sequence[CommandFrame]],
    exchange: Callable[[bytes], bytes],
    *,
    apply_mode: bool = True,
) -> bool:
    """Native P5 CheckSupportDid RVA63950, with explicit observed caches.

    Caches are per selected ECU. DataIdForAct rows are already selected for the
    action DID. Source reply indexing/32-bit shifts are preserved literally.
    """
    if len(row) != 64:
        raise ToyotaCodecError("ActTestP5 record must be 64 bytes", INVALID_RECORD)
    if not 0 <= protocol <= 255 or any(len(item) != 12 for item in data_id_records):
        raise ToyotaCodecError("Invalid P5 protocol/data-ID record", INVALID_RECORD)

    def finish(value: bool) -> bool:
        # 640a9..641dc applies the record mode after raw cache reads/writes.
        return value if not apply_mode or row[56] == 0 else row[56] == 1

    signal, did, end = word(row, 32), word(row, 52), word(row, 42)
    if signal in support_cache:
        return finish(bool(support_cache[signal]))
    supported = False
    if did in enabled_dids:
        if protocol & 31 == 21:
            # Native starts received_length at0; missing length is stored as
            # WORD(0-3), not an invented observation from a reply.
            length = length_cache.setdefault(did, 0xFFFD)
            supported = (length & 0xFFFF) * 8 > end
        elif data_id_records:
            try:
                selected = frames(0xCA)
                if selected and len(selected[0].request) >= 3:
                    template = selected[0].request
                    reply = exchange(
                        template[:1] + did.to_bytes(2, "big") + template[3:]
                    )
                    if len(reply) > 3:
                        length_cache.setdefault(did, (len(reply) - 3) & 0xFFFF)
                        if ((len(reply) - 3) & 0xFFFF) * 8 > end:
                            mode = data_id_records[0][10]
                            if mode in (0, 3, 4):
                                supported = True
                            elif mode == 1:
                                start = word(row, 40)
                                if start > end:
                                    raise ToyotaCodecError(
                                        "Invalid active bit range", INVALID_RECORD
                                    )
                                position = (end >> 3) + 2
                                if position >= len(reply):
                                    raise ToyotaCodecError(
                                        "Short active support reply", SHORT_REPLY
                                    )
                                for index in range(end - start + 1):
                                    # 63e0d..63e49: native scans one byte using
                                    # x86 count masking and 8-bit comparison.
                                    shift = ((end & 7) - index) & 31
                                    mask = (0x80 >> shift) & 0xFF
                                    if reply[position] & mask == mask:
                                        supported = True
                                        break
                            if supported and word(row, 34):
                                definition = bit_records.get(word(row, 34))
                                supported = (
                                    definition is not None
                                    and check_p5_bit_support(
                                        definition, variables, frames, exchange
                                    )
                                )
            except ToyotaCodecError:
                supported = False
    support_cache[signal] = supported
    return finish(supported)


def check_active_support_p4(
    row: bytes,
    pid_lengths: Mapping[int, int],
    check_bits: Callable[[int, int, int], bool],
) -> bool:
    """CCmdSupportEcu::DidCheckSupportBitP4 RVA558d0 cache gate."""
    if len(row) != 92:
        raise ToyotaCodecError("ActTest record must be 92 bytes", INVALID_RECORD)
    if row[83] in (1, 2):
        return row[83] == 1
    if row[83] != 0:
        raise ToyotaCodecError("Invalid active support mode", 0xA0040004)
    return row[82] in pid_lengths and check_bits(row[82], word(row, 66), word(row, 68))


def check_routine_support(
    row: bytes,
    enabled_rids: Collection[int],
    support_cache: MutableMapping[int, bool],
    *,
    apply_mode: bool = True,
    database_version: int = 0x0100032F,
) -> bool:
    """CheckSupportRid RVA64390: observed RID membership, then mode override."""
    width, mode_offset = (60, 58) if database_version == 0x0100030C else (64, 60)
    if database_version not in (0x0100030C, 0x0100032F) or len(row) != width:
        raise ToyotaCodecError(
            "RoutineActTestP5 record/version mismatch", INVALID_RECORD
        )
    signal = word(row, 30)
    if signal not in support_cache:
        support_cache[signal] = word(row, 28) in enabled_rids
    value = bool(support_cache[signal])
    return value if not apply_mode or row[mode_offset] == 0 else row[mode_offset] == 1


def check_subaru_routine_support(
    row: bytes,
    enabled_dids: Collection[int],
    support_cache: MutableMapping[int, bool],
    bit_records: Mapping[int, bytes],
    variables: VariableTable,
    frames: Callable[[int], Sequence[CommandFrame]],
    exchange: Callable[[bytes], bytes],
    *,
    apply_mode: bool = True,
) -> bool:
    """CheckSupportRidForSUBARU RVA66360; its cache is separate from normal RID."""
    if len(row) != 64:
        raise ToyotaCodecError(
            "RoutineActTestP5 record must be 64 bytes", INVALID_RECORD
        )
    signal = word(row, 30)
    if signal not in support_cache:
        reference = word(row, 32)
        value = not reference
        if reference:
            definition = bit_records.get(reference)
            if definition is not None:
                if len(definition) != 12:
                    raise ToyotaCodecError(
                        "Invalid routine support-bit row", INVALID_RECORD
                    )
                identifier = variables.get(word(definition, 2))
                # 6651a..66540 accumulates through DH/DL: only the last two
                # bytes survive, unlike a general unlimited-width integer.
                if (
                    identifier
                    and int.from_bytes(identifier[-2:], "big") in enabled_dids
                ):
                    value = check_p5_bit_support(
                        definition, variables, frames, exchange
                    )
        support_cache[signal] = value
    result = bool(support_cache[signal])
    return result if not apply_mode or row[60] == 0 else row[60] == 1


def check_subaru_active_support(
    row: bytes,
    support_cache: MutableMapping[int, bool],
    bit_records: Mapping[int, bytes],
    variables: VariableTable,
    frames: Callable[[int], Sequence[CommandFrame]],
    exchange: Callable[[bytes], bytes],
) -> bool:
    """CheckSupportDidForSUBARU RVA66740; no enabled-DID membership gate."""
    if len(row) != 64:
        raise ToyotaCodecError("ActTestP5 record must be 64 bytes", INVALID_RECORD)
    signal = word(row, 32)
    if signal not in support_cache:
        reference = word(row, 34)
        value = not reference
        if reference:
            definition = bit_records.get(reference)
            value = definition is not None and check_p5_bit_support(
                definition, variables, frames, exchange
            )
        support_cache[signal] = value
    value = bool(support_cache[signal])
    return value if row[56] == 0 else row[56] == 1
