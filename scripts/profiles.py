"""Explicit native DDB profile selection with provenance and validated joins.

This catalog never infers installed ECUs from model names or opens a transport.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from scripts.diagnostic_db import Database, DiagnosticCatalog
from scripts.support import (
    DDR_TABLE_GROUPS,
    ExceptionContext,
    PidBit,
    ProtocolCandidate,
    ProtocolSelection,
    check_active_support,
    correspondence_rows,
    word,
)
from scripts.toyota import CommandFrame, ToyotaCodecError, VariableTable


def _rows(database: Database, slot: int, width: int) -> tuple[bytes, ...]:
    section = database.sections.get(slot)
    return tuple(section.rows(width)) if section else ()


def _one(rows: tuple[bytes, ...], description: str) -> bytes:
    if len(rows) != 1:
        raise ValueError(f"Expected one {description}; found {len(rows)}")
    return rows[0]


def _variables(database: Database) -> VariableTable:
    section = database.sections.get(0)
    if section is None:
        raise ValueError("Database has no variable section")
    return VariableTable(section.payload, section.count)


@dataclass(frozen=True)
class VinVehicleContext:
    """Native VIN decision key; attributes are eleven literal caller bytes."""

    category: int
    variant: int
    attributes: bytes

    def __post_init__(self) -> None:
        if type(self.category) is not int or not 0 <= self.category <= 0xFFFF:
            raise ValueError("VIN category must be u16")
        if type(self.variant) is not int or not 0 <= self.variant <= 255:
            raise ValueError("VIN variant must be u8")
        if not isinstance(self.attributes, bytes) or len(self.attributes) != 11:
            raise ValueError("VIN decision attributes must be eleven bytes")

    @classmethod
    def from_vin(cls, category: int, variant: int, vin: bytes) -> VinVehicleContext:
        """SelectCarTypVn10_DT 0x637d/0x7113 copies VIN bytes 0..10."""
        if not isinstance(vin, bytes) or len(vin) != 17:
            raise ValueError("Native VIN input must be seventeen bytes")
        if vin[0] in (0, 0xFF, ord("?")):
            raise ValueError("Native VIN input has an unavailable first byte")
        return cls(category, variant, vin[:11])


def vin_vehicle_matches(row: bytes, context: VinVehicleContext) -> bool:
    """CDbVinVehicleDecisionTable::DecisionKey RVA 0x55693."""
    if len(row) != 32:
        raise ValueError("VIN decision record must be 32 bytes")
    mask = int.from_bytes(row[:4], "little")
    return (
        word(row, 16) == context.category
        and row[18] == context.variant
        and all(
            mask & (1 << index) or row[19 + index] == value
            for index, value in enumerate(context.attributes)
        )
    )


@dataclass(frozen=True)
class VehicleContext:
    """SOriginalVehicleDecisionFindKeyItem with opaque fields kept literal.

    mode 0/1 selects legacy/New; 2/3 selects EU/NewEU. New modes use
    selected_fields to require individual fields; zero means unconstrained.
    """

    identity: ExceptionContext
    mode: int = 0
    selected_fields: int = 0
    option_keys: tuple[int, int, int, int] = (0, 0, 0, 0)

    def __post_init__(self) -> None:
        if type(self.mode) is not int or self.mode not in (0, 1, 2, 3):
            raise ValueError("Vehicle decision mode must be 0..3")
        if (
            type(self.selected_fields) is not int
            or not 0 <= self.selected_fields <= 0xFFFF
        ):
            raise ValueError("Vehicle selected-field mask must be u16")
        if len(self.option_keys) != 4 or any(
            type(key) is not int or not 0 <= key <= 0xFFFF for key in self.option_keys
        ):
            raise ValueError("Vehicle option keys must be four u16 values")

    @classmethod
    def from_identification_fields(
        cls, category: int, variant: int, data: bytes, *, extended: bool = False
    ) -> VehicleContext:
        """Native EU identification-field buffers (not a complete wire reply).

        SelectCarTypVn10_DT 0x297b maps the 22 bytes at object+0x18;
        0x38db maps the extended 25 bytes at object+0x50. Both select mode 2.
        """
        if len(data) != (25 if extended else 22):
            raise ValueError("Identification-field buffer has the wrong native size")
        sub_offset, capacity = (8, 7) if extended else (4, 3)
        if data[0] > capacity or data[sub_offset] > capacity:
            raise ValueError("Identification prefix length exceeds its native buffer")
        identifier = data[1 : 1 + data[0]]
        subidentifier = data[sub_offset + 1 : sub_offset + 1 + data[sub_offset]]
        if not extended and subidentifier:
            subidentifier = bytes((subidentifier[0] | 0x30,)) + subidentifier[1:]
        fields = (
            (data[16], data[18], data[20], data[22], 0, 0, 0, data[24])
            if extended
            else (
                data[9],
                data[11],
                data[13],
                data[15],
                data[17],
                data[19],
                data[21],
                0,
            )
        )
        return cls(
            ExceptionContext(category, variant, identifier, subidentifier, *fields),
            mode=2,
        )

    @classmethod
    def from_native_key(
        cls, key: bytes, *, identifier: bytes = b"", subidentifier: bytes = b""
    ) -> VehicleContext:
        """Pointer-free import of the forty-byte original decision key.

        Pointer fields at +8/+16 are never dereferenced. Their pointee data must
        be supplied separately; all scalar offsets follow native DecisionKey.
        """
        if len(key) != 40:
            raise ValueError("Original vehicle decision key must be forty bytes")
        if len(identifier) < word(key, 0) or len(subidentifier) < word(key, 4):
            raise ValueError(
                "Native decision identifier is shorter than its declared length"
            )
        identity = ExceptionContext(
            word(key, 2),
            key[27],
            identifier[: word(key, 0)],
            subidentifier[: word(key, 4)],
            key[12],
            *key[20:27],
        )
        return cls(identity, key[30], word(key, 28), struct.unpack_from("<4H", key, 32))


def _comparison(mode: int, expected: int, value: int, *, ordered: bool = True) -> bool:
    if mode == 1:
        return expected == value
    if mode == 2:
        return expected != value
    if ordered and mode == 3:
        return expected <= value
    if ordered and mode == 4:
        return expected >= value
    return False


def vehicle_matches(
    row: bytes, context: VehicleContext, score: int = 0
) -> tuple[bool, int]:
    """Four native VehicleDecision matchers, including EU rolling prefix score.

    The score can change before a later field fails; the caller must preserve it
    across rows as FindDbItem does. Field names are not guessed vehicle metadata.
    """
    if len(row) != 52:
        raise ValueError("VehicleDecision record must be 52 bytes")
    identity = context.identity
    newer, european = context.mode in (1, 3), context.mode in (2, 3)

    def needed(bit: int) -> bool:
        return not newer or bool(context.selected_fields & bit)

    if needed(1) and word(row, 0) != identity.category:
        return False, score
    if needed(2) and row[2] != identity.variant:
        return False, score
    mask = struct.unpack_from("<I", row, 36)[0]
    for bit, offset, length_offset, mode_offset, value in (
        (1, 3, 10, 11, identity.identifier),
        (2, 12, 18, 19, identity.subidentifier),
    ):
        if mask & bit or not needed(bit << 2):
            continue
        length = row[length_offset]
        if length > (7 if bit == 1 else 6):
            raise ValueError("Vehicle decision prefix exceeds its native field")
        expected = row[offset : offset + length]
        if european and bit == 1:
            if any(byte > 127 for byte in expected + value):
                raise ValueError("Non-ASCII EU suffix needs the original CRT locale")
            expected = expected.rstrip(b"# \t\n\r\v\f")
            value = value.rstrip(b"# \t\n\r\v\f")
            length = len(expected)
            if length > len(value) or length < score:
                return False, score
        equal = length > 0 and len(value) >= length and expected == value[:length]
        mode = row[mode_offset]
        if mode not in (1, 2) or equal != (mode == 1):
            return False, score
        if european and bit == 1:
            score = length
    for bit, expected_offset, mode_offset, value in (
        (4, 20, 21, identity.key_0c),
        (8, 22, 23, identity.key_14),
        (16, 24, 25, identity.key_15),
        (32, 26, 27, identity.key_16),
        (64, 28, 29, identity.key_17),
        (128, 30, 29, identity.key_18),
        (256, 32, 33, identity.key_19),
        (512, 34, 35, identity.key_1a),
    ):
        if (
            not mask & bit
            and needed(bit << 2)
            and not _comparison(
                row[mode_offset], row[expected_offset], value, ordered=bit < 256
            )
        ):
            return False, score
    if newer and any(
        key and key != word(row, 40 + index * 2)
        for index, key in enumerate(context.option_keys)
    ):
        return False, score
    return True, score


@dataclass(frozen=True)
class DiagnosticMode:
    """Meaningful DIAGNOSTIC_INFO fields written by GetDefaultExcept_DT."""

    key1: int
    key2: int
    protocol: int
    group: int

    def replace_in(self, original: bytes) -> bytes:
        if len(original) != 16:
            raise ValueError("DIAGNOSTIC_INFO must be sixteen bytes")
        data = bytearray(original)
        struct.pack_into("<H", data, 0, 1)
        struct.pack_into(
            "<IIHH", data, 4, self.key1, self.key2, self.protocol, self.group
        )
        return bytes(data)


@dataclass(frozen=True)
class SelectedFrame:
    frame: CommandFrame
    function_record: bytes
    communication_record: bytes
    settings_record: bytes
    provenance: str


@dataclass(frozen=True)
class SelectedSignal:
    pid_id: int
    check_record: bytes
    freeze_record: bytes
    physical_record: bytes | None
    provenance: str


@dataclass(frozen=True)
class ProtocolProfile:
    """Selected management context before an ECU resource is bound.

    Protocol/VIN acquisition uses management records even when EcuCategory has
    no ECU filename. This type deliberately has no database or ECU records.
    """

    catalog: VehicleCatalog = field(repr=False)
    category_record: bytes
    exception_ids: tuple[int, ...] = ()
    vehicle_name_key: int | None = None

    @property
    def ecu_database_sha256(self) -> str | None:
        return None

    @property
    def category(self) -> int:
        return word(self.category_record, 68)

    @property
    def filename(self) -> str:
        return self.category_record[:40].decode("utf-16le").split("\0", 1)[0]

    @staticmethod
    def _query_key(key: int) -> None:
        if type(key) is not int or not 0 <= key <= 65535:
            raise ValueError("Native selection key must fit uint16")

    def protocol_info(self, observed_bus_id: int) -> bytes | None:
        """DB10D(category,bus), first selected row; bus is not truncated.

        ProtInfo::FindDbItem2 compares the full incoming key with the stored
        byte (18: +24; 12: +22), so values above 255 cannot match.
        """
        self._query_key(observed_bus_id)
        if 13 not in self.catalog.management.sections:
            raise ToyotaCodecError("Selected ProtInfo table is absent", 0xA0030107)
        offset = 22 if self.catalog.management.version == 0x0100030C else 24
        return next(
            (
                row
                for row in correspondence_rows(
                    self.catalog.management, 13, self.exception_ids
                )
                if word(row, 0) == self.category and row[offset] == observed_bus_id
            ),
            None,
        )

    def comm_info_can_records(self, key: int) -> tuple[bytes, ...]:
        """Plain DB10E FindDbItem1: first contiguous WORD8 group, no overlay."""
        self._query_key(key)
        management = self.catalog.management
        if management.version not in (0x0100030C, 0x0100032F):
            raise ValueError("CommInfoCan layout is unproven for this database version")
        section = management.sections.get(14)
        if section is None:
            raise ToyotaCodecError("Selected CommInfoCan table is absent", 0xA0030107)
        selected: list[bytes] = []
        for row in section.rows(28):
            if word(row, 8) == key:
                selected.append(row)
            elif selected:
                break
        return tuple(selected)

    def comm_info_iso_records(self, key: int) -> tuple[bytes, ...]:
        """Plain DB10F FindDbItem1: first contiguous WORD4 group, no overlay."""
        self._query_key(key)
        management = self.catalog.management
        if management.version not in (0x0100030C, 0x0100032F):
            raise ValueError("CommInfoIso layout is unproven for this database version")
        section = management.sections.get(15)
        if section is None:
            raise ToyotaCodecError("Selected CommInfoIso table is absent", 0xA0030107)
        selected: list[bytes] = []
        for row in section.rows(56):
            if word(row, 4) == key:
                selected.append(row)
            elif selected:
                break
        return tuple(selected)

    def communication_support_records(self, reference: int) -> tuple[bytes, ...]:
        """DB130 FindDbItem1 selects support reference WORD0, not ECU category."""
        self._query_key(reference)
        if 48 not in self.catalog.management.sections:
            raise ToyotaCodecError(
                "Selected CommSupportBit table is absent", 0xA0030107
            )
        return tuple(
            row
            for row in correspondence_rows(
                self.catalog.management, 48, self.exception_ids
            )
            if word(row, 0) == reference
        )

    def dll_records(self, command_id: int) -> tuple[bytes, ...]:
        """DB113 command/category query, with its native FIRST-command fallback."""
        self._query_key(command_id)
        if 19 not in self.catalog.management.sections:
            raise ToyotaCodecError("Selected DLL table is absent", 0xA0030107)
        command_rows = tuple(
            row
            for row in correspondence_rows(
                self.catalog.management, 19, self.exception_ids
            )
            if row[86] == command_id
        )
        selected = tuple(row for row in command_rows if word(row, 80) == self.category)
        # CDbDllTable.GetQuery30f1f uses count1/FIRST command row when category empty.
        return selected if selected else command_rows[:1]

    def category_records(self, category: int) -> tuple[bytes, ...]:
        """DB110 selected WORD68 group, including target ECUs without opening their DDB."""
        self._query_key(category)
        if 16 not in self.catalog.management.sections:
            raise ToyotaCodecError("Selected ECU category table is absent", 0xA0030107)
        return tuple(
            row
            for row in correspondence_rows(
                self.catalog.management, 16, self.exception_ids
            )
            if word(row, 68) == category
        )

    def ecu_function_info(self, function_id: int) -> tuple[bytes, ...]:
        """DB11A query WORD8 category then WORD10 function; overlay order is WORD20."""
        self._query_key(function_id)
        if 26 not in self.catalog.management.sections:
            raise ToyotaCodecError(
                "Selected ECU function information table is absent", 0xA0030107
            )
        rows = correspondence_rows(self.catalog.management, 26, self.exception_ids)
        selected: list[bytes] = []
        for row in rows:
            if word(row, 8) != self.category:
                continue
            if word(row, 10) == function_id:
                selected.append(row)
            elif selected:
                break
        if len(selected) > 0x7FFF:
            raise ToyotaCodecError(
                "Selected record count exceeds native SHORT", 0xA0030110
            )
        return tuple(selected)

    def mode_wwh(self) -> bool:
        """GetModeWWH17bf0: native query errors or empty function27 group yield false."""
        try:
            return bool(self.ecu_function_info(0x27))
        except ToyotaCodecError:
            return False

    def _comm_data_records(
        self, slot: int, logical_id: int, *, key_offset: int = 16
    ) -> tuple[bytes, ...]:
        self._query_key(logical_id)
        if slot not in self.catalog.management.sections:
            raise ToyotaCodecError(
                "Selected communication data table is absent", 0xA0030107
            )
        return tuple(
            row
            for row in correspondence_rows(
                self.catalog.management, slot, self.exception_ids
            )
            if word(row, key_offset) == logical_id
        )

    def comm_pid_records(self, logical_id: int) -> tuple[bytes, ...]:
        """Common1b69b DB136 logical ID -> candidate target/support rows."""
        return self._comm_data_records(54, logical_id)

    def comm_rid_records(self, logical_id: int) -> tuple[bytes, ...]:
        """Common6b550 DB158 logical ID -> candidate ECU-specific rows."""
        return self._comm_data_records(88, logical_id)

    def comm_did_records(self, logical_id: int) -> tuple[bytes, ...]:
        """Common1a7be DB13E logical WORD0 -> candidate target rows."""
        return self._comm_data_records(62, logical_id, key_offset=0)

    def ecu_function_details(self, function_id: int) -> tuple[bytes, ...]:
        """Common1b4c0: management DB11B(category,function), all detail rows."""
        self._query_key(function_id)
        if 27 not in self.catalog.management.sections:
            raise ToyotaCodecError(
                "Selected ECU function detail table is absent", 0xA0030107
            )
        return tuple(
            row
            for row in correspondence_rows(
                self.catalog.management, 27, self.exception_ids
            )
            if word(row, 4) == self.category and word(row, 6) == function_id
        )

    def timer_records(self, timer_id: int) -> tuple[bytes, ...]:
        """Management DB119(category,timer), preserving native selected order."""
        self._query_key(timer_id)
        if 25 not in self.catalog.management.sections:
            raise ToyotaCodecError("Selected timer table is absent", 0xA0030107)
        return tuple(
            row
            for row in correspondence_rows(
                self.catalog.management, 25, self.exception_ids
            )
            if word(row, 4) == self.category and word(row, 6) == timer_id
        )

    def carb_mode_info(
        self, observed_bus_id: int, *, p5: bool = False
    ) -> DiagnosticMode:
        """V18 Common62b70 base /65d20 P5 alternate diagnostic context."""
        if type(p5) is not bool:
            raise ValueError("CARB cache family selector must be boolean")
        if self.catalog.management.version != 0x0100032F:
            raise ValueError(
                "Base CARB cache mode producer is recovered for version 18"
            )
        protocol = self.protocol_info(observed_bus_id)
        if protocol is None:
            raise ToyotaCodecError("Selected CARB protocol group is empty", 0xC0040101)
        if (
            73 not in self.catalog.management.sections
            or 72 not in self.catalog.management.sections
            or 16 not in self.catalog.management.sections
        ):
            raise ToyotaCodecError("Selected CARB resource is absent", 0xA0030107)
        carb = next(
            (
                row
                for row in correspondence_rows(
                    self.catalog.management, 73, self.exception_ids
                )
                if row[6] == observed_bus_id and row[7] == self.category_record[72]
            ),
            None,
        )
        if carb is None:
            raise ToyotaCodecError(
                "Selected CARB information group is empty", 0xC0040101
            )
        physical = next(
            (
                row
                for row in _rows(self.catalog.management, 72, 4)
                if row[2] == carb[8]
                and word(row, 0) == (word(protocol, 20 if p5 else 8) | 8)
            ),
            None,
        )
        if physical is None:
            raise ToyotaCodecError(
                "Selected CARB physical address is empty", 0xC0040101
            )
        target_key = int.from_bytes(carb[:4], "little")
        target = next(
            (
                row
                for row in correspondence_rows(
                    self.catalog.management, 16, self.exception_ids
                )
                if word(row, 68) == target_key
            ),
            None,
        )
        if target is None:
            raise ToyotaCodecError("Selected CARB target category is empty", 0xC0040101)
        return DiagnosticMode(target_key, word(physical, 0), carb[9], target[72])

    def _frame_context(self) -> str:
        values = (
            self.catalog.management.sha256,
            self.ecu_database_sha256,
            self.category_record,
            self.exception_ids,
            self.vehicle_name_key,
        )
        return hashlib.sha256(repr(values).encode("ascii")).hexdigest()

    def _function_rows(self, function_id: int) -> tuple[bytes, ...]:
        self._query_key(function_id)
        if 18 not in self.catalog.management.sections:
            raise ToyotaCodecError(
                "Selected function frame table is absent", 0xA0030107
            )
        rows = tuple(
            row
            for row in correspondence_rows(
                self.catalog.management, 18, self.exception_ids
            )
            if word(row, 0) == self.category and word(row, 2) == function_id
        )
        if len(rows) > 0x7FFF:
            raise ToyotaCodecError(
                "Selected record count exceeds native SHORT", 0xA0030110
            )
        return rows

    def function_frame(self, function_id: int) -> SelectedFrame:
        """Nativecc40 FIRST DB112 function/DB111 frame, with no ComSet lookup."""
        rows = self._function_rows(function_id)
        if not rows:
            raise ToyotaCodecError(
                "Selected function communication group is absent", 0x90020104
            )
        frame, comm = self._communication_frame(word(rows[0], 6))
        return SelectedFrame(
            frame,
            rows[0],
            comm,
            b"",
            f"DDB:{self.catalog.management.sha256}:native-function-only:category={self.category}:function={function_id}:profile={self._frame_context()}",
        )

    def frame_records(self, function_id: int) -> tuple[SelectedFrame, ...]:
        management = self.catalog.management
        functions = self._function_rows(function_id)
        if not functions:
            raise ValueError("No selected function communication frames")
        # GetCommFrmInfo selects settings from the FIRST function row for all frames.
        settings = self._communication_settings(word(functions[0], 4))
        selected = []
        for row in functions:
            frame, comm = self._communication_frame(word(row, 6))
            if not frame.request:
                raise ToyotaCodecError(
                    "Selected communication frame has no send bytes", 0xC0040102
                )
            selected.append(
                SelectedFrame(
                    frame,
                    row,
                    comm,
                    settings,
                    f"DDB:{management.sha256}:1/18:category={self.category}:function={function_id}:order={word(row, 10)}:profile={self._frame_context()}",
                )
            )
        return tuple(selected)

    def _communication_settings(self, settings_id: int, *, exact: bool = True) -> bytes:
        management = self.catalog.management
        if 29 not in management.sections:
            raise ToyotaCodecError(
                "Selected communication settings table is absent", 0xA0030107
            )
        rows = tuple(
            row
            for row in correspondence_rows(management, 29, self.exception_ids)
            if word(row, 10) == settings_id
        )
        if len(rows) > 0x7FFF:
            raise ToyotaCodecError(
                "Selected record count exceeds native SHORT", 0xA0030110
            )
        if not exact:
            if not rows:
                raise ToyotaCodecError(
                    "Selected communication settings group is empty", 0xC0040101
                )
            return rows[0]
        # SetCommSet6abe7 (12:47877) requires exactly one selected record.
        if len(rows) != 1:
            raise ToyotaCodecError(
                f"Expected one communication settings record; found {len(rows)}",
                0xC0040102,
            )
        return rows[0]

    def _communication_frame(self, frame_id: int) -> tuple[CommandFrame, bytes]:
        management = self.catalog.management
        if 17 not in management.sections:
            raise ToyotaCodecError(
                "Selected communication frame table is absent", 0xA0030107
            )
        rows: list[bytes] = []
        for row in management.sections[17].rows(8):
            if word(row, 0) == frame_id:
                rows.append(row)
            elif rows:
                break
        if not rows:
            raise ToyotaCodecError("No selected communication frame", 0xC0040101)
        if len(rows) > 0x7FFF:
            raise ToyotaCodecError(
                "Selected record count exceeds native SHORT", 0xA0030110
            )
        # GetDbRecord's SetRecVariableData10ace resolves all three blobs for ALL
        # rows before the first-row getters; a later invalid reference still fails.
        variables = _variables(management)
        for row in rows:
            if any(word(row, offset) > variables.count for offset in (2, 4, 6)):
                # CDbVariableTable.GetVariableData502c1 returns native invalid-argument.
                raise ToyotaCodecError(
                    "Variable reference outside directory", 0xA0030102
                )
        frames = tuple(CommandFrame.from_record(row, variables) for row in rows)
        return frames[0], rows[0]

    def communication_settings(self, settings_id: int) -> bytes:
        """Native SetCommSet alone: exactly one selected DB11D record."""
        self._query_key(settings_id)
        return self._communication_settings(settings_id)

    def communication_settings_first(self, settings_id: int) -> bytes:
        """Native packet-cache Init accepts FIRST nonempty ComSet group."""
        self._query_key(settings_id)
        return self._communication_settings(settings_id, exact=False)

    def behavior_frame(self, frame_id: int, settings_id: int) -> SelectedFrame:
        """IsBehaviorCode14050 (12:fc10): FIRST settings, then DB111 variables."""
        self._query_key(frame_id)
        self._query_key(settings_id)
        settings = self._communication_settings(settings_id, exact=False)
        frame, comm = self._communication_frame(frame_id)
        return SelectedFrame(
            frame,
            b"",
            comm,
            settings,
            f"DDB:{self.catalog.management.sha256}:native-behavior:1/29:settings={settings_id}:1/17:frame={frame_id}:profile={self._frame_context()}",
        )

    def direct_frame(self, frame_id: int, settings_id: int) -> SelectedFrame:
        """Native71790: DB111+variables first, then SetCommSet, without DB112."""
        self._query_key(frame_id)
        self._query_key(settings_id)
        frame, comm = self._communication_frame(frame_id)
        settings = self._communication_settings(settings_id)
        return SelectedFrame(
            frame,
            b"",
            comm,
            settings,
            f"DDB:{self.catalog.management.sha256}:native-direct:1/17:frame={frame_id}:1/29:settings={settings_id}:profile={self._frame_context()}",
        )

    def validate_frame(self, selected: SelectedFrame) -> None:
        """Fail closed unless actual selected records, decoded bytes and context agree.

        Provenance text alone is never authority: regenerate from this profile.
        """
        if (
            type(selected) is not SelectedFrame
            or type(selected.frame) is not CommandFrame
            or any(
                type(value) is not bytes
                for value in (
                    selected.function_record,
                    selected.communication_record,
                    selected.settings_record,
                    selected.frame.request,
                    selected.frame.receive_mask,
                    selected.frame.receive_check,
                )
            )
            or type(selected.provenance) is not str
            or len(selected.communication_record) != 8
        ):
            raise ValueError("Selected frame does not belong to this profile")
        candidates: list[SelectedFrame] = []
        try:
            if selected.function_record:
                if len(selected.function_record) != 16:
                    raise ValueError("Invalid selected function record")
                function_id = word(selected.function_record, 2)
                if selected.settings_record:
                    candidates.extend(self.frame_records(function_id))
                else:
                    candidates.append(self.function_frame(function_id))
            elif len(selected.settings_record) == 16:
                frame_id, settings_id = (
                    word(selected.communication_record, 0),
                    word(selected.settings_record, 10),
                )
                for producer in (self.direct_frame, self.behavior_frame):
                    try:
                        candidates.append(producer(frame_id, settings_id))
                    except ValueError:
                        continue
        except ValueError as error:
            raise ValueError(
                "Selected frame does not belong to this profile"
            ) from error
        if not any(selected == candidate for candidate in candidates):
            raise ValueError("Selected frame does not belong to this profile")

    def command_frames(self, function_id: int) -> tuple[CommandFrame, ...]:
        return tuple(record.frame for record in self.frame_records(function_id))


@dataclass(frozen=True, init=False)
class VehicleProfile(ProtocolProfile):
    """A management context with an actual bound ECU resource."""

    database: Database = field(repr=False)

    def __init__(
        self,
        catalog: VehicleCatalog,
        category_record: bytes,
        database: Database,
        exception_ids: tuple[int, ...] = (),
        vehicle_name_key: int | None = None,
    ) -> None:
        ProtocolProfile.__init__(
            self, catalog, category_record, exception_ids, vehicle_name_key
        )
        object.__setattr__(self, "database", database)

    @property
    def ecu_database_sha256(self) -> str:
        return self.database.sha256

    def records(self, slot: int) -> tuple[bytes, ...]:
        return correspondence_rows(self.database, slot, self.exception_ids)

    def ddr_records(self, slot: int, *keys: int) -> tuple[bytes, ...]:
        """Selected DDR bank query, excluding the facade's ECU-category argument.

        Each native FindDbItem stage returns its first contiguous matching group.
        Monitor/Invalid expose one query stage; Address/Trigger expose two.
        """
        if type(slot) is not int:
            raise ValueError("DDR slot must be an integer")
        role = next(
            (i for i, (slots, _) in enumerate(DDR_TABLE_GROUPS) if slot in slots), None
        )
        if role is None:
            raise ValueError("Slot is not a proven DDR resource bank")
        expected = 2 if role in (1, 2) else 1
        if len(keys) != expected:
            raise ValueError("Wrong number of native DDR query keys")
        for key in keys:
            self._query_key(key)
        if role == 0:
            offsets = ((24, False),)
        elif role == 1:
            base = 26 if self.database.version == 0x0100030C else 30
            offsets = ((base, True), (base + 1, True))
        elif role == 2:
            offsets = ((10, True), (11, True))
        else:
            offsets = ((4, False),)
        rows = self._signal_rows(slot)
        for key, (offset, byte_key) in zip(keys, offsets, strict=True):
            selected: list[bytes] = []
            for row in rows:
                value = row[offset] if byte_key else word(row, offset)
                if value == key:
                    selected.append(row)
                elif selected:
                    break
            rows = tuple(selected)
        return rows

    def custom_sign_records(self, kind: int) -> tuple[bytes, ...]:
        """DB114 FindDbItem1: selected BYTE8 custom-sign kind group."""
        self._query_key(kind)
        if 20 not in self.catalog.management.sections:
            raise ToyotaCodecError("Selected CustSignList table is absent", 0xA0030107)
        return tuple(
            row
            for row in correspondence_rows(
                self.catalog.management, 20, self.exception_ids
            )
            if row[8] == kind
        )

    def custom_item_records(self, key: int) -> tuple[bytes, ...]:
        """DB115 FindDbItem1: selected WORD8 custom-item group."""
        self._query_key(key)
        if 21 not in self.catalog.management.sections:
            raise ToyotaCodecError("Selected CustItem table is absent", 0xA0030107)
        return tuple(
            row
            for row in correspondence_rows(
                self.catalog.management, 21, self.exception_ids
            )
            if word(row, 8) == key
        )

    def operation_freeze_records(
        self, selector: int | None = None
    ) -> tuple[bytes, ...]:
        """DB236 all selected rows or BYTE7 group, distinct from overlayWORD2."""
        rows = self._signal_rows(54)
        if len(rows) > 0x7FFF:
            raise ToyotaCodecError(
                "Selected record count exceeds native SHORT", 0xA0030110
            )
        if selector is None:
            return rows
        self._query_key(selector)
        selected: list[bytes] = []
        for row in rows:
            if row[7] == selector:
                selected.append(row)
            elif selected:
                break
        return tuple(selected)

    def pcs_operation_pid_records(
        self, selector: int | None = None
    ) -> tuple[bytes, ...]:
        """Plain DB256 native BYTE3 first group; PID BYTE2 remains raw."""
        if self.database.version not in (0x0100030C, 0x0100032F):
            raise ValueError("No recovered PCS operation PID schema for this version")
        if selector is not None:
            self._query_key(selector)
        if 86 not in self.database.sections:
            raise ToyotaCodecError(
                "Selected PCS operation PID table is absent", 0xA0030107
            )
        rows = _rows(self.database, 86, 4)
        if selector is None:
            if len(rows) > 0x7FFF:
                raise ToyotaCodecError(
                    "Selected record count exceeds native SHORT", 0xA0030110
                )
            return rows
        selected: list[bytes] = []
        for row in rows:
            if row[3] == selector:
                selected.append(row)
            elif selected:
                break
        if len(selected) > 0x7FFF:
            raise ToyotaCodecError(
                "Selected record count exceeds native SHORT", 0xA0030110
            )
        return tuple(selected)

    def _bit_records(self, slot: int, reference: int) -> tuple[bytes, ...]:
        self._query_key(reference)
        selected: list[bytes] = []
        for row in self._signal_rows(slot):
            if word(row, 0) == reference:
                selected.append(row)
            elif selected:
                break
        rows = tuple(selected)
        if len(rows) > 0x7FFF:
            raise ToyotaCodecError(
                "Selected record count exceeds native SHORT", 0xA0030110
            )
        if rows:
            variables = _variables(self.catalog.management)
            if any(word(row, 2) > variables.count for row in rows):
                raise ToyotaCodecError(
                    "Variable reference outside directory", 0xA0030102
                )
            # Both native setters resolve EVERY selected row before GetVariable.
            for row in rows:
                variables.get(word(row, 2))
        return rows

    def _bit_variable(self, slot: int, row: bytes) -> bytes:
        if not isinstance(row, bytes) or len(row) < 2:
            raise ValueError("Bit definition row is not in the selected profile")
        if row not in self._bit_records(slot, word(row, 0)):
            raise ValueError("Bit definition row is not in the selected profile")
        return _variables(self.catalog.management).get(word(row, 2))

    def data_id_bit_records(self, reference: int) -> tuple[bytes, ...]:
        """DB23F FindDbItem1 + SetRecVariableData for the selected WORD0 group."""
        return self._bit_records(63, reference)

    def pid_bit_records(self, reference: int) -> tuple[bytes, ...]:
        """DB208 first WORD0 group with eager native WORD2 variable resolution."""
        return self._bit_records(8, reference)

    def pid_bit_variable(self, row: bytes) -> bytes:
        return self._bit_variable(8, row)

    def data_id_bit_variable(self, row: bytes) -> bytes:
        """DB23F native variable bytes from selected row WORD2."""
        return self._bit_variable(63, row)

    def ffd_bit_records(self, reference: int) -> tuple[bytes, ...]:
        """DB250 FindDbItem1 + SetRecVariableData for the selected WORD0 group."""
        return self._bit_records(80, reference)

    def ffd_bit_variable(self, row: bytes) -> bytes:
        """DB250 native variable bytes from selected row WORD2."""
        return self._bit_variable(80, row)

    def rob_bit_records(self, reference: int) -> tuple[bytes, ...]:
        """DB259 first WORD0 group with eager WORD2 variable resolution."""
        return self._bit_records(89, reference)

    def rob_bit_variable(self, row: bytes) -> bytes:
        return self._bit_variable(89, row)

    def work_factor_records(self, slot: int, *keys: int) -> tuple[bytes, ...]:
        """Native WorkFactor FindDbItem stages after selected ECU context."""
        fields = {37: (8, 10), 114: (16,), 115: (4, 18), 116: (8, 10), 117: (14,)}
        if type(slot) is not int or slot not in fields:
            raise ValueError("Unknown WorkFactor table")
        if not 1 <= len(keys) <= len(fields[slot]):
            raise ValueError("Wrong WorkFactor query key count")
        rows = self._signal_rows(slot)
        for key, offset in zip(keys, fields[slot], strict=False):
            if slot == 37 and offset == 10:
                # FindDbItem2 compares zero-extended row WORD with the full
                # DWORD physical value; values above 65535 simply do not match.
                if type(key) is not int or not 0 <= key <= 0xFFFFFFFF:
                    raise ValueError("WorkFactor pattern value must fit uint32")
            else:
                self._query_key(key)
            selected: list[bytes] = []
            for row in rows:
                byte_key = slot == 117 or (slot == 115 and offset == 18)
                value = row[offset] if byte_key else word(row, offset)
                if value == key:
                    selected.append(row)
                elif selected:
                    break
            rows = tuple(selected)
        if len(rows) > 0x7FFF:
            raise ToyotaCodecError(
                "Selected record count exceeds native SHORT", 0xA0030110
            )
        for row in rows:
            if slot in (37, 116):
                # Both setters overwrite the first GetString status before
                # checking the second (Pattern 57cf7/57d21; Operation574e1/5750b).
                try:
                    self.catalog._validate_text_references((row,), (0,))
                except ToyotaCodecError:
                    pass
            self.catalog._validate_text_references(
                (row,), {37: (4,), 114: (12,), 115: (0,), 116: (4,), 117: (0,)}[slot]
            )
        return rows

    def _work_factor_p4_records(
        self, slot: int, reference: int | None
    ) -> tuple[bytes, ...]:
        offset = 4 if slot == 35 else 20
        if reference is None:
            rows = self._signal_rows(slot)
            if len(rows) > 0x7FFF:
                raise ToyotaCodecError(
                    "Selected record count exceeds native SHORT", 0xA0030110
                )
        else:
            rows = self._selected_signal_records(slot, reference, offset)
        for row in rows:
            if slot == 36:
                # Native Item SetRecString overwrites the DWORD12 status with
                # DWORD16 before checking it (56592/565bc; same in version12).
                try:
                    self.catalog._validate_text_references((row,), (12,))
                except ToyotaCodecError:
                    pass
            self.catalog._validate_text_references((row,), (0 if slot == 35 else 16,))
        return rows

    def work_factor_signal_records(
        self, reference: int | None = None
    ) -> tuple[bytes, ...]:
        """DB223 all selected rows or first WORD4 group, eager DWORD0 names."""
        return self._work_factor_p4_records(35, reference)

    def work_factor_item_records(
        self, reference: int | None = None
    ) -> tuple[bytes, ...]:
        """DB224 all selected rows or first WORD20 group; BYTE34 stays raw."""
        return self._work_factor_p4_records(36, reference)

    def rob_data_id_records(self, reference: int) -> tuple[bytes, ...]:
        """DB25A first contiguous WORD2 group; versioned flag bytes remain raw."""
        self._query_key(reference)
        selected: list[bytes] = []
        for row in self._signal_rows(90):
            if word(row, 2) == reference:
                selected.append(row)
            elif selected:
                break
        if len(selected) > 0x7FFF:
            raise ToyotaCodecError(
                "Selected record count exceeds native SHORT", 0xA0030110
            )
        return tuple(selected)

    def _selected_signal_records(
        self,
        slot: int,
        reference: int,
        offset: int,
        *,
        byte_key: bool = False,
        text_offsets: tuple[int, ...] = (),
    ) -> tuple[bytes, ...]:
        if self.database.version not in (0x0100030C, 0x0100032F):
            raise ValueError("No recovered selected signal schema for this version")
        self._query_key(reference)
        selected: list[bytes] = []
        for row in self._signal_rows(slot):
            value = row[offset] if byte_key else word(row, offset)
            if value == reference:
                selected.append(row)
            elif selected:
                break
        if len(selected) > 0x7FFF:
            raise ToyotaCodecError(
                "Selected record count exceeds native SHORT", 0xA0030110
            )
        rows = tuple(selected)
        self.catalog._validate_text_references(rows, text_offsets)
        return rows

    def datamonitor_p5_records(self, logical_pid: int) -> tuple[bytes, ...]:
        """DB23E WORD36 group; SetRecString resolves DWORD24, not DWORD0."""
        return self._selected_signal_records(62, logical_pid, 36, text_offsets=(24,))

    def ddr_behavior_records(self, record_id: int | None = None) -> tuple[bytes, ...]:
        """DB286 all rows or WORD36 group, with eager DWORD24 labels."""
        if record_id is not None:
            return self._selected_signal_records(134, record_id, 36, text_offsets=(24,))
        rows = self._signal_rows(134)
        if len(rows) > 0x7FFF:
            raise ToyotaCodecError(
                "Selected record count exceeds native SHORT", 0xA0030110
            )
        self.catalog._validate_text_references(rows, (24,))
        return rows

    def ddr_behavior_code_records(
        self, behavior: int, first: int | None = None, second: int | None = None
    ) -> tuple[bytes, ...]:
        """DB285 WORD-only or full-structure query and native label setter."""
        if (first is None) != (second is None):
            raise ValueError("Behavior structure query requires both byte subkeys")
        self._query_key(behavior)
        rows = self._signal_rows(133)
        if first is None:
            selected: list[bytes] = []
            for row in rows:
                if word(row, 32) == behavior:
                    selected.append(row)
                elif selected:
                    break
            rows = tuple(selected)
        else:
            assert second is not None
            self._query_key(first)
            self._query_key(second)
            # Native structured FindDbItem scans the entire selected index;
            # unlike WORD-only FindDbItem1 it has no first-group stop.
            rows = tuple(
                row
                for row in rows
                if word(row, 32) == behavior and row[40] == first and row[41] == second
            )
        if len(rows) > 0x7FFF:
            raise ToyotaCodecError(
                "Selected record count exceeds native SHORT", 0xA0030110
            )
        for row in rows:
            # Native 293af/293d9 overwrite both earlier GetString statuses;
            # only the third call at 29403 controls the loop/error return.
            for offset in (12, 28):
                try:
                    self.catalog._validate_text_references((row,), (offset,))
                except ToyotaCodecError:
                    pass
            self.catalog._validate_text_references((row,), (16,))
        return rows

    def signal_group_records(self, signal: int | None = None) -> tuple[bytes, ...]:
        if signal is not None:
            return self._selected_signal_records(
                0, signal, 8, byte_key=True, text_offsets=(0,)
            )
        rows = self._signal_rows(0)
        if len(rows) > 0x7FFF:
            raise ToyotaCodecError(
                "Selected record count exceeds native SHORT", 0xA0030110
            )
        self.catalog._validate_text_references(rows, (0,))
        return rows

    def pid_records(self, pid: int) -> tuple[bytes, ...]:
        """DB206 BYTE2 first group; native SHORT bound follows filtering.

        The raw selected index may contain more than 32767 records in total.
        GetQuery passes FindDbItem1's filtered count to ResRecords.SetData.
        """
        if type(pid) is not int or not 0 <= pid <= 0xFFFFFFFF:
            raise ValueError("Native PID query must fit uint32")
        selected: list[bytes] = []
        for row in self._signal_rows(6):
            if row[2] == pid:
                selected.append(row)
            elif selected:
                break
        if len(selected) > 0x7FFF:
            raise ToyotaCodecError(
                "Selected record count exceeds native SHORT", 0xA0030110
            )
        # Pid ResRecords.SetRecString and SetRecVariableData are NOP in12/18.
        return tuple(selected)

    def signal_check_records(self, reference: int) -> tuple[bytes, ...]:
        """DB201 first WORD0 group; both native hydration setters are NOP."""
        return self._selected_signal_records(1, reference, 0)

    def comm_ecu_records(self, selector: int) -> tuple[bytes, ...]:
        """DB226 first WORD0 group in the selected ECU context; hydration NOP."""
        return self._selected_signal_records(38, selector, 0)

    def pattern_records(self, reference: int) -> tuple[bytes, ...]:
        """DB20E versioned family key; eagerly resolve every DWORD0 label."""
        offset = 4 if self.database.version == 0x0100030C else 12
        return self._selected_signal_records(14, reference, offset, text_offsets=(0,))

    def physical_records(self, reference: int) -> tuple[bytes, ...]:
        return self._selected_signal_records(13, reference, 12)

    def unit_records(self, reference: int) -> tuple[bytes, ...]:
        return self._selected_signal_records(15, reference, 4, text_offsets=(0,))

    def detail_code_records(self, reference: int) -> tuple[bytes, ...]:
        """DB22F selected FindDbItem1 WORD8 group; overlay also compares DWORD0."""
        self._query_key(reference)
        selected: list[bytes] = []
        for row in self._signal_rows(47):
            if word(row, 8) == reference:
                selected.append(row)
            elif selected:
                break
        return tuple(selected)

    def highlighting_records(self, reference: int) -> tuple[bytes, ...]:
        """Plain DB230 first contiguous WORD0 group, without exception overlays."""
        self._query_key(reference)
        if self.database.version not in (0x0100030C, 0x0100032F):
            raise ValueError(
                "HighlightingSignalInfo layout is unproven for this version"
            )
        section = self.database.sections.get(48)
        if section is None:
            raise ToyotaCodecError(
                "Selected HighlightingSignalInfo table is absent", 0xA0030107
            )
        selected: list[bytes] = []
        for row in section.rows(8):
            if word(row, 0) == reference:
                selected.append(row)
            elif selected:
                break
        return tuple(selected)

    def dtc_status_records(self, diagnostic_type: int) -> tuple[bytes, ...]:
        """DB242 selected FindDbItem1 compares the full DWORD0 diagnostic type."""
        if type(diagnostic_type) is not int or not 0 <= diagnostic_type <= 0xFFFFFFFF:
            raise ValueError("Diagnostic type must fit uint32")
        selected: list[bytes] = []
        for row in self._signal_rows(66):
            if struct.unpack_from("<I", row, 0)[0] == diagnostic_type:
                selected.append(row)
            elif selected:
                break
        if len(selected) > 0x7FFF:
            raise ToyotaCodecError(
                "Selected record count exceeds native SHORT", 0xA0030110
            )
        return tuple(selected)

    def multi_pid_records(self, parent_pid: int) -> tuple[bytes, ...]:
        """DB21A FindDbItem1: all selected WORD0 matches, in native order."""
        self._query_key(parent_pid)
        return tuple(row for row in self._signal_rows(26) if word(row, 0) == parent_pid)

    def signal_lsb_records(self, pid: int) -> tuple[bytes, ...]:
        """Common1f120: selected DB227 rows keyed by WORD8 signal PID."""
        self._query_key(pid)
        # Common1f176 explicitly treats missing resource A0030107 as count0.
        if 39 not in self.database.sections:
            return ()
        return tuple(row for row in self.records(39) if word(row, 8) == pid)

    def signal_did_lsb_records(self, pid: int) -> tuple[bytes, ...]:
        """Common1f9b0: optional DB240 selected logical PID WORD10 group."""
        self._query_key(pid)
        if 64 not in self.database.sections:
            return ()
        return tuple(row for row in self.records(64) if word(row, 10) == pid)

    def active_comm_mode(self, active_record: bytes) -> bytes | None:
        """PSA676f: optional DB23C override keyed by ActTest WORD56.

        An absent resource is explicitly tolerated by this native caller;
        malformed resources still fail. FIRST record BYTE2 overrides the SID.
        """
        if len(active_record) != 92:
            raise ValueError("ActTest record must be 92 bytes")
        if 60 not in self.database.sections:
            return None
        return next(
            (
                row
                for row in self.records(60)
                if word(row, 0) == word(active_record, 56)
            ),
            None,
        )

    def _signal_rows(self, slot: int) -> tuple[bytes, ...]:
        if slot not in self.database.sections:
            raise ToyotaCodecError("Selected signal table is absent", 0xA0030107)
        return self.records(slot)

    def signal_checks(self, signal_id: int) -> tuple[bytes, ...]:
        """Common84b80: first SignalGroup BYTE8 -> SignalCheck WORD0 group."""
        if type(signal_id) is not int or not 1 <= signal_id <= 255:
            raise ValueError("Native signal ID must be a nonzero byte")
        group = next((row for row in self._signal_rows(0) if row[8] == signal_id), None)
        if group is None:
            raise ToyotaCodecError("Selected SignalGroup key is empty", 0xC0040101)
        selected = tuple(
            row for row in self._signal_rows(1) if word(row, 0) == word(group, 4)
        )
        if not selected:
            raise ToyotaCodecError("Selected SignalCheck group is empty", 0xC0040101)
        return selected

    def signal_pids(self, signal_id: int) -> tuple[int, ...]:
        """Selected PID IDs in native append order, including duplicates84cfe."""
        return tuple(word(row, 2) for row in self.signal_checks(signal_id))

    def dtc_signal_checks(self, code: int) -> tuple[bytes, ...]:
        """CGW Common82a00: first DTCGroupRetrieve WORD0 -> BYTE2 signal."""
        if type(code) is not int or not 0 <= code <= 65535:
            raise ValueError("Native DTC group key must fit uint16")
        group = next(
            (row for row in self._signal_rows(32) if word(row, 0) == code), None
        )
        if group is None:
            raise ToyotaCodecError("Selected DTC group is empty", 0xC0040101)
        # CGW's direct DB200 lookup permits zero, unlike GetPidIdFromSignalId.
        signal = group[2]
        selected_group = next(
            (row for row in self._signal_rows(0) if row[8] == signal), None
        )
        if selected_group is None:
            raise ToyotaCodecError("Selected CGW SignalGroup is empty", 0xC0040101)
        selected = tuple(
            row
            for row in self._signal_rows(1)
            if word(row, 0) == word(selected_group, 4)
        )
        if not selected:
            raise ToyotaCodecError(
                "Selected CGW SignalCheck group is empty", 0xC0040101
            )
        return selected

    def freeze_records(
        self, pid: int = 0x100, logical_pid: int | None = None
    ) -> tuple[bytes, ...]:
        """DB20A native BYTE selector/wildcard query, eagerly resolving DWORD48."""
        if type(pid) is not int or not 0 <= pid <= 0xFFFFFFFF:
            raise ValueError("Freeze selector must fit uint32")
        if logical_pid is not None and (
            type(logical_pid) is not int or not 0 <= logical_pid <= 0xFFFFFFFF
        ):
            raise ValueError("Freeze logical PID must fit uint32")
        rows = self._signal_rows(10)
        if pid <= 0xFF:
            selected: list[bytes] = []
            for row in rows:
                if row[79] == pid:
                    selected.append(row)
                elif selected:
                    break
            rows = tuple(selected)
            if logical_pid is not None:
                selected = []
                for row in rows:
                    if word(row, 56) == logical_pid:
                        selected.append(row)
                    elif selected:
                        break
                rows = tuple(selected)
        elif logical_pid is not None:
            # Native wildcard GetQuery37efd scans ALL rows (37fd1..37ff5),
            # not FindDbItem2's first contiguous WORD group.
            rows = tuple(row for row in rows if word(row, 56) == logical_pid)
        if len(rows) > 0x7FFF:
            raise ToyotaCodecError(
                "Selected record count exceeds native SHORT", 0xA0030110
            )
        self.catalog._validate_text_references(rows, (48,))
        return rows

    def dtc_freeze_records(self, code: int) -> tuple[SelectedSignal, ...]:
        """CGW82585: (category, BYTE wildcard0x100, PID) -> FIRST Freeze."""
        checks = self.dtc_signal_checks(code)
        result = []
        for check in checks:
            pid = word(check, 2)
            freezes = self.freeze_records(0x100, pid)
            freeze = freezes[0] if freezes else None
            if freeze is None:
                raise ToyotaCodecError("Selected CGW Freeze key is empty", 0xC0040101)
            physical = None
            if freeze[78] & 2:
                physical = next(
                    (
                        row
                        for row in self._signal_rows(13)
                        if word(row, 12) == word(freeze, 60)
                    ),
                    None,
                )
            result.append(
                SelectedSignal(
                    pid,
                    check,
                    freeze,
                    physical,
                    f"DDB:{self.database.sha256}:2/32->0->1->10:category={self.category}:DTC={code}:PID={pid}",
                )
            )
        return tuple(result)

    def pid_bits(self) -> dict[int, PidBit]:
        variables = _variables(self.catalog.management)
        rows = self.records(8)
        result = {}
        for row in rows:
            key = word(row, 0)
            if key in result:
                raise ValueError("Ambiguous selected PidBit key")
            result[key] = PidBit.from_record(row, variables)
        return result

    def did_bits(self, references: Sequence[int] | None = None) -> dict[int, PidBit]:
        variables = _variables(self.catalog.management)
        return {
            word(row, 0): PidBit(
                word(row, 6), word(row, 8), row[10], variables.get(word(row, 2))
            )
            for row in self.records(9)
            if references is None or word(row, 0) in references
        }

    def active_tests(
        self,
        *,
        pid_lengths: Mapping[int, int],
        did_lengths: Mapping[int, int],
        exchange: Callable[[bytes], bytes],
    ) -> tuple[dict, ...]:
        """GetActTstList P3/DK: selected rows gated by observed enable lists."""
        rows = self.records(11)
        references = {
            word(row, 60)
            for row in rows
            if row[83] == 0
            and word(row, 60)
            and (did_lengths.get(row[82], 0) & 255) * 8 > word(row, 68)
        }
        bits = self.did_bits(tuple(references))
        selected = []
        for index, row in enumerate(rows):
            if check_active_support(
                row, pid_lengths, did_lengths, bits, self.command_frames, exchange
            ):
                selected.append(
                    {
                        "row": index,
                        "signal_id": word(row, 56),
                        "name": self.catalog.language.resolve(
                            int.from_bytes(row[32:36], "little")
                        ),
                        "short_name_hex": row[:32].hex(),
                        "control_value": int.from_bytes(row[40:44], "little"),
                        "raw_hex": row.hex(),
                        "physical_status": "PHYSICAL_UNCONFIRMED",
                    }
                )
        return tuple(selected)

    def report(self) -> dict:
        return {
            "category": self.category,
            "file": self.filename,
            "vehicle_name_key": self.vehicle_name_key,
            "exception_ids": list(self.exception_ids),
            "management_sha256": self.catalog.management.sha256,
            "ecu_sha256": self.database.sha256,
            "selection": "explicit-resource-selection",
            "physical_status": "PHYSICAL_UNCONFIRMED",
        }


class VehicleCatalog(DiagnosticCatalog):
    """Model/option labels retain their real database keys; no name matching."""

    def __init__(self, root: Path, *, registered_sets: Sequence[str] = ()):
        super().__init__(root)
        if any(not isinstance(name, str) or "\0" in name for name in registered_sets):
            raise ValueError("Registered vehicle-set names must be NUL-free strings")
        self.registered_sets = frozenset(registered_sets)
        self.vehicle_sets = {}
        for row in _rows(self.management, 82, 20):
            self.vehicle_sets.setdefault(
                word(row, 18), row[:18].decode("utf-16le").split("\0", 1)[0]
            )
        self.vehicles = self.management.named_records(43, self.language)
        self.options = [
            {
                "row": index,
                "name": self.language.resolve(int.from_bytes(row[:4], "little")),
                "key1": word(row, 4),
                "key2": word(row, 6),
                "key3": word(row, 8),
                "vehicle_name_key": word(row, 10),
                "next_group": word(row, 12),
                "raw_hex": row.hex(),
            }
            for index, row in enumerate(_rows(self.management, 42, 16))
        ]

        self._option_index: dict[tuple[int, int], list[dict]] = {}
        for option in self.options:
            self._option_index.setdefault((option["key1"], option["key2"]), []).append(
                option
            )
        self.categories = [
            {
                "name": self.language.resolve(int.from_bytes(row[:4], "little")),
                "key": word(row, 4),
                "collect_key": word(row, 6),
            }
            for row in _rows(self.management, 47, 8)
        ]
        self.collect_items = {
            (word(row, 4), word(row, 6)): {
                "name": self.language.resolve(int.from_bytes(row[:4], "little")),
                "key": word(row, 6),
                "order": word(row, 8),
            }
            for row in _rows(self.management, 46, 12)
        }
        self.vehicle_definitions = [
            {
                "row": index,
                "raw_hex": row.hex(),
                "categories": [
                    self._collect_item(group + 1, word(row, 40 + group * 2))
                    for group in range(4)
                    if word(row, 40 + group * 2)
                    and any(
                        category["key"] == group + 1 for category in self.categories
                    )
                ],
                "category_keys": [word(row, 40 + group * 2) for group in range(4)],
                "option_key": word(row, 48),
                "vehicle_name_key": word(row, 50),
            }
            for index, row in enumerate(_rows(self.management, 41, 52))
        ]

    @property
    def vin_vehicle_definitions(self) -> tuple[dict, ...]:
        return tuple(
            {
                "row": index,
                "raw_hex": row.hex(),
                "option_key": word(row, 12),
                "vehicle_name_key": word(row, 14),
                "category": word(row, 16),
                "variant": row[18],
            }
            for index, row in enumerate(_rows(self.management, 59, 32))
        )

    def raw_matching_vin_vehicles(
        self, context: VinVehicleContext, *, collect_key: int = 0
    ) -> tuple[dict, ...]:
        """Native VIN matches before optional caller-specific registration filtering."""
        if type(collect_key) is not int or not 0 <= collect_key <= 0xFFFF:
            raise ValueError("VIN collection key must be u16")
        return tuple(
            definition
            for definition in self.vin_vehicle_definitions
            if vin_vehicle_matches(bytes.fromhex(definition["raw_hex"]), context)
            and (
                not collect_key
                or word(bytes.fromhex(definition["raw_hex"]), 4) == collect_key
            )
        )

    def matching_vin_vehicles(
        self, context: VinVehicleContext, *, collect_key: int = 0
    ) -> tuple[dict, ...]:
        return tuple(
            definition
            for definition in self.raw_matching_vin_vehicles(
                context, collect_key=collect_key
            )
            if (
                self._option_choices(definition["option_key"], 1)
                if not definition["vehicle_name_key"]
                else self._vehicle_allowed(definition["vehicle_name_key"])
            )
        )

    def resolve_vin_vehicle(
        self, decision_row: int, answers: Sequence[int] = ()
    ) -> dict:
        definitions = self.vin_vehicle_definitions
        if type(decision_row) is not int or not 0 <= decision_row < len(definitions):
            raise ValueError("VIN decision row is outside this catalog")
        return self._resolve_definition(definitions[decision_row], answers)

    def vehicle_identity(self, vehicle_name_key: int) -> ExceptionContext:
        """SetVehicleInfoForVehicleId_DT first normal row, then VIN fallback.

        Native lookup scans all rows of the referenced option tree for the
        terminal key; it does not require a particular answered option path.
        Only category/variant are supplied by this operation.
        """
        if type(vehicle_name_key) is not int or not any(
            row["key"] == vehicle_name_key for row in self.vehicles
        ):
            raise ValueError("Unknown vehicle name key")
        for (
            slot,
            width,
            option_offset,
            direct_offset,
            category_offset,
            variant_offset,
        ) in (
            (41, 52, 48, 50, 0, 2),
            (59, 32, 12, 14, 16, 18),
        ):
            for row in _rows(self.management, slot, width):
                option_key = word(row, option_offset)
                matched = (
                    any(
                        option["key1"] == option_key
                        and option["vehicle_name_key"] == vehicle_name_key
                        for option in self.options
                    )
                    if option_key
                    else word(row, direct_offset) == vehicle_name_key
                )
                if matched:
                    return ExceptionContext(
                        word(row, category_offset), row[variant_offset]
                    )
        raise ValueError("Vehicle name has no original normal or VIN decision row")

    def default_diagnostic_mode(
        self, category: int, protocol: int, exception_ids: tuple[int, ...] = ()
    ) -> DiagnosticMode:
        """GetDefaultExcept_DT RVA 0x1910: static alternate diagnostic context.

        Uses first matching records, as the native caller does. Reserved bytes
        at DIAGNOSTIC_INFO+2 are left to the caller's original sixteen-byte value.
        """
        for value, limit in ((category, 0xFFFF), (protocol, 255)):
            if type(value) is not int or not 0 <= value <= limit:
                raise ValueError("Diagnostic category/protocol out of range")

        def first(rows: Sequence[bytes], description: str) -> bytes:
            if not rows:
                raise ValueError(f"Missing {description}")
            return rows[0]

        prot = first(
            [
                row
                for row in correspondence_rows(self.management, 13, exception_ids)
                if word(row, 0) == category
                and row[22 if self.management.version == 0x0100030C else 24] == protocol
            ],
            "protocol info",
        )
        categories = correspondence_rows(self.management, 16, exception_ids)
        source = first(
            [row for row in categories if word(row, 68) == category], "source category"
        )
        carb = first(
            [
                row
                for row in correspondence_rows(self.management, 73, exception_ids)
                if row[6] == protocol and row[7] == source[72]
            ],
            "CARB info",
        )
        physical = first(
            [
                row
                for row in _rows(self.management, 72, 4)
                if row[2] == carb[8] and word(row, 0) == (word(prot, 20) | 8)
            ],
            "CARB physical address",
        )
        key1 = int.from_bytes(carb[:4], "little")
        target = first(
            [row for row in categories if word(row, 68) == key1], "target category"
        )
        return DiagnosticMode(key1, word(physical, 0), carb[9], target[72])

    def resolve_protocol_vehicle(
        self,
        selection: ProtocolSelection,
        vin: bytes,
        *,
        decision_row: int | None = None,
        answers: Sequence[int] = (),
        collect_key: int = 0,
    ) -> dict:
        """Protocol cache observation -> original VIN matches -> native options.

        Multiple matching definitions require an explicit row choice. No VIN is
        obtained here: caller supplies the selected protocol's observed bytes.
        """
        matches = self.matching_vin_vehicles(
            VinVehicleContext.from_vin(selection.category, selection.variant, vin),
            collect_key=collect_key,
        )
        if not matches:
            raise ValueError(
                "Observed protocol/VIN has no selectable vehicle definition"
            )
        if decision_row is None and len(matches) != 1:
            if answers:
                raise ValueError(
                    "Choose a VIN vehicle definition before answering options"
                )
            return {"status": "needs_vehicle", "choices": list(matches)}
        if decision_row is None:
            decision_row = matches[0]["row"]
        if type(decision_row) is not int or not any(
            row["row"] == decision_row for row in matches
        ):
            raise ValueError("VIN vehicle choice is not a matching definition")
        return self.resolve_vin_vehicle(decision_row, answers)

    def protocol_candidates(
        self, exception_ids: tuple[int, ...] = ()
    ) -> tuple[ProtocolCandidate, ...]:
        """ProtJudge ordering and selected EcuCategory protocol field for probes."""
        categories = correspondence_rows(self.management, 16, exception_ids)
        result = []
        for row in _rows(self.management, 2, 4):
            category = word(row, 0)
            resource = _one(
                tuple(item for item in categories if word(item, 68) == category),
                "protocol candidate ECU category",
            )
            result.append(ProtocolCandidate(category, row[2], resource[72]))
        return tuple(result)

    def protocol_resume_index(self, category: int, variant: int) -> int:
        """SelectCarTypVn10 RVA 0x6590 resumes AFTER the current candidate."""
        for value, limit in ((category, 0xFFFF), (variant, 255)):
            if type(value) is not int or not 0 <= value <= limit:
                raise ValueError("Protocol category/variant out of range")
        rows = _rows(self.management, 2, 4)
        return next(
            (
                index + 1
                for index, row in enumerate(rows)
                if word(row, 0) == category and row[2] == variant
            ),
            len(rows),
        )

    def _collect_item(self, category: int, key: int) -> dict:
        item = self.collect_items.get((category, key))
        if item is None:
            raise ValueError(
                "Vehicle category value is missing from original collection table"
            )
        return item

    def _validate_text_references(
        self, rows: tuple[bytes, ...], offsets: tuple[int, ...]
    ) -> None:
        for row in rows:
            for offset in offsets:
                try:
                    self.language.resolve(struct.unpack_from("<I", row, offset)[0])
                except ValueError as error:
                    # GetString48bf9 delegates to50383: out-of-directory A0030102.
                    raise ToyotaCodecError(str(error), 0xA0030102) from error

    def _vehicle_label_records(
        self,
        slot: int,
        width: int,
        keys: tuple[int, ...],
        *,
        key_offsets: tuple[int, ...] = (4, 6),
        text_offsets: tuple[int, ...] = (0,),
    ) -> tuple[bytes, ...]:
        if self.management.version not in (0x0100030C, 0x0100032F):
            raise ValueError("No recovered vehicle-label schema for this version")
        if slot not in self.management.sections:
            raise ToyotaCodecError("Selected vehicle-label table is absent", 0xA0030107)
        rows = _rows(self.management, slot, width)
        for offset, key in zip(key_offsets, keys, strict=False):
            VehicleProfile._query_key(key)
            selected: list[bytes] = []
            for row in rows:
                if word(row, offset) == key:
                    selected.append(row)
                elif selected:
                    break
            rows = tuple(selected)
        if len(rows) > 0x7FFF:
            raise ToyotaCodecError(
                "Selected record count exceeds native SHORT", 0xA0030110
            )
        # Native SetRecString resolves DWORD0 for EVERY selected row.
        self._validate_text_references(rows, text_offsets)
        return rows

    def category_master_records(self) -> tuple[bytes, ...]:
        """DB12F ALL query with eager DWORD0 names; rows remain unnormalized."""
        if self.management.version not in (0x0100030C, 0x0100032F):
            raise ValueError("No recovered category master schema for this version")
        if 47 not in self.management.sections:
            raise ToyotaCodecError(
                "Selected category master table is absent", 0xA0030107
            )
        rows = _rows(self.management, 47, 8)
        if len(rows) > 0x7FFF:
            raise ToyotaCodecError(
                "Selected record count exceeds native SHORT", 0xA0030110
            )
        self._validate_text_references(rows, (0,))
        return rows

    def collect_item_records(self, level: int, value: int) -> tuple[bytes, ...]:
        """Plain DB12E: staged WORD4/WORD6 groups, preserving duplicate count."""
        return self._vehicle_label_records(46, 12, (level, value))

    def vehicle_brand_records(self, vehicle_name_key: int) -> tuple[bytes, ...]:
        """Plain DB143: first contiguous WORD4 group; DWORD0 is BrandName."""
        return self._vehicle_label_records(67, 8, (vehicle_name_key,))

    def option_records(
        self, option_key: int, group: int | None = None, choice: int | None = None
    ) -> tuple[bytes, ...]:
        """DB12A literal WORD4/6/8 query stages, without registration pruning."""
        if choice is not None and group is None:
            raise ValueError("An option choice requires its group")
        keys = (
            (option_key,)
            + ((group,) if group is not None else ())
            + ((choice,) if choice is not None else ())
        )
        return self._vehicle_label_records(42, 16, keys, key_offsets=(4, 6, 8))

    def vehicle_name_records(self, vehicle_name_key: int) -> tuple[bytes, ...]:
        """DB12B WORD4 group; DWORD0 is native GetCarSignName reference."""
        return self._vehicle_label_records(43, 12, (vehicle_name_key,))

    def vehicle_set_records(self, vehicle_name_key: int) -> tuple[bytes, ...]:
        """DB152 WORD18 group; inline name bytes remain raw, no language lookup."""
        return self._vehicle_label_records(
            82, 20, (vehicle_name_key,), key_offsets=(18,), text_offsets=()
        )

    def ecu_group_records(
        self, selection_key: int, kind: int, exception_ids: Sequence[int] = ()
    ) -> tuple[bytes, ...]:
        """DB105 GetEcuGroupList: explicit shared key WORD4, then kind BYTE11."""
        VehicleProfile._query_key(selection_key)
        VehicleProfile._query_key(kind)
        if 5 not in self.management.sections:
            raise ToyotaCodecError("Selected ECU group table is absent", 0xA0030107)
        rows = correspondence_rows(self.management, 5, exception_ids)
        for offset, key in ((4, selection_key), (11, kind)):
            selected: list[bytes] = []
            for row in rows:
                value = row[offset] if offset == 11 else word(row, offset)
                if value == key:
                    selected.append(row)
                elif selected:
                    break
            rows = tuple(selected)
        if len(rows) > 0x7FFF:
            raise ToyotaCodecError(
                "Selected record count exceeds native SHORT", 0xA0030110
            )
        self._validate_text_references(rows, (0,))
        return rows

    def _vehicle_allowed(self, key: int) -> bool:
        name = self.vehicle_sets.get(key)
        return name is None or name in self.registered_sets

    def _option_choices(
        self, option_key: int, group: int, visited: frozenset[int] = frozenset()
    ) -> list[dict]:
        if group in visited:
            raise ValueError("Cycle in vehicle option tree")
        rows = self._option_index.get((option_key, group), [])
        if not rows:
            raise ValueError("Missing vehicle option group")
        choices = []
        for row in rows:
            key = row["vehicle_name_key"]
            if key:
                allowed = self._vehicle_allowed(key)
            else:
                next_group = row["next_group"]
                allowed = (
                    bool(
                        self._option_choices(option_key, next_group, visited | {group})
                    )
                    if next_group
                    else False
                )
                if not next_group:
                    raise ValueError(
                        "Native option fallback needs a protocol-selection observation"
                    )
            if allowed:
                choices.append(row)
        return choices

    def selectable_vehicles(self) -> tuple[dict, ...]:
        """Original DelVehicleResRecord/VehicleSet registration policy."""
        return tuple(
            definition
            for definition in self.vehicle_definitions
            if (
                self._option_choices(definition["option_key"], 1)
                if not definition["vehicle_name_key"]
                else self._vehicle_allowed(definition["vehicle_name_key"])
            )
        )

    def raw_matching_vehicles(self, context: VehicleContext) -> tuple[dict, ...]:
        """DB129 matches before non-display/option pruning, preserving EU scoring."""
        if 41 not in self.management.sections:
            raise ToyotaCodecError(
                "Selected vehicle decision table is absent", 0xA0030107
            )
        selected = []
        score, best = 0, 0
        for index, row in enumerate(_rows(self.management, 41, 52)):
            matched, score = vehicle_matches(row, context, score)
            if not matched:
                continue
            if context.mode in (2, 3) and score > best:
                selected.clear()
                best = score
            definition = self.vehicle_definitions[index]
            selected.append({**definition, "prefix_score": score})
        # VehicleDecision's override forwards the matched count to baseSetData
        # (18:51139 ->447fa;12:4aac9 ->3e18a).
        if len(selected) > 0x7FFF:
            raise ToyotaCodecError(
                "Selected record count exceeds native SHORT", 0xA0030110
            )
        return tuple(selected)

    def matching_vehicles(self, context: VehicleContext) -> tuple[dict, ...]:
        """Native matches plus the catalog's registration/option policy."""
        selectable = {definition["row"] for definition in self.selectable_vehicles()}
        return tuple(
            row
            for row in self.raw_matching_vehicles(context)
            if row["row"] in selectable
        )

    def resolve_vehicle(self, decision_row: int, answers: Sequence[int] = ()) -> dict:
        """Follow the native Option tree; an unanswered branch returns its choices."""
        if type(decision_row) is not int or not 0 <= decision_row < len(
            self.vehicle_definitions
        ):
            raise ValueError("Vehicle decision row is outside this catalog")
        return self._resolve_definition(self.vehicle_definitions[decision_row], answers)

    def _resolve_definition(self, definition: dict, answers: Sequence[int]) -> dict:
        option_key, group = definition["option_key"], 1
        vehicle_key = definition["vehicle_name_key"] if not option_key else 0
        position, visited = 0, set()
        while option_key and not vehicle_key:
            if group in visited:
                raise ValueError("Cycle in vehicle option tree")
            visited.add(group)
            choices = self._option_choices(option_key, group)
            if not choices:
                raise ValueError("Missing vehicle option group")
            if position == len(answers):
                return {
                    "status": "needs_option",
                    "decision": definition,
                    "group": group,
                    "choices": choices,
                }
            answer = answers[position]
            if type(answer) is not int:
                raise ValueError("Option answer must be an integer key")
            choice = [row for row in choices if row["key3"] == answer]
            if len(choice) != 1:
                raise ValueError("Option answer is missing or ambiguous")
            position += 1
            vehicle_key, group = choice[0]["vehicle_name_key"], choice[0]["next_group"]
            if not vehicle_key and not group:
                raise ValueError(
                    "Native option fallback needs a protocol-selection observation"
                )
        if position != len(answers):
            raise ValueError("Unused vehicle option answers")
        if not self._vehicle_allowed(vehicle_key):
            raise ValueError("Vehicle requires an unregistered native vehicle set")
        names = [row for row in self.vehicles if row["key"] == vehicle_key]
        if len(names) != 1:
            raise ValueError("Vehicle selection has no unique original name")
        return {
            "status": "selected",
            "decision": definition,
            "vehicle_name_key": vehicle_key,
            "name": names[0]["name"],
            "answers": list(answers),
        }

    def vehicle_systems(
        self, vehicle_name_key: int, exception_ids: tuple[int, ...] = ()
    ) -> tuple[dict, ...]:
        """EcuGroup type 1 -> InstallingEcuList -> EcuCategory resource join."""
        if type(vehicle_name_key) is not int or not any(
            row["key"] == vehicle_name_key for row in self.vehicles
        ):
            raise ValueError("Unknown vehicle name key")
        if not self._vehicle_allowed(vehicle_name_key):
            raise ValueError("Vehicle requires an unregistered native vehicle set")
        groups = [
            row
            for row in correspondence_rows(self.management, 5, exception_ids)
            if word(row, 4) == vehicle_name_key and row[11] == 1
        ]
        installed = correspondence_rows(self.management, 44, exception_ids)
        categories = correspondence_rows(self.management, 16, exception_ids)
        result = []
        for group in groups:
            for row in installed:
                if word(row, 4) != word(group, 6):
                    continue
                category = word(row, 6)
                resource = _one(
                    tuple(item for item in categories if word(item, 68) == category),
                    "vehicle ECU category",
                )
                result.append(
                    {
                        "category": category,
                        "name": self.language.resolve(
                            int.from_bytes(row[:4], "little")
                        ),
                        "file": resource[:40].decode("utf-16le").split("\0", 1)[0],
                        "group_record_hex": group.hex(),
                        "installing_record_hex": row.hex(),
                        "physical_status": "PHYSICAL_UNCONFIRMED",
                    }
                )
        return tuple(result)

    def build_protocol_profile(
        self, category: int, *, exception_ids: tuple[int, ...] = ()
    ) -> ProtocolProfile:
        """Bind management DB110 FIRST row without opening a per-ECU resource.

        Native ChangeCommIF18 14510 /12 ffa0 accepts count>0, then reads the
        first category row. No filename is needed for this management phase.
        """
        ProtocolProfile._query_key(category)
        if 16 not in self.management.sections:
            raise ToyotaCodecError("Selected ECU category table is absent", 0xA0030107)
        rows = tuple(
            row
            for row in correspondence_rows(self.management, 16, exception_ids)
            if word(row, 68) == category
        )
        if len(rows) > 0x7FFF:
            raise ToyotaCodecError(
                "Selected record count exceeds native SHORT", 0xA0030110
            )
        if not rows:
            raise ValueError(
                "Selected protocol category is not in the management database"
            )
        # EcuCategory SetRecString resolves DWORD60 for every row, but its
        # loop returns only the LAST status (18:32e8b/32e93;12:2d00b/2d013).
        last_error: ToyotaCodecError | None = None
        for row in rows:
            try:
                self._validate_text_references((row,), (60,))
                last_error = None
            except ToyotaCodecError as error:
                last_error = error
        if last_error is not None:
            raise last_error
        return ProtocolProfile(self, rows[0], tuple(exception_ids))

    def build_profile(
        self,
        category: int,
        *,
        exception_ids: tuple[int, ...] = (),
        vehicle_name_key: int | None = None,
    ) -> VehicleProfile:
        if type(category) is not int or not 0 <= category <= 0xFFFF:
            raise ValueError("Category must be u16")
        if vehicle_name_key is not None and not any(
            row["key"] == vehicle_name_key for row in self.vehicles
        ):
            raise ValueError("Vehicle name key is not in this management database")
        if vehicle_name_key is not None:
            if not self._vehicle_allowed(vehicle_name_key):
                raise ValueError("Vehicle requires an unregistered native vehicle set")
            if not any(
                row["category"] == category
                for row in self.vehicle_systems(vehicle_name_key, exception_ids)
            ):
                raise ValueError("Category is not associated with the selected vehicle")
        row = _one(
            tuple(
                row
                for row in correspondence_rows(self.management, 16, exception_ids)
                if word(row, 68) == category
            ),
            "selected ECU category",
        )
        filename = row[:40].decode("utf-16le").split("\0", 1)[0]
        database = self.read_system(filename)
        return VehicleProfile(
            self, row, database, tuple(exception_ids), vehicle_name_key
        )
