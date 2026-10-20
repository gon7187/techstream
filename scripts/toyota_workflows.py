"""Selected native Toyota workflows over explicit offline transport evidence."""

from __future__ import annotations

import copy
import hashlib
import json
import struct
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

if TYPE_CHECKING:
    from scripts.freeze_p5 import P5Diagnostic, P5FreezeState, P5SnapshotRequest
    from scripts.native_communication import NativeCommunication

from scripts.data_monitor import MonitorSignalMetadata
from scripts.local_files import read_regular
from scripts.monitor_support import (
    MonitorSupportCache,
    SupportQuery,
    SupportReceive,
    SupportSend,
    SupportStream,
    SupportTransaction,
)
from scripts.native_replay import NativeReplay
from scripts.profiles import SelectedFrame, VehicleProfile
from scripts.signal_conversion import extract_bits
from scripts.signal_display import render_signal
from scripts.signal_lsb import SignalLSB
from scripts.support import correspondence_rows, word
from scripts.toyota import CommandFrame, ToyotaCodecError, VariableTable
from scripts.toyota_session import (
    Cancelled,
    CommandSpec,
    Exchange,
    Limits,
    NativeFrameSend,
    NativeSend,
    NativeStatus,
    SessionError,
    ToyotaSession,
    ffd_type,
)


def _unsigned(value: int, maximum: int) -> None:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("Selected native context field is outside its ABI bounds")


def _multi_frame_index(value: int) -> int:
    """Native V2:15B0 / MultiP4:1B40 signed circular high-nibble mapping."""
    high = (value & 0xF0) >> 4
    return high if high < 3 else high - 16


@dataclass(frozen=True)
class WorkflowLabel:
    text: str
    source_sha256: str
    source_path: str | None
    source_version: int
    synthetic: bool = False

    def __post_init__(self) -> None:
        if type(self.source_version) is not int or self.source_version not in (12, 18):
            raise ValueError("Workflow label source version must be12/18")
        if type(self.synthetic) is not bool:
            raise TypeError("Workflow label provenance must be explicitly boolean")
        if (
            not isinstance(self.source_sha256, str)
            or len(self.source_sha256) != 64
            or any(c not in "0123456789abcdef" for c in self.source_sha256)
        ):
            raise ValueError("Workflow label source requires a SHA256 digest")
        if self.source_path is not None and (
            not isinstance(self.source_path, str)
            or len(self.source_path.encode("utf-8")) > 4096
        ):
            raise ValueError("Workflow label path exceeds the local bound")
        if not self.synthetic and self.source_path is None:
            raise ValueError("Native workflow label requires its source path")
        if (
            not isinstance(self.text, str)
            or not self.text
            or len(self.text.encode("utf-8")) > 65535
        ):
            raise ValueError("Workflow label must be a nonempty bounded string")

    @classmethod
    def authored(cls, text: str, *, version: int = 18) -> WorkflowLabel:
        return cls(
            text, hashlib.sha256(text.encode("utf-8")).hexdigest(), None, version, True
        )


def load_psd_label(path: Path) -> WorkflowLabel:
    """Read the exact supplied native literal; never load or execute a DLL."""
    source = path.resolve(strict=True)
    raw = read_regular(source, limit=16 * 1024 * 1024)
    digest = hashlib.sha256(raw).hexdigest()
    verified = {
        "cb035c7de5342d886994f31ca82b96240e1a89a466b5a8ef0dc52ec937438ae1": (
            18,
            0x9214,
        ),
        "d88c6401cbaa83508d637887b537c8d1fdca62a833579f9509f653775e12e1e0": (
            12,
            0x90AC,
        ),
    }
    if digest not in verified:
        raise ValueError("PSD label source is not a verified original module")
    version, offset = verified[digest]
    encoded = raw[offset : offset + 256].split(b"\0", 1)
    if len(encoded) != 2:
        raise ValueError("Verified PSD label lacks a bounded terminator")
    return WorkflowLabel(encoded[0].decode("cp932"), digest, str(source), version)


@dataclass(frozen=True)
class WorkflowObservations:
    """One selected ECU's native identity and explicitly supplied cache state.

    Function keys are the three native CFuncInfoCache keys; values are the
    native DWORD returned for the leaf. An explicit empty map means the
    observed tree has no matching nodes. None means no observation was supplied.
    """

    native_id: int
    bus_id: int
    functions: Mapping[tuple[int, int, int], int] | None = None
    targets: tuple[tuple[int, int], ...] = ()
    pid_positions: Mapping[int, bytes] | None = None
    pid_lengths: Mapping[int, int] | None = None
    did_lengths: Mapping[int, int] | None = None
    enabled_rids: frozenset[int] | None = None
    mode_seed: bytes | None = None
    source_version: int = 18

    def __post_init__(self) -> None:
        _unsigned(self.native_id, 0xFFFFFFFF)
        _unsigned(self.bus_id, 0xFFFF)
        if type(self.source_version) is not int or self.source_version not in (12, 18):
            raise ValueError(
                "Workflow algorithms require explicit supported source version12/18"
            )
        if self.mode_seed is not None and (
            type(self.mode_seed) is not bytes or len(self.mode_seed) != 16
        ):
            raise ValueError("Observed native diagnostic-mode seed must be 16 bytes")
        for category, bus in self.targets:
            _unsigned(category, 0xFFFF)
            _unsigned(bus, 255)
        for key, value in (self.functions or {}).items():
            if len(key) != 3:
                raise ValueError("Function cache key must contain three native words")
            for item in key:
                _unsigned(item, 0xFFFF)
            _unsigned(value, 0xFFFFFFFF)

    def function(self, group: int, child: int = 0, leaf: int = 0) -> tuple[bool, int]:
        if self.functions is None:
            raise SessionError("Native ECU function cache was not supplied")
        for key, value in self.functions.items():
            if (
                key[0] == group
                and (not child or key[1] == child)
                and (not leaf or key[2] == leaf)
            ):
                return True, value if leaf else 0
        return False, 0


@dataclass(frozen=True)
class SelectedTarget:
    """A cache boundary: requests cannot be shared across different targets."""

    ecu: str
    category: int
    native_id: int
    bus_id: int
    database_sha256: str
    exception_ids: tuple[int, ...] = ()


@dataclass(frozen=True)
class SavedLogInput:
    number: int
    metadata: Mapping[str, object] = field(default_factory=dict)
    _metadata_json: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        _unsigned(self.number, 0xFFFFFFFF)
        pending: list[tuple[object, int]] = [(self.metadata, 0)]
        budget = 0
        count = 0
        while pending:
            value, depth = pending.pop()
            count += 1
            budget += 64
            if depth > 16 or count > 100000 or budget > 16 * 1024 * 1024:
                raise ValueError("Saved-log metadata exceeds local bounds")
            if type(value) is str:
                budget += 12 * len(value)
            elif type(value) is int:
                if value.bit_length() > 64:
                    raise ValueError("Saved-log metadata integer exceeds64 bits")
            elif value is None or type(value) is bool:
                pass
            elif type(value) is dict:
                if len(value) > 100000 or any(type(key) is not str for key in value):
                    raise ValueError("Saved-log metadata keys must be bounded strings")
                pending.extend(
                    (item, depth + 1) for pair in value.items() for item in pair
                )
            elif type(value) in (list, tuple):
                sequence = cast(list[object] | tuple[object, ...], value)
                if len(sequence) > 100000:
                    raise ValueError("Saved-log metadata sequence exceeds local bound")
                pending.extend((item, depth + 1) for item in sequence)
            else:
                raise TypeError("Saved-log metadata requires bounded JSON values")
        if budget > 16 * 1024 * 1024:
            raise ValueError("Saved-log metadata exceeds local byte bound")
        object.__setattr__(
            self,
            "_metadata_json",
            json.dumps(self.metadata, ensure_ascii=True, separators=(",", ":")),
        )


@dataclass(frozen=True)
class SelectedDidTarget:
    logical_id: int
    record: bytes
    category_record: bytes
    management_sha256: str
    exception_ids: tuple[int, ...]


@dataclass(frozen=True)
class SavedLogBinding:
    logical_id: int
    target: SelectedTarget
    record: bytes
    frame: SelectedFrame
    bcd: bool = False


@dataclass(frozen=True)
class SavedPidPlan:
    setter: SavedLogBinding
    components: tuple[SavedLogBinding, ...]


@dataclass(frozen=True)
class SavedRoutineBinding:
    logical_id: int
    target: SelectedTarget
    record: bytes
    command_frame: SelectedFrame
    status_frame: SelectedFrame | None = None
    bcd: bool = False


def select_comm_did_target(
    cache: MonitorSupportCache,
    logical_id: int,
    *,
    connections: Mapping[tuple[int, int], NativeCommunication] | None = None,
    targets: Sequence[tuple[int, int]] = (),
) -> SelectedDidTarget | None:
    """Native18 Common1A730 FIRST supported CommDid target candidate."""
    _unsigned(logical_id, 65535)
    if cache.source_build != 18:
        raise SessionError("Native12 CommDid target selector parity is unverified")
    if len(targets) > 100000:
        raise ValueError("Target list exceeds local bound")
    for category, bus in targets:
        _unsigned(category, 0xFFFFFFFF)
        _unsigned(bus, 65535)
    selected_targets = set(targets)
    cache.check_context()
    rows = cache.profile.comm_did_records(logical_id)
    if not rows:
        raise ToyotaCodecError("CommDid candidate group empty", 0xC0040101)
    for row in rows:
        cache.check_context()
        if selected_targets and (word(row, 2), row[20]) not in selected_targets:
            continue
        categories = cache.profile.category_records(word(row, 2))
        if not categories:
            raise ToyotaCodecError("CommDid category group empty", 0xC0040101)
        category = categories[0]
        if category[72] != 4:
            raise ToyotaCodecError("CommDid target category type invalid", 0xC0040102)
        reference = word(row, 8)
        supported = reference == 0
        if reference:
            try:
                supported = cache.get_comm_support_bit(
                    reference,
                    connections=connections,
                    temporary=False,
                    force=False,
                    with_value=False,
                ).supported
            except ToyotaCodecError:
                continue
        if supported:
            return SelectedDidTarget(
                logical_id,
                row,
                category,
                cache.profile.catalog.management.sha256,
                cache.profile.exception_ids,
            )
    return None


class _WorkflowSupportStream:
    def __init__(self, owner: ToyotaWorkflows, provider: SupportStream):
        self.owner, self.provider = owner, provider

    def send(self, call: SupportSend) -> int:
        self.owner._before_io()
        try:
            return self.provider.send(call)
        finally:
            self.owner._check()

    def receive(self, call: SupportReceive) -> tuple[int, bytes]:
        self.owner._before_io()
        try:
            return self.provider.receive(call)
        finally:
            self.owner._check()


def selected_saved_logs(items: Sequence[SavedLogInput]) -> tuple[SavedLogInput, ...]:
    """Native3D10 retains FIRST raw MultiData DWORD8 and its metadata."""
    found: set[int] = set()
    result = []
    for item in items:
        if not isinstance(item, SavedLogInput):
            raise TypeError("Saved logs require explicit raw log numbers and metadata")
        if item.number not in found:
            found.add(item.number)
            result.append(item)
    return tuple(result)


def parse_each_p5_reply(reply: bytes, *, requested_number: int) -> dict[str, object]:
    """EachP5 source18 helper1CD0 self-describing DID records (not stored FFD)."""
    _unsigned(requested_number, 255)
    if type(reply) is not bytes or len(reply) > 65535:
        raise ValueError("EachP5 reply must fit the native extended receive bound")
    records: list[dict[str, object]] = []
    result: dict[str, object] = {"code": None, "records": records, "status": "empty"}
    if len(reply) <= 6:
        return result
    result.update(
        code=int.from_bytes(reply[2:5], "big"), header_byte_5=reply[5], status="ok"
    )
    cursor = 6

    def partial(reason: str, start: int) -> dict[str, object]:
        result.update(
            status="partial", reason=reason, unparsed_tail=reply[start:].hex()
        )
        return result

    while cursor < len(reply):
        start = cursor
        if cursor + 2 > len(reply):
            return partial("record_header_truncated", cursor)
        number, count = reply[cursor : cursor + 2]
        kind = ffd_type(number)
        if not kind:
            return partial("native_ffd_type_unknown", cursor)
        cursor += 2
        items: list[dict[str, object]] = []
        record: dict[str, object] = {
            "number": number,
            "kind": kind,
            "index": ((number - 127 + 128) & 255) - 128,
            "data_ids": items,
            "complete": False,
        }
        records.append(record)
        if not count and requested_number == 255:
            return partial("zero_count_for_all_records_request", start)
        seen = set()
        consumed = 0
        while consumed < count or not count and cursor < len(reply):
            item_start = cursor
            if cursor + 3 > len(reply):
                return partial("data_id_header_truncated", cursor)
            did = int.from_bytes(reply[cursor : cursor + 2], "big")
            length = reply[cursor + 2]
            cursor += 3
            if cursor + length > len(reply):
                return partial("data_id_value_truncated", item_start)
            data = reply[cursor : cursor + length]
            cursor += length
            consumed += 1
            # Common201A0 CCmdDataIdData.Set rejects DID0/length0 and
            # SearchDataId retains FIRST duplicate in this record.
            if did and length and did not in seen:
                seen.add(did)
                items.append({"did": did, "data": data.hex()})
        record["complete"] = True
    return result


def parse_predictive_p5_reply(
    reply: bytes, *, requested_number: int
) -> dict[str, object]:
    """Each4C50 predictive six-byte group header and self-describing DIDs."""
    _unsigned(requested_number, 255)
    if type(reply) is not bytes or len(reply) > 65535:
        raise ValueError("PredictiveP5 reply exceeds native ushort capacity")
    records: list[dict[str, object]] = []
    report: dict[str, object] = {"status": "ok", "records": records}
    cursor = 2

    def partial(reason: str, start: int) -> dict[str, object]:
        report.update(
            status="partial", reason=reason, unparsed_tail=reply[start:].hex()
        )
        return report

    while cursor < len(reply):
        if cursor + 6 > len(reply):
            return partial("predictive_header_truncated", cursor)
        number, ignored_header = reply[cursor], reply[cursor + 4]
        kind = ffd_type(number, extended=True)
        if not kind:
            return partial("native_ffd_type_unknown", cursor)
        code = int.from_bytes(reply[cursor + 1 : cursor + 4], "big")
        count = reply[cursor + 5]
        items: list[dict[str, object]] = []
        records.append(
            {
                "number": number,
                "header_byte_6": ignored_header,
                "code": code,
                "kind": kind,
                "index": ((number + 1) & 255) - 128,
                "data_ids": items,
            }
        )
        cursor += 6
        if not count and requested_number == 255:
            return partial("zero_count_for_all_records_request", cursor)
        consumed = 0
        seen: set[int] = set()
        while consumed < count or not count and cursor < len(reply):
            start = cursor
            if cursor + 3 > len(reply):
                return partial("data_id_header_truncated", cursor)
            did = int.from_bytes(reply[cursor : cursor + 2], "big")
            size = reply[cursor + 2]
            cursor += 3
            if cursor + size > len(reply):
                return partial("data_id_value_truncated", start)
            data = reply[cursor : cursor + size]
            cursor += size
            consumed += 1
            if did and size and did not in seen:
                seen.add(did)
                items.append({"did": did, "data": data.hex()})
    return report


def parse_operation_p5_reply(
    reply: bytes, *, source_version: int = 18
) -> dict[str, object]:
    """OperationP5 1B10/2030: count/DID/length blocks, DID0501 WORD value."""
    if type(source_version) is not int or source_version not in (12, 18):
        raise ValueError("OperationP5 requires original source12 or18")
    if type(reply) is not bytes or len(reply) > 4096:
        raise ValueError("OperationP5 reply exceeds its native extended capacity")
    values: list[int] = []
    ignored: list[int] = []
    report: dict[str, object] = {
        "status": "ok",
        "trip_time_words": values,
        "ignored_data_ids": ignored,
    }
    cursor = 6
    if len(reply) <= cursor:
        return report

    def partial(reason: str, start: int) -> dict[str, object]:
        report.update(
            status="partial", reason=reason, unparsed_tail=reply[start:].hex()
        )
        return report

    while cursor < len(reply):
        count = reply[cursor]
        cursor += 1
        if not count:
            if source_version == 12:
                # Original12 1B10 has no zero-count rescan; its empty list exits
                # successfully, retaining values from preceding blocks only.
                result_tail = reply[cursor:]
                if result_tail:
                    report["ignored_tail"] = result_tail.hex()
                return report
            # Native2150 always rescans from fixed offset7, including when a
            # later block carries zero. Preserve that count, not "all remaining".
            scan = 7
            while scan + 3 <= len(reply):
                scan += 3 + reply[scan + 2]
                if scan > len(reply):
                    break
                count += 1
            if not count:
                return partial("native_zero_count_has_no_complete_items", cursor)
        seen: set[int] = set()
        consumed = 0
        while consumed < count:
            start = cursor
            if cursor + 3 > len(reply):
                return partial("data_id_header_truncated", cursor)
            did = int.from_bytes(reply[cursor : cursor + 2], "big")
            size = reply[cursor + 2]
            cursor += 3
            if cursor + size > len(reply):
                return partial("data_id_value_truncated", start)
            data = reply[cursor : cursor + size]
            cursor += size
            consumed += 1
            if did and size and did not in seen:
                seen.add(did)
                if did == 0x501 and size >= 2:
                    values.append(int.from_bytes(data[:2], "big"))
                else:
                    ignored.append(did)
    return report


def analyze_each_p5_reply(
    state: object,
    reply: bytes,
    *,
    requested_number: int,
    create_diagnostics: bool = True,
) -> dict[str, object]:
    """Each1CD0 parsed DID records into the concrete Common freeze state.

    Earlier valid records and DID entries remain observable after a truncated
    later entry, as in the original mutable native lists.
    """
    from scripts.freeze_p5 import P5DataIdObservation, P5FreezeState, P5Value

    if not isinstance(state, P5FreezeState) or state.subaru:
        raise TypeError("Normal EachP5 requires its concrete non-Subaru freeze state")
    # Each1CD0 resolves its timestamp/odometer PID groups before analysis.
    state.set_timestamp_odometer_pid_ids()
    parsed = parse_each_p5_reply(reply, requested_number=requested_number)
    code = parsed["code"]
    if type(code) is not int:
        return parsed
    if create_diagnostics:
        state.add_diagnostic(code)
    elif state.diagnostic(code) is None:
        return parsed
    records = cast(list[dict[str, Any]], parsed["records"])
    for record in records:
        if create_diagnostics:
            state.set_ffd_exist_flag(code, record["number"])
        items = tuple(
            P5DataIdObservation(item["did"], bytes.fromhex(item["data"]))
            for item in record["data_ids"]
        )
        multi = P5Value(0, record["index"], record["kind"])
        for item in items:
            state.analyze_single_data_id(code, item.did, multi, item.data, items)
    return parsed


def analyze_predictive_p5_replies(
    state: P5FreezeState, captures: tuple[tuple[bytes, int], ...]
) -> dict[str, object]:
    """Standalone Each4C50 predictive temporary diagnostics and native merge.

    This is the D0 format, distinct from GetDiag's CF/3180 format.
    """
    from scripts.freeze_p5 import P5DataIdObservation, P5FreezeState, P5Value

    if not isinstance(state, P5FreezeState) or state.subaru:
        raise TypeError("Predictive EachP5 requires concrete normal Common state")
    if not isinstance(captures, tuple) or len(captures) > 65535:
        raise TypeError("Bounded predictive capture tuple required")
    if sum(len(reply) for reply, _number in captures) > 16 * 1024 * 1024:
        raise SessionError("Predictive capture byte budget exhausted")
    temporary = P5FreezeState(
        state.profile, source_build=state.source_build, cache=state.cache
    )
    temporary.set_timestamp_odometer_pid_ids()
    reports: list[dict[str, object]] = []
    all_records: dict[int, bool] = {}
    result: dict[str, object] = {
        "status": "ok",
        "parsed": reports,
        "native_field_7c": all_records,
    }
    for reply, requested_number in captures:
        state._check()
        parsed = parse_predictive_p5_reply(reply, requested_number=requested_number)
        reports.append(parsed)
        if parsed["status"] == "partial":
            result["status"] = "partial"
        for record in cast(list[dict[str, Any]], parsed["records"]):
            code = record["code"]
            diagnostic = temporary.add_diagnostic(code, diag_type=8)
            if record["number"] < 16:
                temporary.set_ffd_exist_flag(code, record["number"], extended=True)
            if diagnostic is None:
                continue
            all_records[code] = requested_number == 255
            diagnostic.stored_all = requested_number == 255
            items = tuple(
                P5DataIdObservation(item["did"], bytes.fromhex(item["data"]))
                for item in record["data_ids"]
            )
            multi = P5Value(0, record["index"], record["kind"])
            for item in items:
                temporary.analyze_single_data_id(
                    code, item.did, multi, item.data, items
                )
    merge_p5_diagnostics(state, temporary)
    return result


def merge_p5_diagnostics(state: P5FreezeState, temporary: P5FreezeState) -> None:
    """Each4C50 native temporary-list merge, including original index defect."""
    from scripts.freeze_p5 import P5FreezeState

    if not isinstance(state, P5FreezeState) or not isinstance(temporary, P5FreezeState):
        raise TypeError("Concrete Common freeze states required")
    if (
        state.subaru
        or temporary.subaru
        or state.cache is not temporary.cache
        or state.profile is not temporary.profile
        or state.source_build != temporary.source_build
    ):
        raise SessionError("Predictive merge selected source differs")
    # All parsing and sorting precedes merge, so a metadata failure leaves the
    # caller's diagnostic values unchanged, matching the native temporary list.
    for diagnostic in temporary.diagnostics:
        temporary.sort_multi_data_by_timestamp(diagnostic)
        existing = state.diagnostic(diagnostic.code)
        if existing is None:
            maximum = state.diagnostic_limit
            if len(state.diagnostics) >= maximum:
                raise SessionError("Merged predictive diagnostic bound exhausted")
            state.diagnostics.append(copy.deepcopy(diagnostic))
            continue
        existing.diag_type |= diagnostic.diag_type
        existing.status |= diagnostic.status
        existing.existence_flags |= diagnostic.existence_flags
        existing.extended_numbers[:] = diagnostic.extended_numbers
        existing.stored_all = diagnostic.stored_all
        if existing.timestamps[0] is None or not existing.timestamps[0].values:
            existing.timestamps[:] = copy.deepcopy(diagnostic.timestamps)
        else:
            count = len(temporary._values(diagnostic.timestamps[0]))
            for index in range(count):
                for target, source in zip(
                    existing.timestamps, diagnostic.timestamps, strict=True
                ):
                    if source is not None and index < len(source.values):
                        if target is None:
                            raise SessionError(
                                "Native predictive paired timestamp target absent"
                            )
                        target.values.append(copy.deepcopy(source.values[index]))
        if existing.odometer is None or not existing.odometer.values:
            existing.odometer = copy.deepcopy(diagnostic.odometer)
        elif diagnostic.odometer is not None:
            existing.odometer.values.extend(copy.deepcopy(diagnostic.odometer.values))
        for source_index, signal in enumerate(diagnostic.signals):
            target_index = state.search_pid(signal.pid, existing.signals)
            if target_index < 0:
                existing.signals.append(copy.deepcopy(signal))
                continue
            # Original4C50 accidentally bounds this loop by the SOURCE signal
            # at the DESTINATION index; do not silently repair its semantics.
            if target_index >= len(diagnostic.signals):
                raise SessionError(
                    "Native predictive source PID index is outside its list"
                )
            count = len(diagnostic.signals[target_index].values)
            for value_index in range(count):
                state._check()
                if value_index >= len(diagnostic.signals[source_index].values):
                    raise SessionError(
                        "Native predictive source value index is outside its list"
                    )
                existing.signals[target_index].values.append(
                    copy.deepcopy(signal.values[value_index])
                )


def selected_freeze_metadata(
    profile: VehicleProfile, freeze: bytes, lsb: SignalLSB
) -> MonitorSignalMetadata:
    """Common224D0 selected Freeze metadata; concrete LSB runs at native phase."""
    if not isinstance(lsb, SignalLSB) or lsb.cache.profile is not profile:
        raise SessionError("Freeze metadata and LSB must share one selected profile")
    if type(freeze) is not bytes or len(freeze) != 84:
        raise ValueError("Native Freeze metadata requires84 bytes")
    # Common224D0 requires FIRST PhyData/Unit and an optional group-zero PatDisp.
    for slot in (13, 15, 14):
        if slot not in profile.database.sections:
            raise ToyotaCodecError("Freeze metadata resource absent", 0xA0030107)
    physical = next(
        (row for row in profile.records(13) if word(row, 12) == word(freeze, 60)),
        None,
    )
    unit = (
        None
        if physical is None
        else next(
            (row for row in profile.records(15) if word(row, 4) == word(physical, 14)),
            None,
        )
    )
    if physical is None or unit is None:
        raise ToyotaCodecError("Freeze physical/unit group empty", 0xC0040101)
    pattern_key = word(freeze, 70)
    patterns = [
        row
        for row in profile.records(14)
        if word(row, 4 if len(row) == 20 else 12) == pattern_key
    ]
    if pattern_key and not patterns:
        raise ToyotaCodecError("Freeze pattern group empty", 0xC0040101)
    signal = word(freeze, 56)
    begin, end = struct.unpack_from("<HH", freeze, 62)

    def dword(row: bytes, offset: int) -> int:
        return struct.unpack_from("<I", row, offset)[0]

    language = profile.catalog.language
    multiplier, divisor, offset = struct.unpack_from("<III", physical)
    lower, upper = struct.unpack_from("<II", freeze, 32)
    # ChangeSignalLSB1F0E0 writes runtime74; SetFrzFrmDat does not overwrite it.
    multiplier, divisor, lower = lsb.p4(
        signal,
        exponent=physical[21],
        width=end - begin + 1,
        multiplier=multiplier,
        divisor=divisor,
        threshold=lower,
    ).values
    return MonitorSignalMetadata(
        signal,
        0,
        begin,
        end,
        language.resolve(dword(freeze, 48)),
        freeze[:24].split(b"\0", 1)[0],
        language.resolve(dword(unit, 0)),
        freeze[76],
        word(unit, 6),
        physical[20],
        multiplier,
        divisor,
        offset,
        physical[21],
        dword(freeze, 24),
        dword(freeze, 28),
        tuple(
            (
                pattern_key,
                language.resolve(dword(row, 0)),
                word(row, 10) if len(row) == 20 else dword(row, 4),
                0,
            )
            for row in patterns
        ),
        (dword(freeze, 52), lower, upper),
    )


class ToyotaWorkflows:
    """Profile producer and bounded executor; never selects an arbitrary PDU."""

    @classmethod
    def from_communication(
        cls,
        communication: NativeCommunication,
        *,
        observations: WorkflowObservations,
        cancelled: Callable[[], bool] = lambda: False,
        limits: Limits | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> ToyotaWorkflows:
        """Bind actual native selected-frame runtime, not a payload-only fake."""
        from scripts.native_communication import CommunicationError, NativeCommunication

        if not isinstance(communication, NativeCommunication):
            raise TypeError("An actual selected NativeCommunication is required")
        if not isinstance(communication.profile, VehicleProfile):
            raise TypeError("Toyota workflows require a selected VehicleProfile")
        if (
            observations.source_version != communication.source_build
            or observations.bus_id != communication.bus_id
        ):
            raise ValueError("Workflow and communication source/bus contexts differ")

        def raw(_ecu: str, _request: bytes) -> bytes:
            raise SessionError("Raw transaction lacks selected frame metadata")

        def send(ecu: str, call: NativeFrameSend) -> int:
            if ecu != communication.ecu:
                raise ValueError("Native send target differs")
            return communication.send_native(call)

        workflow = cls.from_profile(
            communication.profile,
            raw,
            ecu=communication.ecu,
            observations=observations,
            native_send=send,
            cancelled=cancelled,
            limits=limits or communication.limits,
            clock=communication.clock,
            sleep=sleep,
        )
        workflow._communication = communication
        workflow._communication_calls = communication.calls
        workflow._communication_cache_calls = communication.cache.calls
        workflow._support_cache = communication.cache

        def transaction(ecu: str, spec: CommandSpec, request: bytes) -> bytes:
            workflow._check()
            if workflow._remaining <= 0:
                raise SessionError("Selected Toyota workflow exchange budget exhausted")
            if ecu != communication.ecu or spec.selected is None:
                raise SessionError(
                    "Native transaction requires its actual selected target/frame"
                )
            try:
                if spec.check == "raw":
                    result = communication.execute_raw(
                        spec.selected, request, capacity=spec.receive_capacity or 255
                    )
                    if result.status:
                        raise CommunicationError(result)
                    return result.response
                return communication.cache.transaction(
                    spec.selected,
                    request,
                    cached=False,
                    extended=spec.extended,
                    capacity=spec.receive_capacity,
                )
            finally:
                workflow._check()

        workflow.session.native_transaction = transaction
        workflow.session.native_communication = communication
        return workflow

    @classmethod
    def from_profile(
        cls,
        profile: VehicleProfile,
        exchange: Exchange,
        *,
        ecu: str,
        observations: WorkflowObservations,
        native_send: NativeSend | None = None,
        native_get_mode: Callable[[str], bytes] | None = None,
        native_set_mode: Callable[[str, bytes], None] | None = None,
        native_cleanup_set_mode: Callable[[str, bytes], None] | None = None,
        support_exchange: SupportTransaction | None = None,
        support_stream: SupportStream | None = None,
        cancelled: Callable[[], bool] = lambda: False,
        limits: Limits | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> ToyotaWorkflows:
        return cls(
            profile,
            exchange,
            ecu=ecu,
            observations=observations,
            native_send=native_send,
            native_get_mode=native_get_mode,
            native_set_mode=native_set_mode,
            native_cleanup_set_mode=native_cleanup_set_mode,
            support_exchange=support_exchange,
            support_stream=support_stream,
            cancelled=cancelled,
            limits=limits,
            clock=clock,
            sleep=sleep,
        )

    def __init__(
        self,
        profile: VehicleProfile,
        exchange: Exchange,
        *,
        ecu: str,
        observations: WorkflowObservations,
        native_send: NativeSend | None = None,
        native_get_mode: Callable[[str], bytes] | None = None,
        native_set_mode: Callable[[str, bytes], None] | None = None,
        native_cleanup_set_mode: Callable[[str, bytes], None] | None = None,
        support_exchange: SupportTransaction | None = None,
        support_stream: SupportStream | None = None,
        cancelled: Callable[[], bool] = lambda: False,
        limits: Limits | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        if not isinstance(profile, VehicleProfile) or not ecu:
            raise ValueError("A selected vehicle profile and ECU identity are required")
        if not isinstance(observations, WorkflowObservations):
            raise TypeError("Explicit native workflow observations are required")
        self.profile, self.observations = profile, observations
        self.target = SelectedTarget(
            ecu,
            profile.category,
            observations.native_id,
            observations.bus_id,
            profile.database.sha256,
            profile.exception_ids,
        )
        self.exchange, self.native_send = exchange, native_send
        self.support_exchange, self.support_stream = support_exchange, support_stream
        self._support_cache: MonitorSupportCache | None = None
        self._communication: NativeCommunication | None = None
        self._communication_calls = 0
        self._communication_cache_calls = 0
        self.cancelled, self.clock, self.sleep = cancelled, clock, sleep
        self.limits = limits or Limits()

        def get_mode(selected_ecu: str) -> bytes:
            self._before_io()
            assert native_get_mode is not None
            try:
                return native_get_mode(selected_ecu)
            finally:
                self._check()

        def set_mode(selected_ecu: str, mode: bytes) -> None:
            self._before_io()
            assert native_set_mode is not None
            try:
                return native_set_mode(selected_ecu, mode)
            finally:
                self._check()

        self.session = ToyotaSession(
            self._exchange,
            ecu,
            {},
            limits=self.limits,
            cancelled=cancelled,
            clock=clock,
            native_send=self._native_send if native_send is not None else None,
            native_get_mode=get_mode if native_get_mode is not None else None,
            native_set_mode=set_mode if native_set_mode is not None else None,
            native_cleanup_set_mode=native_cleanup_set_mode or native_set_mode,
        )
        self._deadline, self._remaining = 0.0, 0
        self.native_output: dict[str, object] = {}

    def _begin(self, *, source12_verified: bool = False) -> None:
        if self.observations.source_version == 12 and not source12_verified:
            raise SessionError(
                "This workflow's version12 source parity is not yet verified"
            )
        self.native_output = {}
        self._deadline, self._remaining = (
            self.clock() + self.limits.seconds,
            self.limits.exchanges,
        )
        if self._communication is not None:
            self._communication.begin_operation(limits=self.limits)
            self._communication_calls = 0
            self._communication_cache_calls = 0
        self._check()
        if self._support_cache is not None:
            self._support_cache.begin_operation(limits=self.limits)

    def _check(self) -> None:
        if self._communication is not None:
            communication = self._communication
            self._remaining -= max(
                communication.calls - self._communication_calls,
                communication.cache.calls - self._communication_cache_calls,
            )
            self._communication_calls = communication.calls
            self._communication_cache_calls = communication.cache.calls
            if self._remaining < 0:
                raise SessionError("Selected Toyota workflow exchange budget exhausted")
            communication.limits = replace(
                communication.limits,
                exchanges=max(1, communication.calls + max(0, self._remaining)),
            )
            communication.cache.limits = replace(
                communication.cache.limits,
                exchanges=max(1, communication.cache.calls + max(0, self._remaining)),
            )
        if self.cancelled():
            raise Cancelled("Selected Toyota workflow cancelled")
        if self.clock() >= self._deadline:
            raise SessionError("Selected Toyota workflow deadline exceeded")

    def _before_io(self) -> None:
        self._check()
        if self._remaining <= 0:
            raise SessionError("Selected Toyota workflow exchange budget exhausted")
        self._remaining -= 1
        if self._communication is not None:
            self._check()

    def _support_query(self, query: SupportQuery) -> bytes:
        self._before_io()
        if self.support_exchange is None:
            raise SessionError("Typed support transaction provider was not supplied")
        try:
            return self.support_exchange(query)
        finally:
            self._check()

    def _support(self) -> MonitorSupportCache:
        if self._support_cache is None:
            self._support_cache = MonitorSupportCache(
                self.profile,
                self._support_query,
                self.target.ecu,
                limits=self.limits,
                cancelled=self.cancelled,
                clock=self.clock,
                bus_id=self.observations.bus_id,
                source_build=self.observations.source_version,
                stream=_WorkflowSupportStream(self, self.support_stream)
                if self.support_stream is not None
                else None,
            )
        return self._support_cache

    def _exchange(self, ecu: str, request: bytes) -> bytes:
        self._before_io()
        try:
            return self.exchange(ecu, request)
        finally:
            self._check()

    def _native_send(self, ecu: str, call: NativeFrameSend) -> int:
        self._before_io()
        if self.native_send is None:
            raise SessionError("Recorded native send provider was not supplied")
        try:
            return self.native_send(ecu, call)
        finally:
            self._check()

    def _delay(self, milliseconds: int) -> None:
        end = self.clock() + milliseconds / 1000
        while self.clock() < end:
            self._check()
            self.sleep(min(0.01, end - self.clock()))
        self._check()

    def _frames(self, function: int) -> tuple[SelectedFrame, ...]:
        rows = correspondence_rows(
            self.profile.catalog.management, 18, self.profile.exception_ids
        )
        if not any(
            word(row, 0) == self.profile.category and word(row, 2) == function
            for row in rows
        ):
            raise ToyotaCodecError(
                "Selected workflow function has no frames", 0xC0040101
            )
        return self.profile.frame_records(function)

    def _register(self, function: int) -> tuple[str, ...]:
        names = []
        for index, selected in enumerate(self._frames(function)):
            name = f"{function:04x}:{index}"
            self.session.commands[name] = CommandSpec(
                selected.frame, provenance=selected.provenance, selected=selected
            )
            names.append(name)
        return tuple(names)

    def _send_function(self, function: int) -> list[bytes]:
        return self.session.sequence(self._register(function))

    def _address_function(self, function: int, *, p5: bool = False) -> list[bytes]:
        seed = self.observations.mode_seed
        if seed is None:
            raise SessionError("Native diagnostic-mode seed was not observed")
        override_category: list[int] = []
        frame_failure: list[ToyotaCodecError] = []

        def mode_factory() -> bytes:
            selected = self.profile.carb_mode_info(self.observations.bus_id, p5=p5)
            override_category.append(selected.key1)
            return selected.replace_in(seed)

        try:
            with self.session.diagnostic_scope(mode_factory):
                categories = correspondence_rows(
                    self.profile.catalog.management, 16, self.profile.exception_ids
                )
                category = next(
                    row for row in categories if word(row, 68) == override_category[0]
                )
                alternate = replace(self.profile, category_record=category)
                # Frame selection follows mode installation, including failures.
                functions = correspondence_rows(
                    self.profile.catalog.management, 18, self.profile.exception_ids
                )
                if not any(
                    word(row, 0) == alternate.category and word(row, 2) == function
                    for row in functions
                ):
                    raise ToyotaCodecError(
                        "Selected alternate function has no frames", 0xC0040101
                    )
                names = []
                for index, selected in enumerate(alternate.frame_records(function)):
                    name = f"carb:{alternate.category:04x}:{function:04x}:{index}"
                    self.session.commands[name] = CommandSpec(
                        selected.frame,
                        provenance=selected.provenance,
                        selected=selected,
                    )
                    names.append(name)
                try:
                    return self.session.sequence(names)
                except ToyotaCodecError as error:
                    frame_failure.append(error)
                    raise
        except ToyotaCodecError as error:
            # DifferentAddress has its own ordinary-address timeout fallback; FunctionAddress does not.
            if (
                not p5
                and frame_failure
                and error is frame_failure[0]
                and error.code == 0x91010009
            ):
                return self._send_function(function)
            raise

    def clear_dtc_p4(self) -> dict[str, object]:
        """P4 Execute1010 selects actual detail57 and native fallback102 paths."""
        self._begin(source12_verified=True)
        timers = self.profile.timer_records(1)
        if not timers:
            raise ToyotaCodecError("Selected P4 clear timer is absent", 0xC0040101)
        if self.observations.source_version == 12:
            # V12 Execute1135..1199 has ordinary function1 only; no address/fallback tree.
            self._send_function(1)
            self._delay(struct.unpack_from("<I", timers[0])[0])
            return {"native_status": 0, "native_clear_flag": 1}
        detail, feature = False, 0
        if self.observations.bus_id in (0x12, 0x22):
            present, value = self.observations.function(0x1E, 0x15, 0x14)
            feature = value if present else 0
            detail = any(
                word(row, 8) == 0x57 for row in self.profile.ecu_function_details(1)
            )
            if not detail:
                detail = any(
                    word(row, 8) == 0x57
                    for row in self.profile.ecu_function_details(0x10)
                )
        fallback_statuses = {
            0x91010009,
            0x90020321,
            0x90020323,
            0xA0040201,
            0xC0040001,
            0xA0040202,
            0x90020327,
            0x91020320,
            0x91020310,
            0x91020322,
        }
        try:
            self._address_function(1) if detail else self._send_function(1)
        except ToyotaCodecError as original:
            eligible = (
                original.code == 0x91010009
                if feature == 1
                else original.code in fallback_statuses
            )
            if not eligible:
                raise
            try:
                if feature != 1 and self.observations.bus_id == 0x22:
                    self._address_function(0x102, p5=True)
                else:
                    self._send_function(0x102)
            except ToyotaCodecError as fallback:
                if fallback.code == 0xC0040101:
                    raise original from fallback
                raise
        self._delay(struct.unpack_from("<I", timers[0])[0])
        return {"native_status": 0, "native_clear_flag": 1}

    def clear_dtc(self) -> dict[str, object]:
        """DelDiagCode Execute1006: timer1, function1, status mapping, nativeflag."""
        self._begin(source12_verified=True)
        timers = self.profile.timer_records(1)
        if not timers:
            raise ToyotaCodecError("Selected clear-DTC timer1 is absent", 0xC0040101)
        try:
            self._send_function(1)
        except ToyotaCodecError as error:
            if error.code == 0x91010009:
                raise ToyotaCodecError(
                    "Native clear-DTC timeout", 0x90040501
                ) from error
            raise
        self._delay(struct.unpack_from("<I", timers[0])[0])
        return {"native_status": 0, "native_clear_flag": 1}

    def clear_dtc_mazda(self) -> dict[str, object]:
        """Mazda1010: fixed DB112(394,F2), each row's settings, send-only ABI."""
        self._begin(source12_verified=True)
        management = self.profile.catalog.management
        rows = [
            row
            for row in correspondence_rows(management, 18, self.profile.exception_ids)
            if word(row, 0) == 0x394 and word(row, 2) == 0xF2
        ]
        if not rows:
            raise ToyotaCodecError("Mazda fixed394/F2 frames are absent", 0xC0040101)
        variable = management.sections.get(0)
        if variable is None:
            raise ToyotaCodecError(
                "Selected frame variable table is absent", 0xA0030107
            )
        variables = VariableTable(variable.payload, variable.count)
        frames = management.sections.get(17)
        if frames is None:
            raise ToyotaCodecError("Selected communication table is absent", 0xA0030107)
        settings = correspondence_rows(management, 29, self.profile.exception_ids)
        statuses = []
        for row in rows:
            chosen = [item for item in settings if word(item, 10) == word(row, 4)]
            if len(chosen) != 1:
                raise ToyotaCodecError(
                    "Mazda settings require exactly one row", 0xC0040102
                )
            communication = [
                item for item in frames.rows(8) if word(item, 0) == word(row, 6)
            ]
            if len(communication) != 1:
                raise ToyotaCodecError(
                    "Mazda communication frame is ambiguous", 0xC0040102
                )
            frame = CommandFrame.from_record(communication[0], variables)
            statuses.extend(
                self.session.native_frame_sends(
                    [
                        NativeFrameSend(
                            "SendIntNoInit",
                            0x394,
                            frame.request,
                            struct.unpack_from("<I", chosen[0])[0],
                            50,
                            0,
                            1,
                        )
                    ],
                    ignore_status=True,
                )
            )
        return {"native_status": 0, "send_statuses": statuses}

    def _masked_function(self, function: int) -> None:
        frames = self._frames(function)
        replies = self._send_function(function)
        first, reply = frames[0].frame, replies[0]
        mask, check = first.receive_mask, first.receive_check
        if len(mask) > len(reply):
            raise ToyotaCodecError("Reset first reply lacks mask bytes", 0xA0040202)
        if len(mask) > len(check):
            raise ToyotaCodecError(
                "Reset first check list is shorter than mask", 0xC0040102
            )
        if any((reply[i] & byte) != (check[i] & byte) for i, byte in enumerate(mask)):
            raise ToyotaCodecError("Reset first reply mask mismatch", 0xA0040201)

    def _reset(self) -> None:
        # CEcuReset740B0: second function is conditional on first success.
        self._masked_function(0xC5)
        self._masked_function(0x67)

    def _psa_feature(self, feature: int) -> bool:
        present, _ = self.observations.function(1, feature)
        if not present:
            present, _ = self.observations.function(0x10, feature)
        return present

    def clear_dtc_psa(self) -> dict[str, object]:
        """PSA1010: observed reset flags, C6/C7 masks, timer1 and clear1."""
        self._begin(source12_verified=True)
        if self._psa_feature(0x40):
            self._reset()
        if self._psa_feature(0x44):
            self._masked_function(0xC6)
            self._masked_function(0xC7)
        timers = self.profile.timer_records(1)
        if not timers:
            raise ToyotaCodecError("Selected PSA clear timer is absent", 0xC0040101)
        try:
            self._send_function(1)
        except ToyotaCodecError as error:
            if error.code == 0x91010009:
                raise ToyotaCodecError(
                    "Native PSA clear-DTC timeout", 0x90040501
                ) from error
            raise
        self._delay(struct.unpack_from("<I", timers[0])[0])
        if self._psa_feature(0x41):
            self._reset()
        return {"native_status": 0, "native_clear_flag": 1}

    def clear_dtc_vgrs(self) -> dict[str, object]:
        """Vgrs1010 checks C1555 first and conditionally sends function2."""
        self._begin(source12_verified=True)
        names = self._register(0x0A)
        if len(names) != 1:
            raise ToyotaCodecError("VGRS DTC read requires one frame", 0xC0040102)
        codes = self.session.dtcs(
            names[0], retries=self._frames(0x0A)[0].settings_record[14]
        )
        timers = self.profile.timer_records(1)
        if not timers:
            raise ToyotaCodecError("Selected VGRS timer is absent", 0xC0040101)
        self._send_function(1)
        self._delay(struct.unpack_from("<I", timers[0])[0])
        self.native_output["native_clear_flag"] = 1
        if 0x5555 in codes:
            self._send_function(2)
        result: dict[str, object] = {
            "native_status": 0,
            "native_clear_flag": 1,
            "c1555_observed": 0x5555 in codes,
        }
        # Native1160 logs the cardinality warning and still continues.
        if len(timers) >= 2:
            result["native_warnings"] = [0xC0040102]
        return result

    def _saved_context(
        self,
        contexts: Mapping[tuple[int, int], ToyotaWorkflows],
        category: int,
        bus: int,
    ) -> ToyotaWorkflows:
        context = contexts.get((category, bus))
        if (
            not isinstance(context, ToyotaWorkflows)
            or context.profile.category != category
            or context.observations.bus_id != bus
        ):
            raise SessionError("Saved-log candidate lacks its selected target context")
        if (
            context.profile.catalog.management.sha256
            != self.profile.catalog.management.sha256
            or context.profile.exception_ids != self.profile.exception_ids
            or context.observations.source_version != self.observations.source_version
            or getattr(context.profile, "vehicle_name_key", None)
            != getattr(self.profile, "vehicle_name_key", None)
        ):
            raise SessionError("Saved-log candidate source/exception context differs")
        return context

    def selected_absolute_pid_plan(
        self, contexts: Mapping[tuple[int, int], ToyotaWorkflows], *, begin: bool = True
    ) -> SavedPidPlan | None:
        """Absolute2940 candidate preflight, bound to every actual target frame."""
        from scripts.database_resources import DdrEcuContext, select_comm_pid_target

        if type(begin) is not bool:
            raise TypeError("Saved-log phase control must be boolean")
        if begin:
            self._begin()
        else:
            self._check()
        if self.profile.category != 0xD4 or self.observations.bus_id != 0x12:
            raise SessionError(
                "Native saved PID cache requires selected categoryD4/bus12"
            )
        for context in contexts.values():
            if not isinstance(context, ToyotaWorkflows):
                raise TypeError("Saved-log contexts must be selected ToyotaWorkflows")
            if context is not self and context._communication is not None:
                context._communication.begin_operation(limits=context.limits)
        connections = {
            key: context._communication
            for key, context in contexts.items()
            if context._communication is not None
        }
        cache = self._support()
        cache.invalidate_a8(2)
        did = select_comm_did_target(
            cache, 2, connections=connections, targets=self.observations.targets
        )
        if did is None:
            return None
        setter_context = self._saved_context(
            contexts, word(did.record, 2), did.record[20]
        )
        if setter_context.profile.category_record != did.category_record:
            raise SessionError("Saved-log setter category record differs")
        frames = setter_context._frames(0x9D)
        if len(frames) != 1:
            raise ToyotaCodecError(
                "Saved-log setter requires exactly one frame", 0xC0040102
            )
        setter = SavedLogBinding(2, setter_context.target, did.record, frames[0])
        cache.invalidate_a8(1)
        targets = tuple(
            DdrEcuContext(category, bus) for category, bus in self.observations.targets
        )
        components = []
        for logical_id in range(0x8F, 0x9B):
            self._check()
            selected = select_comm_pid_target(
                cache, logical_id, connections=connections, ecu_specific=targets
            )
            if selected is None:
                return None
            context = self._saved_context(
                contexts, word(selected.record, 18), selected.record[38]
            )
            if context.profile.category_record != selected.category_record:
                raise SessionError("Saved-log PID category record differs")
            kind = context.profile.category_record[72]
            frames = context._frames(0xCA if kind in (0x14, 0x15, 0x34) else 0x6B)
            if len(frames) != 1:
                raise ToyotaCodecError(
                    "Saved-log PID requires exactly one frame", 0xC0040102
                )
            components.append(
                SavedLogBinding(
                    logical_id,
                    context.target,
                    selected.record,
                    frames[0],
                    0x91 <= logical_id <= 0x96,
                )
            )
        return SavedPidPlan(setter, tuple(components))

    @contextmanager
    def _saved_no_init(self, context: ToyotaWorkflows) -> Iterator[None]:
        with self._saved_operation(context, no_init=True):
            yield

    def _saved_routine_names(self, binding: SavedRoutineBinding) -> tuple[str, str]:
        names = ("absolute-routine-command", "absolute-routine-status")
        for name, selected in zip(
            names, (binding.command_frame, binding.status_frame), strict=True
        ):
            if selected is None:
                continue
            self.session.commands[name] = CommandSpec(
                selected.frame,
                provenance=selected.provenance,
                selected=selected,
                extended=True,
            )
        return names

    def selected_absolute_routine_plan(
        self, contexts: Mapping[tuple[int, int], ToyotaWorkflows], *, begin: bool = True
    ) -> tuple[SavedRoutineBinding, ...] | None:
        """Common6B710 candidates with actual CC probes; Abs359C no-init cache."""
        if type(begin) is not bool:
            raise TypeError("Saved-log phase control must be boolean")
        if begin:
            self._begin()
        else:
            self._check()
        if self.profile.category_record[72] != 0x14:
            raise ToyotaCodecError("Saved routine category type invalid", 0xC0040001)
        for context in contexts.values():
            if not isinstance(context, ToyotaWorkflows):
                raise TypeError("Saved-log contexts must be selected ToyotaWorkflows")
            if context is not self and context._communication is not None:
                context._communication.begin_operation(limits=context.limits)
        targets = set(self.observations.targets)
        caches: dict[SelectedTarget, dict[tuple[str, int, bytes], bytes]] = {}
        selected: list[SavedRoutineBinding] = []
        for logical_id in range(1, 13):
            self._check()
            rows = self.profile.comm_rid_records(logical_id)
            if not rows:
                raise ToyotaCodecError("CommRid candidate group empty", 0xC0040101)
            for row in rows:
                category, bus = word(row, 18), row[32]
                if targets and (category, bus) not in targets:
                    continue
                categories = self.profile.category_records(category)
                if not categories:
                    raise ToyotaCodecError("CommRid category group empty", 0xC0040101)
                if categories[0][72] != 0x14:
                    raise ToyotaCodecError("CommRid target type invalid", 0xC0040102)
                context = self._saved_context(contexts, category, bus)
                if context.profile.category_record != categories[0]:
                    raise SessionError("Saved routine category record differs")
                try:
                    # ReadData uses FIRST frame; lookup errors are candidate
                    # errors at native6B87C, not fatal category-query errors.
                    command = context._frames(0xCC)[0]
                    command_name = "absolute-routine-command"
                    context.session.commands[command_name] = CommandSpec(
                        command.frame,
                        provenance=command.provenance,
                        selected=command,
                        extended=True,
                    )
                    with self._saved_no_init(context):
                        support = context.session.routine_data_no_enable_list(
                            word(row, 30),
                            3,
                            command_name=command_name,
                            response_cache=caches.setdefault(context.target, {}),
                        )
                except ToyotaCodecError:
                    # Native6B87C discards candidate communication errors only.
                    continue
                if support["phase"] == 2:
                    selected.append(
                        SavedRoutineBinding(
                            logical_id,
                            context.target,
                            row,
                            command,
                            None,
                            3 <= logical_id <= 8,
                        )
                    )
                    break
            else:
                return None
        return tuple(selected)

    def absolute_routine_logs(
        self,
        logs: Sequence[SavedLogInput],
        *,
        contexts: Mapping[tuple[int, int], ToyotaWorkflows],
        begin: bool = True,
    ) -> dict[str, object]:
        """Abs34C0 selected routine reads with native per-log/context caches."""
        from scripts.toyota_session import (
            assemble_absolute_log,
            comm_signal_data,
            decode_bcd32,
        )

        if len(logs) > 100000:
            raise ValueError("Saved-log input count exceeds local bound")
        selected_logs = selected_saved_logs(logs)
        retained = sum(len(item._metadata_json) for item in selected_logs)
        if retained > 16 * 1024 * 1024:
            raise ValueError("Saved-log metadata exceeds aggregate bound")
        plan = self.selected_absolute_routine_plan(contexts, begin=begin)
        output: list[dict[str, object]] = []
        omissions: list[dict[str, object]] = []
        result: dict[str, object] = {
            "native_status": 0,
            "supported": plan is not None,
            "logs": output,
            "status": "ok",
            "omissions": omissions,
        }
        self.native_output = result
        if plan is None:
            return result
        for item in selected_logs:
            self._check()
            caches: dict[SelectedTarget, dict[tuple[str, int, bytes], bytes]] = {}
            values: list[tuple[int, int, int]] = []
            signals: dict[int, dict[str, object]] = {}
            assembled: dict[int, int] | None = {}
            for binding in plan:
                context = self._saved_context(
                    contexts, binding.target.category, binding.target.bus_id
                )
                command_name, status_name = context._saved_routine_names(binding)
                try:
                    with self._saved_no_init(context):
                        response_cache = caches.setdefault(context.target, {})
                        context.session.routine_data_no_enable_list(
                            0x1104,
                            4,
                            command_name=command_name,
                            command=(item.number & 65535).to_bytes(2, "big"),
                            response_cache=response_cache,
                        )
                        status = context._frames(0xD7)[0]
                        context.session.commands[status_name] = CommandSpec(
                            status.frame,
                            provenance=status.provenance,
                            selected=status,
                            extended=True,
                        )
                        sample = context.session.routine_data_no_enable_list(
                            0x1104,
                            8,
                            status_name=status_name,
                            record=binding.record,
                            response_cache=response_cache,
                        )
                        raw = sample["value"]
                        if type(raw) is not int:
                            raise SessionError("Routine component value is unwritten")
                        value = decode_bcd32(raw) if binding.bcd else raw
                except ToyotaCodecError as error:
                    # Abs37C8 discards this log on any native read/BCD failure.
                    omissions.append(
                        {
                            "log_number": item.number,
                            "logical_id": binding.logical_id,
                            "native_code": error.code,
                        }
                    )
                    result["status"] = "partial"
                    assembled = None
                    break
                start_bit, end_bit = struct.unpack_from("<HH", binding.record, 20)
                values.append((binding.logical_id, value, end_bit - start_bit + 1))
                assembled = assemble_absolute_log(values, item.number)
                if assembled is None:
                    omissions.append(
                        {
                            "log_number": item.number,
                            "logical_id": binding.logical_id,
                            "phase": "value_validation",
                        }
                    )
                    result["status"] = "partial"
                    break
                rendered = comm_signal_data(binding.record, value, routine=True)
                retained += len(_workflow_json(rendered)) + 128
                if retained > 16 * 1024 * 1024:
                    raise SessionError("Saved-log output exceeds aggregate bound")
                signals[binding.logical_id] = {
                    "target": binding.target.ecu,
                    "category": binding.target.category,
                    "bus_id": binding.target.bus_id,
                    **rendered,
                }
            if assembled is not None:
                output.append(
                    {
                        "log_number": item.number,
                        "metadata": json.loads(item._metadata_json),
                        "components": assembled,
                        "signals": signals,
                    }
                )
        return result

    @contextmanager
    def _saved_operation(
        self, context: ToyotaWorkflows, *, no_init: bool = False
    ) -> Iterator[None]:
        """Share the whole wrapper's host bounds without merging native caches."""
        communication = context._communication
        if communication is None:
            raise SessionError(
                "Saved-log execution requires concrete NativeCommunication contexts"
            )
        self._check()
        if self._remaining <= 0:
            raise SessionError("Saved-log exchange budget exhausted")
        old_deadline, old_remaining = context._deadline, context._remaining
        seconds = self._deadline - self.clock()
        context._deadline = context.clock() + seconds
        context._remaining = self._remaining
        context._communication_calls = communication.calls
        context._communication_cache_calls = communication.cache.calls
        initial_calls, initial_cache = communication.calls, communication.cache.calls
        previous_flags = communication.no_init, communication.no_session
        communication.no_init, communication.no_session = no_init, False
        try:
            with communication.constrain_operation(
                deadline=communication.clock() + seconds,
                exchanges=self._remaining,
                cancelled=self.cancelled,
            ):
                try:
                    yield
                finally:
                    context._check()
        finally:
            communication.no_init, communication.no_session = previous_flags
            used = max(
                communication.calls - initial_calls,
                communication.cache.calls - initial_cache,
            )
            if context is not self:
                self._remaining -= used
                context._deadline = old_deadline
                context._remaining = old_remaining - used
                context._communication_calls = communication.calls
                context._communication_cache_calls = communication.cache.calls
            self._check()

    def absolute_pid_logs(
        self,
        logs: Sequence[SavedLogInput],
        *,
        contexts: Mapping[tuple[int, int], ToyotaWorkflows],
        begin: bool = True,
    ) -> dict[str, object]:
        """Selected absolute PID plan with isolated ECU/frame response caches."""
        from scripts.toyota_session import assemble_absolute_log, comm_signal_data

        if len(logs) > 100000:
            raise ValueError("Saved-log input count exceeds local bound")
        selected_logs = selected_saved_logs(logs)
        retained = sum(len(item._metadata_json) for item in selected_logs)
        if retained > 16 * 1024 * 1024:
            raise ValueError("Saved-log input metadata exceeds aggregate bound")
        plan = self.selected_absolute_pid_plan(contexts, begin=begin)
        result: dict[str, object] = {
            "native_status": 0,
            "supported": plan is not None,
            "logs": [],
            "status": "ok",
            "omissions": [],
        }
        output: list[dict[str, object]] = []
        result["logs"] = output
        omissions: list[dict[str, object]] = []
        result["omissions"] = omissions
        self.native_output = result
        if plan is None:
            return result
        setter_context = self._saved_context(
            contexts, plan.setter.target.category, plan.setter.target.bus_id
        )
        setter_name = "absolute-saved-setter"
        setter_context.session.commands[setter_name] = CommandSpec(
            plan.setter.frame.frame,
            provenance=plan.setter.frame.provenance,
            selected=plan.setter.frame,
        )
        skipped = {
            0x91010009,
            0x90020321,
            0x90020323,
            0xA0040201,
            0xC0040001,
            0xA0040202,
            0x90020327,
            0x91020320,
            0x91020310,
            0x91020322,
        }
        for item in selected_logs:
            self._check()
            include = True
            with self._saved_operation(setter_context):
                masks = setter_context._support().support_bits(2)
                positions = masks.get(plan.setter.record[21])
                if positions is None:
                    raise ToyotaCodecError(
                        "Saved selector DID support positions absent", 0xC005100C
                    )
                try:
                    setter_context.session.send_comm_did(
                        setter_name,
                        plan.setter.record,
                        positions,
                        (item.number & 65535).to_bytes(2, "big"),
                    )
                except ToyotaCodecError as error:
                    if error.code not in skipped:
                        raise
                    include = False
                    omissions.append(
                        {
                            "log_number": item.number,
                            "phase": "selector",
                            "native_code": error.code,
                        }
                    )
                    result["status"] = "partial"
            caches: dict[
                tuple[SelectedTarget, bytes, bytes, bytes], dict[bytes, bytes]
            ] = {}
            values = []
            metadata: dict[int, dict[str, object]] = {}
            assembled: dict[int, int] | None = {}
            for component in plan.components:
                context = self._saved_context(
                    contexts, component.target.category, component.target.bus_id
                )
                key = (
                    component.target,
                    component.frame.function_record,
                    component.frame.communication_record,
                    component.frame.settings_record,
                )
                cache = caches.setdefault(key, {})
                name = f"absolute-saved-pid:{component.logical_id:04x}"
                context.session.commands[name] = CommandSpec(
                    component.frame.frame,
                    provenance=component.frame.provenance,
                    selected=component.frame,
                    extended=context.profile.category_record[72] in (0x14, 0x15, 0x34),
                )
                try:
                    with self._saved_operation(context):
                        value = context.session.read_comm_pid(
                            name,
                            component.record,
                            context.profile.category_record[72],
                            bcd=component.bcd,
                            response_cache=cache,
                            support_cache=context._support(),
                        )
                except ToyotaCodecError as error:
                    if error.code not in skipped:
                        raise
                    assembled = None
                    omissions.append(
                        {
                            "log_number": item.number,
                            "phase": "component",
                            "logical_id": component.logical_id,
                            "native_code": error.code,
                        }
                    )
                    result["status"] = "partial"
                    break
                start_bit, end_bit = struct.unpack_from("<HH", component.record, 20)
                values.append((component.logical_id, value, end_bit - start_bit + 1))
                assembled = assemble_absolute_log(
                    values, item.number, pid_identifiers=True
                )
                if assembled is None:
                    omissions.append(
                        {
                            "log_number": item.number,
                            "phase": "value_validation",
                            "logical_id": component.logical_id,
                        }
                    )
                    result["status"] = "partial"
                    break
                signal = comm_signal_data(component.record, value)
                retained += len(_workflow_json(signal)) + 128
                if retained > 16 * 1024 * 1024:
                    raise SessionError("Saved-log output exceeds aggregate bound")
                metadata[component.logical_id - 0x8E] = {
                    "target": component.target.ecu,
                    "category": component.target.category,
                    "bus_id": component.target.bus_id,
                    **signal,
                }
            if include and assembled is not None:
                output.append(
                    {
                        "log_number": item.number,
                        "metadata": json.loads(item._metadata_json),
                        "components": assembled,
                        "signals": metadata,
                    }
                )
        return result

    def _signal_freezes(self, signal: int) -> tuple[bytes, ...]:
        checks = self.profile.signal_checks(signal)
        pid = word(checks[0], 2)
        if 10 not in self.profile.database.sections:
            raise ToyotaCodecError("Selected Freeze resource is absent", 0xA0030107)
        rows = tuple(row for row in self.profile.records(10) if word(row, 56) == pid)
        if not rows:
            raise ToyotaCodecError("Selected signal Freeze group is empty", 0xC0040101)
        return rows

    def _pattern_label(
        self, freeze: bytes, value: int, *, fallback: bool = False
    ) -> str | None:
        if 14 not in self.profile.database.sections:
            raise ToyotaCodecError("Selected pattern resource is absent", 0xA0030107)
        old = self.profile.database.version == 0x0100030C
        rows = [
            row
            for row in self.profile.records(14)
            if word(row, 4 if old else 12) == word(freeze, 70)
        ]
        if not rows:
            raise ToyotaCodecError("Selected pattern group is empty", 0xC0040101)
        compared_value = value & 0xFFFF if old else value
        match = next(
            (
                row
                for row in rows
                if (word(row, 10) if old else struct.unpack_from("<I", row, 4)[0])
                == compared_value
            ),
            None,
        )
        if match is None and fallback:
            match = next(
                (
                    row
                    for row in rows
                    if (word(row, 10) if old else struct.unpack_from("<I", row, 4)[0])
                    == 255
                ),
                None,
            )
        if match is None:
            if fallback:
                raise ToyotaCodecError(
                    "P4 absolute pattern match is absent", 0xC0040101
                )
            return None
        label = self.profile.catalog.language.resolve(
            struct.unpack_from("<I", match)[0]
        )
        return label if label else None

    def is_absolute_freeze(self) -> dict[str, object]:
        """IsAbsFrzFrmDat1010: signal4, SupFreeze order, raw value, function18 and label."""
        self._begin(source12_verified=True)
        freeze = self._signal_freezes(4)[0]
        if 2 not in self.profile.database.sections:
            raise ToyotaCodecError("Selected SupFreeze resource is absent", 0xA0030107)
        supported = self.profile.records(2)
        if not supported:
            raise ToyotaCodecError("Selected SupFreeze group is empty", 0xC0040101)
        output = []
        for index, row in enumerate(supported):
            self._check()
            number = row[2]
            names = self._register(0x11)
            if len(names) != 1:
                raise ToyotaCodecError(
                    "Absolute freeze requires one data frame", 0xC0040102
                )
            try:
                payload = self.session.freeze_p3(names[0], freeze, number)
            except ToyotaCodecError as error:
                if error.code in (0x91010009, 0x90020323):
                    continue
                raise
            begin, end = struct.unpack_from("<HH", freeze, 62)
            value = extract_bits(payload, begin, end)
            if not value:
                continue
            status_frames = self._frames(0x18)
            if len(status_frames) != 1:
                raise ToyotaCodecError(
                    "Absolute freeze requires one status frame", 0xC0040102
                )
            selected = status_frames[0]
            request = selected.frame.request
            if len(request) < 3:
                raise ToyotaCodecError(
                    "Absolute status frame lacks number byte", 0xC0040102
                )
            patched = replace(
                selected.frame, request=request[:2] + bytes([number]) + request[3:]
            )
            self.session.commands["absolute-status"] = CommandSpec(
                patched, provenance=selected.provenance, selected=selected
            )
            try:
                reply = self.session.execute("absolute-status")
            except ToyotaCodecError as error:
                if error.code in (0x91010009, 0x90020323):
                    continue
                raise
            if len(reply) < 5:
                raise ToyotaCodecError(
                    "Absolute status response lacks bytes3/4", 0xA0040202
                )
            if reply[3] or reply[4]:
                continue
            label = self._pattern_label(freeze, value & 255)
            if label is not None:
                output.append(
                    {
                        "frame_number": number,
                        "ordinal": (index + 1) & 255,
                        "label": label,
                    }
                )
        return {"native_status": 0, "frames": output}

    def is_absolute_freeze_p4(self) -> dict[str, object]:
        """P4 availability uses exactly one signal definition and full-value/FF patterns."""
        self._begin(source12_verified=True)
        if 0 not in self.profile.database.sections:
            raise ToyotaCodecError(
                "Selected SignalGroup resource is absent", 0xA0030107
            )
        groups = [row for row in self.profile.records(0) if row[8] == 4]
        if len(groups) != 1:
            raise ToyotaCodecError(
                "P4 absolute SignalGroup requires one row", 0xC0040102
            )
        checks = self.profile.signal_checks(4)
        freezes = self._signal_freezes(4)
        if len(checks) != 1 or len(freezes) != 1:
            raise ToyotaCodecError(
                "P4 absolute signal requires one check and Freeze", 0xC0040102
            )
        freeze = freezes[0]
        if 2 not in self.profile.database.sections:
            raise ToyotaCodecError("Selected SupFreeze resource is absent", 0xA0030107)
        supported = self.profile.records(2)
        if not supported:
            raise ToyotaCodecError("Selected SupFreeze group is empty", 0xC0040101)
        positions = self.observations.pid_positions
        selected_positions = (
            None if positions is None else positions.get(freeze[79], b"")
        )
        omitted = {
            0x91010009,
            0x90020321,
            0x90020323,
            0xA0040201,
            0xC0040001,
            0xA0040202,
            0x90020327,
            0x91020320,
            0x91020310,
            0x91020322,
        }
        output = []
        response_cache: dict[bytes, bytes | ToyotaCodecError] = {}
        for index, row in enumerate(supported):
            self._check()
            names = self._register(0x11)
            if len(names) != 1:
                raise ToyotaCodecError(
                    "P4 absolute freeze requires one frame", 0xC0040102
                )
            try:
                payload = self.session.freeze_p4(
                    names[0],
                    freeze,
                    row[2],
                    selected_positions,
                    response_cache=response_cache,
                    support_cache=self._support() if positions is None else None,
                )
            except ToyotaCodecError as error:
                if error.code in omitted:
                    continue
                raise
            begin, end = struct.unpack_from("<HH", freeze, 62)
            value = extract_bits(payload, begin, end)
            if not value:
                continue
            label = self._pattern_label(freeze, value, fallback=True)
            if label is None:
                raise ToyotaCodecError(
                    "P4 absolute pattern has no nonempty label", 0xC0040102
                )
            output.append(
                {"frame_number": row[2], "ordinal": (index + 1) & 255, "label": label}
            )
        return {"native_status": 0, "frames": output}

    def is_absolute_freeze_dk(self) -> dict[str, object]:
        """DK availability preserves byte-value gating and native FF/FE order bytes."""
        self._begin(source12_verified=True)
        freeze = self._signal_freezes(4)[0]
        if 2 not in self.profile.database.sections:
            raise ToyotaCodecError("Selected SupFreeze resource is absent", 0xA0030107)
        supported = self.profile.records(2)
        if not supported:
            raise ToyotaCodecError("Selected SupFreeze group is empty", 0xC0040101)
        output = []
        for index, row in enumerate(supported):
            self._check()
            names = self._register(0x11)
            if len(names) != 1:
                raise ToyotaCodecError(
                    "DK absolute freeze requires one data frame", 0xC0040102
                )
            try:
                payload = self.session.freeze_dk_abs(names[0], freeze, row[2])
            except ToyotaCodecError as error:
                if error.code in (0x91010009, 0x90020321):
                    continue
                raise
            begin, end = struct.unpack_from("<HH", freeze, 62)
            value = extract_bits(payload, begin, end) & 255
            if not value:
                continue
            selected = self._frames(0x18)[0]
            request = selected.frame.request
            if len(request) < 4:
                raise ToyotaCodecError(
                    "DK status frame requires four bytes", 0xC0040102
                )
            patched = replace(
                selected.frame, request=request[:1] + bytes([row[2]]) + request[2:]
            )
            self.session.commands["absolute-dk-status"] = CommandSpec(
                patched, provenance=selected.provenance, selected=selected
            )
            try:
                reply = self.session.execute("absolute-dk-status")
            except ToyotaCodecError as error:
                if error.code in (0x91010009, 0x90020321):
                    continue
                raise
            if len(reply) < 4:
                raise ToyotaCodecError(
                    "DK status response requires four bytes", 0xA0040202
                )
            if reply[2] or reply[3]:
                continue
            label = self._pattern_label(freeze, value)
            if label is not None:
                output.append(
                    {
                        "frame_number": row[2],
                        "ordinal": 255 if index == 0 else 254 if index == 1 else 0,
                        "label": label,
                    }
                )
        return {"native_status": 0, "frames": output}

    def _legacy_multi_value(self, function: int, detail: int) -> int:
        try:
            frames = self._frames(function)
        except ToyotaCodecError as error:
            if error.code != 0xC0040101:
                raise
            frames = ()
        if not frames:
            present, value = self.observations.function(1, 6, detail)
            if not present:
                raise ToyotaCodecError(
                    "Selected multi-freeze feature is absent", 0xC0040601
                )
            return value & 255
        if len(frames) != 1:
            raise ToyotaCodecError("Multi-freeze info requires one frame", 0xC0040102)
        reply = self._send_function(function)[0]
        mask = frames[0].frame.receive_mask
        # Native17A0 rejects excess reply bytes; reject its unsafe short-read case too.
        if len(reply) > len(mask):
            raise ToyotaCodecError(
                "Multi-freeze info exceeds selected mask", 0xA0040201
            )
        if len(reply) < len(mask):
            raise ToyotaCodecError(
                "Multi-freeze info lacks selected mask bytes", 0xA0040202
            )
        return next(
            (
                byte & chosen
                for byte, chosen in zip(reply, mask, strict=True)
                if byte & chosen
            ),
            0,
        )

    def is_multi_freeze(self, alias: int, dtc: int) -> dict[str, object]:
        """Original IsMulti selects71/73/72 or exact native function-tree fallbacks."""
        _unsigned(alias, 255)
        _unsigned(dtc, 65535)
        self._begin(source12_verified=True)
        count = self._legacy_multi_value(0x71, 4)
        if not count:
            return {"native_status": 0, "available": False}
        number = self._legacy_multi_value(0x73, 6)
        if not number & 0xF0:
            number = self._legacy_multi_value(0x72, 5)
        if not number & 0xF0:
            return {"native_status": 0, "available": False}
        number = (number & 0xF0) | (alias & 15)
        try:
            code = self.session.freeze_diagnostic_code_profile(
                self.profile, number, mask_flags=0
            )
        except ToyotaCodecError as error:
            if error.code != 0x91010009:
                raise
            code = None
        # Original initializes the output WORD to FFFF before the timeout-allowed call.
        comparison = 0xFFFF if code is None else code
        return {
            "native_status": 0,
            "available": comparison == dtc,
            "frame_number": number,
            "dtc": code,
            "native_comparison_word": comparison,
        }

    def is_multi_freeze_v2(self, alias: int, dtc: int) -> dict[str, object]:
        """V2 enumerates descending native high nibbles and keeps its alias marker."""
        _unsigned(alias, 255)
        _unsigned(dtc, 65535)
        self._begin(source12_verified=True)
        info = self.session.multi_freeze_info(
            self.profile, self.observations, support_cache=self._support()
        )
        result: dict[str, object] = {
            "native_status": 0,
            "available": False,
            "native_numbers": [],
            "info": info,
        }
        if info["supported"] is not True:
            return result
        count, lower, upper = (info[key] for key in ("out1", "out2", "out3"))
        if type(count) is not int or type(lower) is not int or type(upper) is not int:
            raise SessionError(
                "Supported multi-freeze info has unwritten native outputs"
            )
        count, lower, upper = count & 255, lower & 255, upper & 255
        if not count or not (lower | upper) & 0xF0:
            return result
        numbers = [alias & 15]
        result["native_numbers"] = numbers
        omitted = {
            0x91010009,
            0x90020321,
            0x90020323,
            0xA0040201,
            0xC0040001,
            0xA0040202,
            0x90020327,
            0x91020320,
            0x91020310,
            0x91020322,
        }
        encoded = (upper & 0xF0) | (alias & 15)
        for _index in range(
            _multi_frame_index(upper), _multi_frame_index(lower) - 1, -1
        ):
            self._check()
            number = encoded
            encoded = (encoded - 0x10) & 255
            if not number & 0xF0:
                continue
            try:
                code = self.session.freeze_diagnostic_code_profile(
                    self.profile, number, mask_flags=2
                )
            except ToyotaCodecError as error:
                if error.code in omitted:
                    continue
                raise
            # V2 explicitly clears this output WORD before every call.
            if (0 if code is None else code) == dtc:
                result["available"] = True
                numbers.append(number)
        return result

    @staticmethod
    def _freeze_supported_p4(
        freeze: bytes,
        enabled: Mapping[int, int],
        masks: Mapping[int, bytes],
        *,
        force: bool = False,
        raw_only: bool = False,
    ) -> bool:
        mode = freeze[77]
        if mode in (1, 2) and not force and not raw_only:
            return mode == 1
        if mode > 2 and not raw_only:
            raise ToyotaCodecError("Invalid native P4 support mode", 0xA0040004)
        pid = freeze[79]
        if pid not in enabled:
            return False
        if pid not in masks:
            raise ToyotaCodecError("Native P4 support mask is absent", 0xC0040001)
        begin, end = struct.unpack_from("<HH", freeze, 62)
        if end >= len(masks[pid]) * 8:
            return False
        return extract_bits(masks[pid], begin, end) != 0

    def _freeze_metadata(self, freeze: bytes) -> MonitorSignalMetadata:
        return selected_freeze_metadata(
            self.profile,
            freeze,
            SignalLSB(
                self._support(),
                source_build=12 if self.observations.source_version == 12 else 18,
            ),
        )

    def _operation_freezes(self, signal: int, *, exact: bool) -> tuple[bytes, ...]:
        if 0 not in self.profile.database.sections:
            raise ToyotaCodecError("Signal group resource absent", 0xA0030107)
        groups = [row for row in self.profile.records(0) if row[8] == signal]
        if not groups or (exact and len(groups) != 1):
            raise ToyotaCodecError(
                "Operation signal group count", 0xC0040102 if exact else 0xC0040101
            )
        if 1 not in self.profile.database.sections:
            raise ToyotaCodecError("Signal check resource absent", 0xA0030107)
        checks = [
            row for row in self.profile.records(1) if word(row, 0) == word(groups[0], 4)
        ]
        if not checks or (exact and len(checks) != 1):
            raise ToyotaCodecError(
                "Operation signal check count", 0xC0040102 if exact else 0xC0040101
            )
        if 10 not in self.profile.database.sections:
            raise ToyotaCodecError("Freeze resource absent", 0xA0030107)
        rows = tuple(
            row
            for row in self.profile.records(10)
            if word(row, 56) == word(checks[0], 2)
        )
        if not rows or (exact and len(rows) != 1):
            raise ToyotaCodecError(
                "Operation Freeze count", 0xC0040102 if exact else 0xC0040101
            )
        return rows

    def _operation_read(
        self,
        freeze: bytes,
        number: int,
        cache: dict,
        *,
        initialize_timeout: bool = False,
        control: int = 0,
    ) -> bytes:
        names = self._register(0xE4)
        if len(names) != 1:
            raise ToyotaCodecError("Operation freeze requires one frame", 0xC0040102)
        positions = self.observations.pid_positions
        try:
            return self.session.freeze_operation_p4(
                names[0],
                freeze,
                number,
                control,
                None if positions is None else positions.get(freeze[79], b""),
                response_cache=cache,
                support_cache=self._support() if positions is None else None,
            )
        except ToyotaCodecError as error:
            if initialize_timeout and error.code == 0x91010009:
                selected = self._frames(0xE4)[0]
                self.session.native_frame_sends(
                    [
                        NativeFrameSend(
                            "SendInt",
                            self.profile.category,
                            None,
                            struct.unpack_from("<I", selected.settings_record)[0],
                            self.observations.bus_id,
                            1,
                            1,
                        )
                    ],
                    ignore_status=True,
                )
            raise

    def _operation_sample(
        self,
        freeze: bytes,
        number: int,
        cache: dict,
        *,
        initialize_timeout: bool = False,
        budget: list[int] | None = None,
        control: int = 0,
    ) -> dict[str, object]:
        payload = self._operation_read(
            freeze,
            number,
            cache,
            initialize_timeout=initialize_timeout,
            control=control,
        )
        return self._operation_render(freeze, payload, budget=budget)

    def _operation_render(
        self, freeze: bytes, payload: bytes | None, *, budget: list[int] | None = None
    ) -> dict[str, object]:
        metadata = self._freeze_metadata(freeze)
        # ICS02 explicitly clears CCmdEcuData DWORD10 in its constructor and
        # accepts A0040202 before GetValue. This is a proven native default.
        raw = (
            0
            if payload is None
            else extract_bits(payload, metadata.start_bit, metadata.end_bit)
        )
        rendered = render_signal(
            raw,
            selector=metadata.selector,
            sign_mode=metadata.sign_mode,
            bits=metadata.end_bit - metadata.start_bit + 1,
            multiplier=metadata.multiplier,
            divisor=metadata.divisor,
            offset=metadata.offset,
            precision=metadata.precision,
            patterns=tuple(
                (low, label, low, high) for _, label, low, high in metadata.patterns
            ),
            minimum_raw=metadata.extended[1],
            maximum_raw=metadata.extended[2],
            extended=(metadata.extended,),
        )
        sample = {
            "signal_id": word(freeze, 56),
            "name": metadata.name,
            "unit": metadata.unit,
            "native_index": 0,
            "raw": raw,
            **rendered,
        }
        if payload is None:
            sample["native_default"] = "CCmdEcuData_ctor_DWORD10_zero_after_A0040202"
        if budget is not None:
            # Bound retained output before inserting it into any growing list.
            budget[0] += 512
            for value in sample.values():
                if isinstance(value, str):
                    budget[0] += len(value.encode("utf-8"))
            if budget[0] > 16 * 1024 * 1024:
                raise SessionError("Operation output exceeds local byte budget")
        return sample

    def _operation_special(
        self, number: int, budget: list[int]
    ) -> tuple[dict[str, object], bool]:
        """Native37f0 flags use member offsets; no inferred business names."""
        flags: dict[str, object] = {
            "20": 0,
            "24": 0,
            "c0": 0,
            "c4": 0,
            "160": 0,
            "signals": {},
        }
        samples: dict[str, object] = {}
        flags["signals"] = samples
        any_sample = False
        try:
            masks = self._support().support_bits(1)
            enabled = self._support().enabled_pids(family="p4", kind=4, control=number)
        except ToyotaCodecError:
            flags.update({"24": 1, "c4": 1})
            return flags, False
        cache: dict[bytes, bytes | ToyotaCodecError] = {}
        supported35 = False
        try:
            freeze = self._operation_freezes(35, exact=False)[0]
            supported35 = self._freeze_supported_p4(freeze, enabled, masks, force=True)
        except ToyotaCodecError:
            pass
        if supported35:
            try:
                sample = self._operation_sample(
                    freeze, number, cache, initialize_timeout=True, budget=budget
                )
                samples["164"] = sample
                flags["160"] = int(sample["raw"] != 0)
                any_sample = True
            except ToyotaCodecError:
                flags.update({"24": 1, "c4": 1})
                return flags, False
        for signal, present, absent, member in (
            (28, "20", "24", "28"),
            (36 if supported35 else 29, "c0", "c4", "c8"),
        ):
            try:
                freeze = self._operation_freezes(signal, exact=False)[0]
                if not self._freeze_supported_p4(freeze, enabled, masks, force=True):
                    raise ToyotaCodecError(
                        "Operation auxiliary unsupported", 0xC0040001
                    )
                flags[present] = 1
                samples[member] = self._operation_sample(
                    freeze, number, cache, initialize_timeout=True, budget=budget
                )
                any_sample = True
            except ToyotaCodecError:
                flags[present], flags[absent] = 0, 1
        return flags, any_sample

    def operation_freeze_p4(self) -> dict[str, object]:
        """Native Execute1000 with selected SupOperationFreeze query semantics."""
        self._begin(source12_verified=True)
        probe = self._operation_freezes(37, exact=True)[0]
        selector = {366: 1, 170: 129}.get(self.profile.category)
        rows = (
            () if selector is None else self.profile.operation_freeze_records(selector)
        )
        if not rows:
            raise ToyotaCodecError("Operation freeze group empty", 0xC0040101)
        operations: list[dict[str, object]] = []
        result: dict[str, object] = {
            "native_status": 0,
            "operations": operations,
            "status": "ok",
        }
        caches: list[dict[bytes, bytes | ToyotaCodecError]] = [{}, {}]
        budget = [0]
        omitted = {
            0x91010009,
            0x90020321,
            0x90020323,
            0xA0040201,
            0xC0040001,
            0xA0040202,
            0x90020327,
            0x91020320,
            0x91020310,
            0x91020322,
        }
        for index, row in enumerate(rows):
            self._check()
            number = row[5]
            payload = self._operation_read(probe, number, caches[0])
            if not self._operation_pattern_matches(
                probe, extract_bits(payload, *struct.unpack_from("<HH", probe, 62))
            ):
                continue
            flags, any_sample = self._operation_special(number, budget)
            support = self._support()
            masks = support.support_bits(1)
            enabled = support.enabled_pids(family="p4_ignore", kind=4, control=number)
            # Group38 has one group but may contain several checks.
            if (
                0 not in self.profile.database.sections
                or 1 not in self.profile.database.sections
            ):
                raise ToyotaCodecError("Operation signal resources absent", 0xA0030107)
            groups = [r for r in self.profile.records(0) if r[8] == 38]
            if len(groups) != 1:
                raise ToyotaCodecError("Operation signal group count", 0xC0040102)
            checks = [
                r for r in self.profile.records(1) if word(r, 0) == word(groups[0], 4)
            ]
            if not checks:
                raise ToyotaCodecError("Operation check group empty", 0xC0040101)
            samples = []
            for check in checks:
                freezes = [
                    r for r in self.profile.records(10) if word(r, 56) == word(check, 2)
                ]
                if len(freezes) != 1:
                    raise ToyotaCodecError("Operation Freeze count", 0xC0040102)
                freeze = freezes[0]
                if not freeze[78] & 2 or not self._freeze_supported_p4(
                    freeze, enabled, masks, raw_only=True
                ):
                    continue
                try:
                    sample = self._operation_sample(
                        freeze, number, caches[1], budget=budget
                    )
                except ToyotaCodecError as error:
                    if error.code in omitted:
                        continue
                    raise
                samples.append(sample)
            groups = [r for r in self.profile.records(0) if r[8] == 41]
            if len(groups) > 1:
                raise ToyotaCodecError("Operation include group count", 0xC0040102)
            include = bool(samples) or any_sample
            if groups:
                freeze = self._operation_freezes(41, exact=True)[0]
                include = False
                if self._freeze_supported_p4(freeze, enabled, masks, raw_only=True):
                    try:
                        payload = self._operation_read(freeze, number, caches[1])
                    except ToyotaCodecError as error:
                        if error.code not in omitted:
                            raise
                    else:
                        include = self._operation_pattern_matches(
                            freeze,
                            extract_bits(
                                payload, *struct.unpack_from("<HH", freeze, 62)
                            ),
                        )
            if include:
                operations.append(
                    {
                        "frame_number": number,
                        "ordinal": (index + 1) & 255,
                        "label": "",
                        "native_fields": flags,
                        "signals": samples,
                    }
                )
                if any(sample["status"] == "unresolved" for sample in samples) or any(
                    isinstance(sample, dict) and sample.get("status") == "unresolved"
                    for sample in cast(Mapping[str, object], flags["signals"]).values()
                ):
                    result["status"] = "partial"
        return result

    def _operation_pattern_matches(self, freeze: bytes, value: int) -> bool:
        if 14 not in self.profile.database.sections:
            raise ToyotaCodecError("Operation pattern resource absent", 0xA0030107)
        old = self.profile.database.version == 0x0100030C
        rows = [
            row
            for row in self.profile.records(14)
            if word(row, 4 if old else 12) == word(freeze, 70)
        ]
        if not rows:
            raise ToyotaCodecError("Operation pattern group empty", 0xC0040101)
        compared_value = value & 0xFFFF if old else value
        return any(
            (word(row, 10) if old else struct.unpack_from("<I", row, 4)[0])
            == compared_value
            for row in rows
        )

    @staticmethod
    def _ics_support(freeze: bytes, masks: Mapping[int, bytes]) -> bool:
        """Common56770 PidCheckSupportBit, without enabled-list shortcuts."""
        pid = freeze[79]
        if pid not in masks:
            raise ToyotaCodecError("Native support PID absent", 0x90040501)
        begin, end = struct.unpack_from("<HH", freeze, 62)
        if end >= len(masks[pid]) * 8:
            return False
        return extract_bits(masks[pid], begin, end) != 0

    def _ics_auxiliary(
        self,
        number: int,
        control: int,
        masks: Mapping[int, bytes],
        *,
        extended: bool,
        budget: list[int],
    ) -> tuple[dict[str, object], bool]:
        omitted = {
            0x91010009,
            0x90020321,
            0x90020323,
            0xA0040201,
            0xC0040001,
            0x90020327,
            0x91020320,
            0x91020310,
            0x91020322,
        }
        fields: dict[str, object] = (
            {"210": 0} if extended else {"20": 0, "24": 0, "c0": 0, "c4": 0, "160": 0}
        )
        samples: dict[str, object] = {}
        fields["signals"] = samples
        cache: dict[bytes, bytes | ToyotaCodecError] = {}
        any_sample = False
        supported35 = False

        def selected(signal: int, member: str) -> tuple[bool, dict[str, object] | None]:
            try:
                freeze = self._operation_freezes(signal, exact=False)[0]
            except ToyotaCodecError:
                return False, None
            try:
                supported = self._ics_support(freeze, masks)
            except ToyotaCodecError as error:
                if error.code != 0x90040501:
                    raise
                supported = False
            try:
                payload = self._operation_read(
                    freeze, number, cache, initialize_timeout=True, control=control
                )
            except ToyotaCodecError as error:
                if error.code != 0xA0040202:
                    raise
                if supported:
                    unwritten = cast(
                        dict[str, int], fields.setdefault("unwritten_signals", {})
                    )
                    unwritten[member] = error.code
                return supported, None
            sample = (
                self._operation_render(freeze, payload, budget=budget)
                if supported
                else None
            )
            if sample is not None:
                samples[member] = sample
            return supported, sample

        if extended:
            values = []
            for signal, member in (
                (71, "34c"),
                (69, "3e4"),
                (70, "47c"),
                (68, "514"),
                (67, "5ac"),
                (66, "644"),
            ):
                try:
                    supported, sample = selected(signal, member)
                except ToyotaCodecError as error:
                    if error.code in omitted:
                        raise
                    return fields, any_sample
                any_sample |= supported
                values.append(
                    None if not supported or sample is None else sample["raw"]
                )
            if all(type(value) is int for value in values) and values not in (
                [0] * 6,
                [0x22, 1, 4, 1, 0, 0],
            ):
                fields["210"] = 1
            return fields, any_sample

        try:
            supported35, sample = selected(35, "164")
            if supported35:
                if sample is None:
                    raise SessionError(
                        "Native ICS02 signal35 accesses an absent MultiData after short reply"
                    )
                fields["160"] = int(sample["raw"] != 0)
                any_sample = True
        except ToyotaCodecError as error:
            if error.code in omitted:
                raise
            fields.update({"24": 1, "c4": 1})
            return fields, any_sample
        for signal, present, absent, member in (
            (28, "20", "24", "28"),
            (36 if supported35 else 29, "c0", "c4", "c8"),
        ):
            fields[present] = 1
            try:
                supported, _sample = selected(signal, member)
                any_sample |= supported
                if not supported:
                    fields[present], fields[absent] = 0, 1
            except ToyotaCodecError as error:
                if error.code in omitted:
                    raise
                fields[present], fields[absent] = 0, 1
        return fields, any_sample

    def each_freeze_p5_core(
        self,
        state: P5FreezeState,
        requests: tuple[P5SnapshotRequest, ...],
        *,
        begin: bool = True,
        create_diagnostics: bool = True,
    ) -> dict[str, object]:
        """Each1050/17E0/1CD0 and GetDiag41B0/4940/4E30 normal CF phase.

        The caller retains the concrete state and mutable native request numbers.
        GetDiag's consumer only decorates existing diagnostics; standalone Each
        creates missing diagnostics and records existence before DID analysis.
        """
        from scripts.freeze_p5 import P5FreezeState, P5SnapshotRequest

        if not isinstance(state, P5FreezeState) or state.subaru:
            raise TypeError("Normal EachP5 requires its concrete Common freeze state")
        maximum = state.diagnostic_limit
        if (
            not isinstance(requests, tuple)
            or len(requests) > maximum
            or any(not isinstance(item, P5SnapshotRequest) for item in requests)
        ):
            raise TypeError("Bounded typed EachP5 requests required")
        for item in requests:
            item.__post_init__()
        if type(begin) is not bool or type(create_diagnostics) is not bool:
            raise TypeError("EachP5 phase controls must be boolean")
        if self._communication is None or state.cache is not self._communication.cache:
            raise SessionError(
                "EachP5 requires the same concrete native selected cache"
            )
        if (
            state.profile is not self.profile
            or state.source_build != self.observations.source_version
        ):
            raise SessionError("EachP5 selected source differs from its state")
        if begin:
            self._begin(source12_verified=True)
        state._check()
        state.init_freeze_data()
        selected = self._frames(0xCF)[0]
        capacity = (
            65535
            if state.source_build == 18 and self.observations.bus_id == 0x14
            else None
        )
        retained = [item for item in requests if item.numbers]
        parsed: list[dict[str, object]] = []
        omissions: list[dict[str, object]] = []
        result: dict[str, object] = {
            "native_status": 0,
            "status": "ok",
            "communication_success": False,
            "parsed": parsed,
            "omissions": omissions,
            "requests": [],
            "phase": "normal_each_data_core",
        }
        self.native_output = result
        captures: list[tuple[bytes, int]] = []
        captured_bytes = 0
        masked = {
            0x91010009,
            0x90020321,
            0x90020323,
            0xA0040201,
            0xC0040001,
            0xA0040202,
            0x90020327,
            0x91020320,
            0x91020310,
            0x91020322,
        }

        def read(item: P5SnapshotRequest, number: int | None) -> bytes:
            self._check()
            if state.native_cancel_value == 1:
                raise ToyotaCodecError("Native EachP5 command cancelled", 0xA0040003)
            request = state.set_dtc(selected.frame.request, item.code, number)
            with self._saved_operation(self):
                return state.cache.transaction(
                    selected, request, cached=False, extended=True, capacity=capacity
                )

        def keep(reply: bytes, number: int) -> None:
            nonlocal captured_bytes
            if len(captures) >= 65535 or captured_bytes + len(reply) > 16 * 1024 * 1024:
                raise SessionError("EachP5 captured response budget exhausted")
            captures.append((reply, number))
            state.snapshot_frames.append(reply)
            captured_bytes += len(reply)

        def omit(item: P5SnapshotRequest, number: int | None, code: int) -> None:
            omissions.append({"code": item.code, "number": number, "native_code": code})
            result["status"] = "partial"

        fallback = False
        attempts = 0
        for item in tuple(retained):
            attempts += 1
            try:
                reply = read(item, None)
            except ToyotaCodecError as error:
                if error.code not in masked:
                    raise
                omit(item, None, error.code)
                if attempts == 1:
                    fallback = True
                    break
                retained.remove(item)
                continue
            result["communication_success"] = True
            # Native checks byte7 after its seven-byte minimum; an absent byte
            # is an unsafe native access, so the bounded host fails explicitly.
            if len(reply) == 7:
                raise SessionError("Native EachP5 aggregate count byte is absent")
            if len(reply) > 6 and reply[7] == 0:
                if attempts == 1:
                    fallback = True
                    break
                retained.remove(item)
                omit(item, None, 0)
                continue
            keep(reply, 255)
            item.numbers[:] = [255]
        if fallback:
            for item in tuple(retained):
                index = 0
                while index < len(item.numbers):
                    number = item.numbers[index]
                    try:
                        reply = read(item, number)
                    except ToyotaCodecError as error:
                        if error.code not in masked:
                            raise
                        omit(item, number, error.code)
                        del item.numbers[index]
                        continue
                    result["communication_success"] = True
                    keep(reply, item.numbers[0])
                    index += 1
                if not item.numbers:
                    retained.remove(item)
        # Native finishes communications before analysis; a fatal wire error
        # therefore leaves captured bytes without inventing analyzed values.
        for reply, number in captures:
            self._check()
            decoded = analyze_each_p5_reply(
                state,
                reply,
                requested_number=number,
                create_diagnostics=create_diagnostics,
            )
            parsed.append(decoded)
            if decoded["status"] == "partial":
                result["status"] = "partial"
        for diagnostic in state.diagnostics:
            self._check()
            state.sort_multi_data_by_timestamp(diagnostic)
        result["requests"] = [
            {"code": item.code, "numbers": list(item.numbers)} for item in retained
        ]
        return result

    def predictive_freeze_p5_core(
        self, state: P5FreezeState, code: int, *, begin: bool = True
    ) -> dict[str, object]:
        """Each44F0/46F0 D0 scan, DTC filtering, analysis and temporary merge."""
        from scripts.freeze_p5 import P5FreezeState

        _unsigned(code, 0xFFFFFF)
        if not isinstance(state, P5FreezeState) or state.subaru:
            raise TypeError("Predictive EachP5 requires its normal Common state")
        if self._communication is None or state.cache is not self._communication.cache:
            raise SessionError(
                "Predictive EachP5 requires its concrete selected native cache"
            )
        if (
            state.profile is not self.profile
            or state.source_build != self.observations.source_version
        ):
            raise SessionError("Predictive EachP5 selected source differs")
        if type(begin) is not bool:
            raise TypeError("Predictive phase control must be boolean")
        if begin:
            self._begin(source12_verified=True)
        state.init_freeze_data()
        selected = self._frames(0xD0)[0]
        if len(selected.frame.request) < 3:
            raise ToyotaCodecError(
                "Predictive D0 selected template too short", 0xC0040001
            )
        capacity = (
            65535
            if state.source_build == 18 and self.observations.bus_id == 0x14
            else None
        )
        captures: list[tuple[bytes, int]] = []
        accepted: list[int] = []
        omissions: list[dict[str, object]] = []
        result: dict[str, object] = {
            "status": "ok",
            "native_status": 0,
            "communication_success": False,
            "accepted_numbers": accepted,
            "omissions": omissions,
            "phase": "predictive_each_data_core",
        }
        self.native_output = result
        captured_bytes = 0
        masked = {
            0x91010009,
            0x90020321,
            0x90020323,
            0xA0040201,
            0xC0040001,
            0xA0040202,
            0x90020327,
            0x91020320,
            0x91020310,
            0x91020322,
        }

        def probe(number: int) -> bool:
            nonlocal captured_bytes
            self._check()
            if state.native_cancel_value == 1:
                raise ToyotaCodecError(
                    "Native predictive command cancelled", 0xA0040003
                )
            request = (
                selected.frame.request[:2]
                + bytes((number,))
                + selected.frame.request[3:]
            )
            try:
                with self._saved_operation(self):
                    reply = state.cache.transaction(
                        selected,
                        request,
                        cached=False,
                        extended=True,
                        capacity=capacity,
                    )
            except ToyotaCodecError as error:
                if error.code not in masked:
                    raise
                omissions.append({"number": number, "native_code": error.code})
                result["status"] = "partial"
                return False
            result["communication_success"] = True
            if len(reply) > 6 and int.from_bytes(reply[3:6], "big") == code:
                if captured_bytes + len(reply) > 16 * 1024 * 1024:
                    raise SessionError("Predictive capture byte budget exhausted")
                captures.append((reply, number))
                state.snapshot_frames.append(reply)
                captured_bytes += len(reply)
                accepted.append(number)
                return True
            return False

        bases = [number for number in range(1, 15) if probe(number)]
        for base in bases:
            for offset in range(16):
                probe(base << 4 | offset)
        analysis = analyze_predictive_p5_replies(state, tuple(captures))
        result["analysis"] = analysis
        if analysis["status"] == "partial":
            result["status"] = "partial"
        return result

    @contextmanager
    def _comm_log(self, kind: int) -> Iterator[dict[str, object]]:
        """Actual native start/body/conditional stop and error precedence."""
        communication = self._communication
        if communication is None:
            raise SessionError("Communication logging requires concrete native context")
        started = communication.start_comm_log(kind)
        lifecycle: dict[str, object] = {"kind": kind, "start_status": started}
        failed = False
        try:
            yield lifecycle
        except BaseException:
            failed = True
            raise
        finally:
            stop_error: BaseException | None = None
            stopped = 0
            if started == 0:
                try:
                    stopped = communication.stop_comm_log()
                    lifecycle["stop_status"] = stopped
                except BaseException as error:  # noqa: BLE001 - preserve primary failure during cleanup
                    stop_error = error
                    lifecycle["stop_error"] = {
                        "type": type(error).__name__,
                        "message": str(error)[:512],
                    }
            self.native_output["communication_log"] = lifecycle
            if not failed:
                if stop_error is not None:
                    raise stop_error
                if started or stopped:
                    raise ToyotaCodecError(
                        "Native communication-log lifecycle failed", started or stopped
                    )

    @contextmanager
    def _logged_connection(self, kind: int) -> Iterator[dict[str, object]]:
        """Original connection-check and ignored Disconnect1 before log stop."""
        communication = self._communication
        if communication is None:
            raise SessionError(
                "Native connection wrapper requires concrete communication"
            )
        lifecycle: dict[str, object] = {}
        with self._comm_log(kind) as logging:
            lifecycle["communication_log"] = logging
            failed = False
            try:
                # Common71790 NULL-cache/last0 is the local Ever path, not TEMP.
                with self._saved_operation(self):
                    connection = communication.connection_no_buffer(0, 1)
                lifecycle["connection_status"] = connection.status
                lifecycle["connected"] = connection.connected
                if connection.status:
                    raise ToyotaCodecError(
                        "Native connection check failed", connection.status
                    )
                yield lifecycle
            except BaseException:
                failed = True
                raise
            finally:
                cleanup_error: BaseException | None = None
                try:
                    lifecycle["disconnect_status"] = communication.disconnect(
                        1, deadline=communication.clock() + self.limits.seconds
                    )
                except BaseException as error:  # noqa: BLE001 - preserve primary failure during cleanup
                    cleanup_error = error
                    lifecycle["cleanup_error"] = {
                        "type": type(error).__name__,
                        "message": str(error)[:512],
                    }
                lifecycle["cleanup_pending"] = communication._cleanup_pending
                self.native_output["lifecycle"] = lifecycle
                if cleanup_error is not None and not failed:
                    raise cleanup_error

    def _validate_saved_outer_contexts(
        self, contexts: Mapping[tuple[int, int], ToyotaWorkflows]
    ) -> None:
        """One native CCommFrameCtrl owns every saved-log target and cleanup."""
        from scripts.native_communication import NativeFrameController

        communication = self._communication
        if communication is None or not isinstance(
            communication.operations, NativeFrameController
        ):
            raise SessionError("Saved-log outer requires its concrete frame controller")
        for context in contexts.values():
            if (
                not isinstance(context, ToyotaWorkflows)
                or context._communication is None
                or context._communication.operations is not communication.operations
            ):
                raise SessionError(
                    "Saved-log targets must share one native frame controller"
                )

    def execute_absolute_pid_logs(
        self,
        logs: Sequence[SavedLogInput],
        *,
        contexts: Mapping[tuple[int, int], ToyotaWorkflows],
    ) -> dict[str, object]:
        """Absolute saved PID Execute with actual log3/check/disconnect1."""
        self._validate_saved_outer_contexts(contexts)
        self._begin()
        with self._logged_connection(3) as lifecycle:
            result = self.absolute_pid_logs(logs, contexts=contexts, begin=False)
            result["lifecycle"] = lifecycle
            result["outer_lifecycle"] = "native"
            self.native_output = result
        return result

    def execute_absolute_routine_logs(
        self,
        logs: Sequence[SavedLogInput],
        *,
        contexts: Mapping[tuple[int, int], ToyotaWorkflows],
    ) -> dict[str, object]:
        """Absolute saved routine Execute with actual log3/check/disconnect1."""
        self._validate_saved_outer_contexts(contexts)
        self._begin()
        with self._logged_connection(3) as lifecycle:
            result = self.absolute_routine_logs(logs, contexts=contexts, begin=False)
            result["lifecycle"] = lifecycle
            result["outer_lifecycle"] = "native"
            self.native_output = result
        return result

    def operation_freeze_p5(self) -> dict[str, object]:
        """OperationP5 Execute3980: log0/check/data/disconnect1/conditional stop."""
        self._begin(source12_verified=True)
        with self._logged_connection(0) as lifecycle:
            result = self.operation_freeze_p5_core(begin=False)
            result["lifecycle"] = lifecycle
            result["outer_lifecycle"] = "native"
            self.native_output = result
        return result

    def each_freeze_p5(
        self, diagnostic: P5Diagnostic, *, log_enabled: bool = False
    ) -> dict[str, object]:
        """Each Execute conditional log14 around the actual selected data flow."""
        if type(log_enabled) is not bool:
            raise TypeError("EachP5 native log flag must be boolean")
        if log_enabled and self.observations.source_version == 12:
            raise ValueError("Original12 Each export has no conditional log flag")
        self._begin(source12_verified=True)
        if not log_enabled:
            result = self._each_freeze_p5_data(diagnostic)
            result["outer_lifecycle"] = (
                "native_source_has_no_log_wrapper"
                if self.observations.source_version == 12
                else "native_log_flag_disabled"
            )
            return result
        with self._comm_log(0x14) as lifecycle:
            result = self._each_freeze_p5_data(diagnostic)
            result["communication_log"] = lifecycle
            result["outer_lifecycle"] = "native_conditional_log"
            self.native_output = result
        return result

    def _each_freeze_p5_data(self, diagnostic: P5Diagnostic) -> dict[str, object]:
        """Standalone Each Execute's selected normal/Subaru/predictive data flow.

        The original conditional communication-log wrapper is separate. A caller
        supplies the concrete input diagnostic with its observed record lists;
        this method does not infer availability from native function presence.
        """
        from scripts.freeze_p5 import P5Diagnostic, P5FreezeState, P5SnapshotRequest

        if not isinstance(diagnostic, P5Diagnostic):
            raise TypeError("EachP5 requires its typed selected input diagnostic")
        _unsigned(diagnostic.code, 0xFFFFFF)
        if (
            len(diagnostic.normal_numbers) > 255
            or len(diagnostic.extended_numbers) > 255
        ):
            raise ValueError("EachP5 record list exceeds native BYTE bound")
        for number in (*diagnostic.normal_numbers, *diagnostic.extended_numbers):
            _unsigned(number, 255)
        original = asdict(diagnostic)
        if len(_workflow_json(original).encode("utf-8")) > 16 * 1024 * 1024:
            raise ValueError("EachP5 input diagnostic exceeds report byte bound")
        self._check()
        communication = self._communication
        if communication is None:
            raise SessionError("EachP5 requires its concrete native selected context")
        subaru = self.observations.source_version == 18 and (
            self.profile.category_record[72] & 0xE0 == 0x20
            or self.profile.category == 0x26B
        )
        state = P5FreezeState(
            self.profile,
            source_build=cast(Literal[12, 18], self.observations.source_version),
            cache=communication.cache,
            subaru=subaru,
        )
        numbers: list[int] = []
        observed = diagnostic.normal_numbers
        for number in observed:
            accepted = (
                number == 1 or 0x10 <= number <= 0x2F and 1 in observed
                if subaru
                else number in (1, 2)
                or 0x10 <= number <= 0x4F
                and 1 in observed
                or 0x50 <= number <= 0x6F
                and 2 in observed
            )
            if accepted and number not in numbers:
                numbers.append(number)
        phases: list[dict[str, object]] = []
        result: dict[str, object] = {
            "native_status": 0,
            "status": "ok",
            "phases": phases,
            "diagnostic": original,
            "outer_lifecycle": "conditional_communication_log_separate",
        }
        self.native_output = result
        if subaru:
            if numbers:
                request = P5SnapshotRequest(diagnostic.code, numbers)
                state.init_freeze_data()
                with self._saved_operation(self):
                    success = state.comm_execute_snapshot((request,))
                    state.analyze_snapshot_received(
                        (request,), create_diagnostics=bool(diagnostic.code)
                    )
                phases.append(
                    {
                        "phase": "subaru_snapshot",
                        "communication_success": success,
                        "retained_numbers": list(request.numbers),
                        "partial": list(state.snapshot_partial),
                    }
                )
                if state.snapshot_partial or state.ignored_errors:
                    result["status"] = "partial"
        else:
            if numbers:
                phases.append(
                    self.each_freeze_p5_core(
                        state,
                        (P5SnapshotRequest(diagnostic.code, numbers),),
                        begin=False,
                    )
                )
            phases.append(
                self.predictive_freeze_p5_core(state, diagnostic.code, begin=False)
            )
        # Both native family branches use the NORMAL base for final display
        # ordering and timestamp flag calculation, even for Subaru-produced data.
        display = P5FreezeState(
            self.profile,
            source_build=cast(Literal[12, 18], self.observations.source_version),
            cache=communication.cache,
        )
        for item in state.diagnostics:
            self._check()
            display.sort_display_order(item)
            display.set_timestamp_odometer_flags(item)
        state.diagnostics[:] = [
            item for item in state.diagnostics if item.existence_flags or item.status
        ]
        selected = state.diagnostic(diagnostic.code)
        if selected is not None:
            result["diagnostic"] = asdict(selected)
        result["matched"] = selected is not None
        if any(phase.get("status") == "partial" for phase in phases):
            result["status"] = "partial"
        self.native_output = result
        return result

    def operation_freeze_p5_core(self, *, begin: bool = True) -> dict[str, object]:
        """OperationP5 2840 data phase; outer log/connection lifecycle separate."""
        if type(begin) is not bool:
            raise TypeError("OperationP5 phase control must be boolean")
        if begin:
            self._begin(source12_verified=True)
        else:
            self._check()
        self.session._begin()
        communication = self._communication
        if communication is None:
            raise SessionError("OperationP5 requires its typed native communication")
        selected = self._frames(0x66)[0]
        name = "operation-p5-rewritten-frame"
        self.session.commands[name] = CommandSpec(
            selected.frame,
            selected=selected,
            provenance=selected.provenance,
            extended=True,
        )
        output: list[dict[str, object]] = []
        omissions: list[dict[str, object]] = []
        result: dict[str, object] = {
            "native_status": 0,
            "status": "ok",
            "trip_times": output,
            "omissions": omissions,
            "phase": "data_core",
            "outer_lifecycle": "unconfirmed",
        }
        self.native_output = result
        masked = {
            0x91010009,
            0x90020321,
            0x90020323,
            0xA0040201,
            0xA0040202,
            0x90020327,
            0x91020320,
            0x91020310,
            0x91020322,
        }

        def read(request: bytes, *, no_init: bool) -> bytes:
            with self._saved_operation(self, no_init=no_init):
                # This native consumer rewrites selected function66's body.
                # Original frame provenance/settings remain the cache boundary.
                spec = self.session.commands[name]
                return self.session._native_call(spec, request)

        # Original18 .rdata A1D4..A203, source-hash-bound in private evidence.
        for request in (
            b"\x22\x10\x07",
            b"\x22\x1f\x01",
            b"\x22\x1f\x02",
            b"\x22\x1f\x03",
        ):
            read(request, no_init=True)
        reply = read(b"\xab\x11", no_init=False)
        count = (len(reply) - 2) // 2
        if count < 1:
            raise ToyotaCodecError("OperationP5 operation list empty", 0x90040501)
        operations = [
            int.from_bytes(reply[at : at + 2], "big")
            for at in range(2, 2 + count * 2, 2)
        ]
        for operation in operations:
            self._check()
            try:
                reply = read(b"\xab\x12" + operation.to_bytes(2, "big"), no_init=False)
            except ToyotaCodecError as error:
                if error.code not in masked:
                    raise
                omissions.append({"operation": operation, "native_code": error.code})
                result["status"] = "partial"
                continue
            if len(reply) < 4:
                raise SessionError("Native OperationP5 snapshot list underflows length")
            end = 4 + ((len(reply) - 4) // 2) * 2
            snapshots = sorted(
                {int.from_bytes(reply[at : at + 2], "big") for at in range(4, end, 2)}
            )
            previous_failure = False
            for snapshot in snapshots:
                self._check()
                request = (
                    b"\xab\x13"
                    + operation.to_bytes(2, "big")
                    + snapshot.to_bytes(2, "big")
                )
                try:
                    reply = read(request, no_init=False)
                except ToyotaCodecError as error:
                    if error.code not in masked:
                        raise
                    omissions.append(
                        {
                            "operation": operation,
                            "snapshot": snapshot,
                            "native_code": error.code,
                        }
                    )
                    result["status"] = "partial"
                    if previous_failure:
                        break
                    previous_failure = True
                    continue
                previous_failure = False
                parsed = parse_operation_p5_reply(
                    reply, source_version=self.observations.source_version
                )
                if parsed["status"] == "partial":
                    result["status"] = "partial"
                    omissions.append(
                        {"operation": operation, "snapshot": snapshot, "parse": parsed}
                    )
                values = parsed["trip_time_words"]
                if 0 < snapshot <= 255 and values:
                    output.append(
                        {
                            "operation": operation,
                            "snapshot": snapshot,
                            "raw_trip_time_words": values,
                            "unit": None,
                            "metadata": "native_constructor_defaults",
                        }
                    )
                    # The native legacy signal has no assigned name/unit/scale.
                    result["status"] = "partial"
        return result

    def operation_freeze_ics02(self) -> dict[str, object]:
        """The five original ICS02 Execute plans; no OperationP4 alias."""
        self._begin(source12_verified=True)
        plans = (
            (129, 52, 55, 4001),
            (128, 53, 56, 4000),
            (132, 54, 57, 4002),
            (133, 58, 59, 4003),
            (134, 75, 76, 4004),
        )
        if self.observations.source_version == 12:
            plans = plans[:4]
        operations: list[dict[str, object]] = []
        result: dict[str, object] = {
            "native_status": 0,
            "operations": operations,
            "native_fields": {"34": 0},
            "status": "ok",
        }
        probe_cache: dict[bytes, bytes | ToyotaCodecError] = {}
        data_cache: dict[bytes, bytes | ToyotaCodecError] = {}
        budget = [0]
        omitted = {
            0x91010009,
            0x90020321,
            0x90020323,
            0xA0040201,
            0xC0040001,
            0xA0040202,
            0x90020327,
            0x91020320,
            0x91020310,
            0x91020322,
        }
        for selector, probe_signal, measurement_signal, label_category in plans:
            probe = self._operation_freezes(probe_signal, exact=True)[0]
            rows = self.profile.operation_freeze_records(selector)
            if not rows:
                raise ToyotaCodecError("ICS02 operation group empty", 0xC0040101)
            for ordinal, row in enumerate(rows, 1):
                self._check()
                number, control = row[5], row[7]
                try:
                    payload = self._operation_read(
                        probe, number, probe_cache, control=control
                    )
                except ToyotaCodecError as error:
                    if error.code in omitted:
                        continue
                    raise
                if not self._operation_pattern_matches(
                    probe, extract_bits(payload, *struct.unpack_from("<HH", probe, 62))
                ):
                    continue
                masks = self._support().support_bits(1)
                groups = [
                    r for r in self.profile.records(0) if r[8] == measurement_signal
                ]
                if len(groups) != 1:
                    raise ToyotaCodecError("ICS02 measurement group count", 0xC0040102)
                checks = [
                    r
                    for r in self.profile.records(1)
                    if word(r, 0) == word(groups[0], 4)
                ]
                if not checks:
                    raise ToyotaCodecError("ICS02 measurement checks empty", 0xC0040101)
                samples = []
                missing_pid = False
                all_unsupported = True
                wire_omitted = False
                for check in checks:
                    freezes = [
                        r
                        for r in self.profile.records(10)
                        if word(r, 56) == word(check, 2)
                    ]
                    if len(freezes) != 1:
                        raise ToyotaCodecError(
                            "ICS02 measurement Freeze count", 0xC0040102
                        )
                    freeze = freezes[0]
                    if not freeze[78] & 2:
                        continue
                    try:
                        supported = self._ics_support(freeze, masks)
                    except ToyotaCodecError as error:
                        if error.code != 0x90040501:
                            raise
                        missing_pid = True
                        supported = False
                    try:
                        payload = self._operation_read(
                            freeze, number, data_cache, control=control
                        )
                    except ToyotaCodecError as error:
                        if error.code == 0xA0040202:
                            payload = None
                        elif error.code in omitted or missing_pid:
                            wire_omitted = True
                            break
                        elif not supported:
                            # Native discards an unselected value even when
                            # this request returned an otherwise fatal code.
                            continue
                        else:
                            raise
                    if missing_pid:
                        break
                    if supported:
                        all_unsupported = False
                        samples.append(
                            self._operation_render(freeze, payload, budget=budget)
                        )
                if wire_omitted:
                    continue
                extended = False
                if (
                    self.observations.source_version == 18
                    and self.profile.category == 469
                ):
                    bit_probe = bytearray(84)
                    bit_probe[79] = 16
                    struct.pack_into("<HH", bit_probe, 62, 18, 18)
                    try:
                        extended = not self._ics_support(bytes(bit_probe), masks)
                    except ToyotaCodecError as error:
                        if error.code != 0x90040501:
                            raise
                        extended = True
                if extended:
                    cast(dict, result["native_fields"])["34"] = 1
                try:
                    fields, _any = self._ics_auxiliary(
                        number, control, masks, extended=extended, budget=budget
                    )
                except ToyotaCodecError as error:
                    if error.code in omitted:
                        continue
                    raise
                if missing_pid or all_unsupported:
                    continue
                management = self.profile.catalog.management
                if 16 not in management.sections:
                    raise ToyotaCodecError(
                        "ICS02 label category resource absent", 0xA0030107
                    )
                categories = correspondence_rows(
                    management, 16, self.profile.exception_ids
                )
                category = next(
                    (r for r in categories if word(r, 68) == label_category), None
                )
                if category is None:
                    raise ToyotaCodecError("ICS02 label category empty", 0xC0040101)
                name_id = struct.unpack_from("<I", category, 60)[0]
                label = self.profile.catalog.language.resolve(name_id)
                budget[0] += len(label.encode("utf-8")) + 128
                if budget[0] > 16 * 1024 * 1024:
                    raise SessionError("Operation output exceeds local byte budget")
                operations.append(
                    {
                        "frame_number": number,
                        "control": control,
                        "ordinal": ordinal & 255,
                        "label": label,
                        "name_id": name_id,
                        "native_fields": fields,
                        "signals": samples,
                    }
                )
                if (
                    any(
                        sample["status"] == "unresolved" or "native_default" in sample
                        for sample in samples
                    )
                    or "unwritten_signals" in fields
                ):
                    result["status"] = "partial"
        return result

    def _active_monitor_ids(self) -> tuple[int, ...]:
        """Native1450→1C70→2160→2530 selected active-test metadata inputs."""
        support = self._support()
        family = (
            "subaru"
            if self.observations.source_version == 18
            and self.profile.category_record[72] & 0xE0 == 0x20
            else "normal"
        )
        enabled = support.data_ids(family=family).identifiers
        if 62 not in self.profile.database.sections:
            raise ToyotaCodecError("DatamonitorP5 resource absent", 0xA0030107)
        rows = self.profile.records(62)
        if len(rows) > 32767:
            raise ToyotaCodecError(
                "Native active monitor row count exceeds signed WORD", 0xA0030110
            )
        normal, special = [], []
        for index, row in enumerate(rows):
            self._check()
            flags = struct.unpack_from("<I", row, 32)[0]
            signal = word(row, 36)
            if flags & 0x10:
                if flags & 0x40:
                    special.append((index, signal))
            elif support.check_support_pid(
                signal, enabled_dids=enabled, raw_support=True
            ):
                normal.append((index, signal, flags))
        supported = {signal for _, signal, _ in normal}
        selected = [(index, signal) for index, signal, flags in normal if flags & 0x40]
        existing = {word(row, 36) for row in rows}
        for index, signal in special:
            self._check()
            if 26 not in self.profile.database.sections:
                raise ToyotaCodecError("Active MultiPID resource absent", 0xA0030107)
            children = self.profile.multi_pid_records(signal)
            if children and all(
                word(child, 4) in existing
                and (word(child, 4) in supported or child[9] == 1)
                for child in children
            ):
                selected.append((index, signal))
        # Native2530 merges two source-order lists using original DB ordinal.
        selected.sort(key=lambda item: item[0])
        return tuple(signal for _, signal in selected)

    def active_test_monitors(self) -> dict[str, object]:
        """Native active-test P5 metadata producer; it starts no polling stream."""
        self._begin(source12_verified=True)
        selected = self._active_monitor_ids()
        lsb = SignalLSB(
            self._support(),
            source_build=12 if self.observations.source_version == 12 else 18,
        )
        signals = []
        unit_name, unit_id = "", 0
        retained = 0
        for signal in selected:
            self._check()
            row = next(
                row for row in self.profile.records(62) if word(row, 36) == signal
            )
            if 13 not in self.profile.database.sections:
                raise ToyotaCodecError(
                    "Active monitor physical resource absent", 0xA0030107
                )
            physical = next(
                (
                    item
                    for item in self.profile.records(13)
                    if word(item, 12) == word(row, 42)
                ),
                None,
            )
            defaults = []
            if physical is None:
                # Actual2940 empty group branch2EFA, distinct from missing resource.
                multiplier, divisor, offset, precision = 1, 1, 0, 0
                defaults.append("physical_empty_group")
            else:
                multiplier, divisor, offset = struct.unpack_from("<III", physical)
                precision = physical[21]
                if 15 not in self.profile.database.sections:
                    raise ToyotaCodecError(
                        "Active monitor unit resource absent", 0xA0030107
                    )
                unit = next(
                    (
                        item
                        for item in self.profile.records(15)
                        if word(item, 4) == word(physical, 14)
                    ),
                    None,
                )
                if unit is None:
                    defaults.append("unit_retained_from_previous_record")
                else:
                    unit_name = self.profile.catalog.language.resolve(
                        struct.unpack_from("<I", unit)[0]
                    )
                    unit_id = word(unit, 6)
            lower, upper = struct.unpack_from("<II", row, 12)
            begin, end = struct.unpack_from("<HH", row, 44)
            changed = lsb.p5(
                signal,
                exponent=precision,
                width=(end - begin + 1) & 65535,
                multiplier=multiplier,
                divisor=divisor,
                threshold=lower,
            )
            multiplier, divisor, lower = changed.values
            name = self.profile.catalog.language.resolve(
                struct.unpack_from("<I", row, 24)[0]
            )
            retained += len(name.encode("utf-8")) + len(unit_name.encode("utf-8")) + 256
            if retained > WORKFLOW_MAX_BYTES:
                raise SessionError("Active monitor metadata exceeds local byte budget")
            signals.append(
                {
                    "signal_id": signal,
                    "name": name,
                    "short_name": "",
                    "unit": unit_name,
                    "unit_id": unit_id,
                    "multiplier": multiplier,
                    "divisor": divisor,
                    "offset": offset,
                    "precision": precision,
                    "native_fields": {
                        "3c": struct.unpack_from("<I", row, 28)[0],
                        "40": struct.unpack_from("<I", row, 20)[0],
                        "54": lower,
                        "58": upper,
                        "5c": struct.unpack_from("<I", row, 4)[0],
                        "60": struct.unpack_from("<I", row, 8)[0],
                    },
                    "lsb_changed": changed.changed,
                    "native_defaults": defaults,
                }
            )
        return {
            "native_status": 0,
            "status": "partial"
            if any(item["native_defaults"] for item in signals)
            else "ok",
            "signals": signals,
        }

    def multi_freeze_p4(
        self, signal_ids: Sequence[int], alias: int, *, frame_filter: bytes = b""
    ) -> dict[str, object]:
        """Selected GetMultiFrzFrmDatP4 Execute; frame filter uses encoded numbers."""
        _unsigned(alias, 255)
        if (
            len(signal_ids) > 65535
            or type(frame_filter) is not bytes
            or len(frame_filter) > 255
        ):
            raise ValueError("Multi-freeze inputs exceed native bounded lists")
        for signal in signal_ids:
            _unsigned(signal, 65535)
        self._begin(source12_verified=True)
        items: list[dict[str, object]] = []
        unresolved = False
        result: dict[str, object] = {"native_status": 0, "signals": items}
        if not signal_ids:
            return result
        info = self.session.multi_freeze_info(
            self.profile, self.observations, support_cache=self._support()
        )
        result["info"] = info
        if info["supported"] is not True:
            return result
        count, first, last = (info[key] for key in ("out1", "out2", "out3"))
        if type(count) is not int or type(first) is not int or type(last) is not int:
            raise SessionError("Supported multi-freeze info has unwritten outputs")
        if not count or not 0 < last < 0x80000000:
            return result
        start, end = _multi_frame_index(first), _multi_frame_index(last)
        result.update(native_start_index=start, native_end_index=end)
        response_cache: dict[bytes, bytes | ToyotaCodecError] = {}
        retained = 0
        omitted = {
            0x91010009,
            0x90020321,
            0x90020323,
            0xA0040201,
            0xC0040001,
            0xA0040202,
            0x90020327,
            0x91020320,
            0x91020310,
            0x91020322,
        }
        for signal in signal_ids:
            self._check()
            if 10 not in self.profile.database.sections:
                raise ToyotaCodecError("Freeze resource absent", 0xA0030107)
            rows = [row for row in self.profile.records(10) if word(row, 56) == signal]
            if len(rows) != 1:
                raise ToyotaCodecError("Multi-freeze requires one Freeze", 0xC0040102)
            freeze = rows[0]
            metadata = self._freeze_metadata(freeze)
            retained += len(metadata.name.encode("utf-8")) + len(
                metadata.unit.encode("utf-8")
            )
            retained += sum(
                len(label.encode("utf-8")) + 32 for _, label, _, _ in metadata.patterns
            )
            if retained > 16 * 1024 * 1024:
                raise SessionError("Multi-freeze metadata exceeds local byte budget")
            samples = []
            item: dict[str, object] = {
                "signal_id": signal,
                "name": metadata.name,
                "unit": metadata.unit,
                "samples": samples,
            }
            items.append(item)
            encoded = (first & 0xF0) | (alias & 15)
            for index in range(start, end + 1):
                self._check()
                number = encoded
                encoded = (encoded + 0x10) & 255
                if frame_filter and number not in frame_filter:
                    continue
                names = self._register(0x11)
                if len(names) != 1:
                    raise ToyotaCodecError("P4 freeze requires one frame", 0xC0040102)
                positions = self.observations.pid_positions
                try:
                    payload = self.session.freeze_p4(
                        names[0],
                        freeze,
                        number,
                        None if positions is None else positions.get(freeze[79], b""),
                        response_cache=response_cache,
                        support_cache=self._support() if positions is None else None,
                    )
                except ToyotaCodecError as error:
                    if error.code in omitted:
                        continue
                    raise
                raw = extract_bits(payload, metadata.start_bit, metadata.end_bit)
                rendered = render_signal(
                    raw,
                    selector=metadata.selector,
                    sign_mode=metadata.sign_mode,
                    bits=metadata.end_bit - metadata.start_bit + 1,
                    multiplier=metadata.multiplier,
                    divisor=metadata.divisor,
                    offset=metadata.offset,
                    precision=metadata.precision,
                    patterns=tuple(
                        (low, label, low, high)
                        for _, label, low, high in metadata.patterns
                    ),
                    minimum_raw=metadata.extended[1],
                    maximum_raw=metadata.extended[2],
                    extended=(metadata.extended,),
                )
                samples.append(
                    {"frame_number": number, "native_index": index, **rendered}
                )
                retained += 128 + len(str(rendered["display"]).encode("utf-8"))
                if retained > 16 * 1024 * 1024:
                    raise SessionError("Multi-freeze results exceed local byte budget")
                unresolved |= rendered["status"] == "unresolved"
        result["status"] = "partial" if unresolved else "ok"
        return result

    def is_psd_freeze(
        self, *, native_label: WorkflowLabel | None = None
    ) -> dict[str, object]:
        """PSD checks feature7/45/A..C and actual per-frame supported Freeze data."""
        self._begin(source12_verified=True)
        values = []
        for leaf in (10, 11, 12):
            present, value = self.observations.function(7, 0x45, leaf)
            if not present:
                raise ToyotaCodecError("PSD function metadata is absent", 0xC0040601)
            values.append(value & 255)
        count, number, last = values
        if not count:
            return {"native_status": 0, "frames": []}
        output = []
        support = self._support()
        response_cache: dict[bytes, bytes | ToyotaCodecError] = {}
        omitted = {
            0x91010009,
            0x90020321,
            0x90020323,
            0xA0040201,
            0xC0040001,
            0xA0040202,
            0x90020327,
            0x91020320,
            0x91020310,
            0x91020322,
        }
        while number <= last:
            self._check()
            masks = support.support_bits(1)
            enabled = support.enabled_pids(family="p4", kind=3, control=number)
            if 10 not in self.profile.database.sections:
                raise ToyotaCodecError(
                    "Selected PSD Freeze resource is absent", 0xA0030107
                )
            rows = self.profile.records(10)
            if not rows:
                raise ToyotaCodecError("Selected PSD Freeze group is empty", 0xC0040101)
            selected = next(
                (
                    row
                    for row in rows
                    if row[78] & 2 and self._freeze_supported_p4(row, enabled, masks)
                ),
                None,
            )
            if selected is not None:
                names = self._register(0x11)
                if len(names) != 1:
                    raise ToyotaCodecError(
                        "PSD freeze requires one data frame", 0xC0040102
                    )
                pid = selected[79]
                try:
                    if pid not in masks:
                        raise ToyotaCodecError(
                            "PSD data PID positions are absent", 0xC0040001
                        )
                    self.session.freeze_p4(
                        names[0],
                        selected,
                        number,
                        masks[pid],
                        response_cache=response_cache,
                    )
                except ToyotaCodecError as error:
                    if error.code not in omitted:
                        raise
                else:
                    if (
                        not isinstance(native_label, WorkflowLabel)
                        or native_label.source_version
                        != self.observations.source_version
                    ):
                        raise SessionError("PSD original module label was not resolved")
                    output.append({"frame_number": number, "label": native_label.text})
            # Native increments a BYTE; last=FF repeats until the host deadline.
            number = (number + 1) & 255
        frames = [
            {**row, "ordinal": (50 + index) & 255}
            for index, row in enumerate(reversed(output))
        ]
        return {
            "native_status": 0,
            "frames": frames,
            "label_source": None
            if native_label is None
            else {
                "sha256": native_label.source_sha256,
                "path": native_label.source_path,
                "synthetic": native_label.synthetic,
            },
        }


WORKFLOW_SCHEMA = "techstream-toyota-workflow-v1"
WORKFLOW_MAX_BYTES = 16 * 1024 * 1024


def _workflow_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _workflow_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate workflow recording field")
        result[key] = value
    return result


def _workflow_hex(value: object, maximum: int = 65535) -> bytes:
    if not isinstance(value, str) or len(value) > maximum * 2:
        raise ValueError("Invalid workflow recorded byte field")
    result = bytes.fromhex(value)
    if result.hex() != value:
        raise ValueError("Workflow byte fields require canonical lowercase hex")
    return result


class WorkflowRecording:
    """Exact native primitive chronology over an explicitly selected profile."""

    def __init__(
        self,
        profile: VehicleProfile,
        document: dict[str, Any],
        *,
        cancelled: Callable[[], bool] = lambda: False,
    ):
        pending: list[tuple[Any, int]] = [(document, 0)]
        retained, nodes = 0, 0
        while pending:
            value, depth = pending.pop()
            nodes += 1
            if depth > 16 or nodes > 1000000:
                raise ValueError("Workflow JSON structure exceeds local bounds")
            if type(value) is str:
                if not value.isascii() or any(ord(c) < 32 for c in value):
                    raise ValueError("Workflow native fields require printable ASCII")
                retained += len(value)
                if retained > WORKFLOW_MAX_BYTES:
                    raise ValueError("Workflow native fields exceed byte budget")
            elif type(value) in (dict, list):
                if len(value) > 100000:
                    raise ValueError("Workflow container exceeds native event bound")
                if isinstance(value, dict):
                    pending.extend((key, depth + 1) for key in value)
                    pending.extend((child, depth + 1) for child in value.values())
                else:
                    pending.extend((child, depth + 1) for child in value)
            elif type(value) not in (type(None), bool, int, float):
                raise TypeError("Workflow recording requires plain JSON values")
        encoded = _workflow_json(document).encode()
        if len(encoded) > WORKFLOW_MAX_BYTES:
            raise ValueError("Workflow recording exceeds byte budget")
        document = json.loads(encoded)
        if (
            not isinstance(document, dict)
            or set(document)
            != {"schema", "source", "context", "events", "operation", "arguments"}
            or document["schema"] != WORKFLOW_SCHEMA
        ):
            raise ValueError("Unsupported workflow recording fields/schema")
        if document["source"] not in ("authored_synthetic", "recorded_unverified"):
            raise ValueError("Workflow recording requires explicit provenance")
        context = document["context"]
        if not isinstance(context, dict) or set(context) != {
            "ecu",
            "category",
            "category_record",
            "exceptions",
            "database_sha256",
            "management_sha256",
            "native_id",
            "bus_id",
            "source_build",
            "functions",
            "targets",
            "pid_positions",
            "mode_seed",
            "limits",
        }:
            raise ValueError("Invalid workflow selected context fields")
        expected = (
            profile.category,
            profile.category_record.hex(),
            list(profile.exception_ids),
            profile.database.sha256,
            profile.catalog.management.sha256,
        )
        actual = tuple(
            context[key]
            for key in (
                "category",
                "category_record",
                "exceptions",
                "database_sha256",
                "management_sha256",
            )
        )
        if _workflow_json(actual) != _workflow_json(expected):
            raise ValueError(
                "Workflow recording belongs to a different selected profile"
            )
        ecu = context["ecu"]
        if (
            not isinstance(ecu, str)
            or not 1 <= len(ecu) <= 64
            or any(
                c
                not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-"
                for c in ecu
            )
        ):
            raise ValueError("Invalid workflow ECU label")
        functions = context["functions"]
        if functions is not None:
            if not isinstance(functions, list) or len(functions) > 65535:
                raise ValueError("Invalid workflow function cache")
            function_map = {}
            for entry in functions:
                if not isinstance(entry, list) or len(entry) != 4:
                    raise ValueError("Function cache entry requires four native values")
                key = tuple(entry[:3])
                if key in function_map:
                    raise ValueError("Duplicate workflow function cache key")
                function_map[key] = entry[3]
        else:
            function_map = None
        targets = context["targets"]
        if (
            not isinstance(targets, list)
            or len(targets) > 65535
            or any(not isinstance(row, list) or len(row) != 2 for row in targets)
        ):
            raise ValueError("Invalid workflow target observations")
        positions = context["pid_positions"]
        position_map = None
        if positions is not None:
            if not isinstance(positions, dict) or len(positions) > 256:
                raise ValueError("Invalid workflow PID position observations")
            position_map = {}
            for key, value in positions.items():
                if not isinstance(key, str) or not key.isascii() or not key.isdecimal():
                    raise ValueError("PID position key must be canonical decimal")
                pid = int(key)
                if str(pid) != key or not 0 <= pid <= 255:
                    raise ValueError("PID position key outside native byte bounds")
                raw = _workflow_hex(value, 255)
                if not raw:
                    raise ValueError("Observed PID positions cannot be empty")
                position_map[pid] = raw
        self.observations = WorkflowObservations(
            context["native_id"],
            context["bus_id"],
            function_map,
            targets=tuple(tuple(row) for row in targets),
            pid_positions=position_map,
            mode_seed=None
            if context["mode_seed"] is None
            else _workflow_hex(context["mode_seed"], 16),
            source_version=context["source_build"],
        )
        limits = context["limits"]
        if not isinstance(limits, dict) or set(limits) != {"seconds", "exchanges"}:
            raise ValueError("Workflow requires explicit host limits")
        if (
            type(limits["seconds"]) not in (int, float)
            or not 0 < limits["seconds"] <= 3600
        ):
            raise ValueError("Workflow deadline outside local bound")
        if (
            type(limits["exchanges"]) is not int
            or not 0 < limits["exchanges"] <= 100000
        ):
            raise ValueError("Workflow exchange limit outside local bound")
        self.limits = Limits(**limits)
        events = document["events"]
        if not isinstance(events, list) or len(events) > 100000:
            raise ValueError("Invalid workflow event count")
        transactions = []
        operations = {
            "exchange",
            "support",
            "send",
            "receive",
            "native_send",
            "get_mode",
            "set_mode",
        }
        for event in events:
            if not isinstance(event, dict) or set(event) != {
                "operation",
                "arguments",
                "status",
                "response",
            }:
                raise ValueError("Invalid workflow event fields")
            op, args, status = event["operation"], event["arguments"], event["status"]
            if (
                op not in operations
                or not isinstance(args, dict)
                or args.get("ecu") != ecu
            ):
                raise ValueError("Invalid workflow primitive operation/context")
            query_fields = {
                "ecu",
                "request",
                "function_record",
                "communication_record",
                "settings_record",
            }
            fields = (
                {"ecu", "request"}
                if op == "exchange"
                else query_fields
                if op == "support"
                else query_fields | {"parameters"}
                if op in ("send", "receive")
                else {"ecu", "native_operation", "arguments"}
                if op == "native_send"
                else {"ecu"}
                if op == "get_mode"
                else {"ecu", "mode", "cleanup"}
            )
            if set(args) != fields:
                raise ValueError("Unexpected native primitive argument fields")
            if op in ("support", "send", "receive"):
                for field_name in query_fields - {"ecu"}:
                    _workflow_hex(args[field_name])
            if op in ("send", "receive") and (
                not isinstance(args["parameters"], list)
                or len(args["parameters"]) != 4
                or any(
                    type(value) is not int or not -0x80000000 <= value <= 0xFFFFFFFF
                    for value in args["parameters"]
                )
            ):
                raise ValueError(
                    "Native stream primitive requires four bounded arguments"
                )
            if op == "set_mode" and (
                len(_workflow_hex(args["mode"], 16)) != 16
                or type(args["cleanup"]) is not bool
            ):
                raise ValueError(
                    "SetDiagnosticMode requires16 bytes and explicit cleanup state"
                )
            if op == "native_send":
                values = args["arguments"]
                if not isinstance(values, list) or len(values) != 7:
                    raise ValueError("Native send requires seven ordered arguments")
                call = NativeFrameSend(
                    args["native_operation"],
                    values[0],
                    None if values[1] is None else _workflow_hex(values[1]),
                    values[3],
                    values[4],
                    values[5],
                    values[6],
                )
                if type(values[2]) is not int or values[2] != call.arguments[2]:
                    raise ValueError("Native send recorded length contradicts request")
            _unsigned(status, 0xFFFFFFFF)
            response = _workflow_hex(event["response"])
            if op in ("exchange", "support", "receive"):
                request = "" if op == "receive" else args.get("request")
                _workflow_hex(request)
                row = {"ecu": ecu, "request": request}
                if status:
                    row.update(status=status, partial_response=response.hex())
                else:
                    row["response"] = response.hex()
                transactions.append(row)
            elif op == "get_mode":
                if len(response) > 16 or not status and len(response) != 16:
                    raise ValueError(
                        "Successful GetDiagnosticMode requires16 recorded bytes"
                    )
            elif response:
                raise ValueError("Void/send primitive cannot contain response bytes")
        self.pdus = (
            NativeReplay(
                {
                    "schema": "techstream-native-exchange-v1",
                    "source": document["source"],
                    "ecus": [ecu],
                    "support": {},
                    "transactions": transactions,
                },
                cancelled,
            )
            if transactions
            else None
        )
        self.events, self.position = tuple(events), 0
        self.ecu, self.source = ecu, document["source"]
        self.operation, self.arguments = document["operation"], document["arguments"]
        self.cancelled = cancelled
        self.sha256 = hashlib.sha256(encoded).hexdigest()
        self.size = len(encoded)

    def _take(
        self, operation: str, arguments: dict[str, Any], *, cleanup: bool = False
    ) -> dict[str, Any]:
        if not cleanup and self.cancelled():
            raise Cancelled("Workflow replay cancelled")
        if self.position >= len(self.events):
            raise ValueError("Workflow replay exhausted")
        event = self.events[self.position]
        if event["operation"] != operation or _workflow_json(
            event["arguments"]
        ) != _workflow_json(arguments):
            raise ValueError(f"Workflow primitive mismatch at event{self.position}")
        self.position += 1
        return event

    @staticmethod
    def _query(query: SupportQuery) -> dict[str, Any]:
        return {
            "ecu": query.ecu,
            "request": query.request.hex(),
            "function_record": query.selected.function_record.hex(),
            "communication_record": query.selected.communication_record.hex(),
            "settings_record": query.selected.settings_record.hex(),
        }

    def _pdu(self, ecu: str, request: bytes) -> bytes:
        if self.pdus is None:
            raise ValueError("Workflow recording has no PDU event")
        return self.pdus.exchange(ecu, request)

    def exchange(self, ecu: str, request: bytes) -> bytes:
        self._take("exchange", {"ecu": ecu, "request": request.hex()})
        return self._pdu(ecu, request)

    def support(self, query: SupportQuery) -> bytes:
        self._take("support", self._query(query))
        return self._pdu(query.ecu, query.request)

    def send(self, call: SupportSend) -> int:
        event = self._take(
            "send",
            {
                **self._query(call.query),
                "parameters": [
                    call.parameter4,
                    call.parameter5,
                    call.parameter6,
                    call.parameter7,
                ],
            },
        )
        return event["status"]

    def receive(self, call: SupportReceive) -> tuple[int, bytes]:
        event = self._take(
            "receive",
            {
                **self._query(call.query),
                "parameters": [
                    call.capacity,
                    call.parameter4,
                    call.parameter5,
                    call.wait_ms,
                ],
            },
        )
        try:
            return 0, self._pdu(call.query.ecu, b"")
        except NativeStatus as error:
            if error.code != event["status"]:
                raise ValueError(
                    "Workflow recorded native status correlation failed"
                ) from error
            return error.code, error.reply

    def native_send(self, ecu: str, call: NativeFrameSend) -> int:
        event = self._take(
            "native_send",
            {
                "ecu": ecu,
                "native_operation": call.operation,
                "arguments": [
                    call.command_id,
                    None if call.request is None else call.request.hex(),
                    call.arguments[2],
                    call.parameter4,
                    call.parameter5,
                    call.parameter6,
                    call.parameter7,
                ],
            },
        )
        return event["status"]

    def get_mode(self, ecu: str) -> bytes:
        event = self._take("get_mode", {"ecu": ecu})
        response = _workflow_hex(event["response"], 16)
        if event["status"]:
            raise NativeStatus(event["status"], response)
        return response

    def set_mode(self, ecu: str, mode: bytes) -> None:
        self._set_mode(ecu, mode, cleanup=False)

    def cleanup_set_mode(self, ecu: str, mode: bytes) -> None:
        self._set_mode(ecu, mode, cleanup=True)

    def _set_mode(self, ecu: str, mode: bytes, *, cleanup: bool) -> None:
        event = self._take(
            "set_mode",
            {"ecu": ecu, "mode": mode.hex(), "cleanup": cleanup},
            cleanup=cleanup,
        )
        if event["status"]:
            raise NativeStatus(event["status"])

    def assert_complete(self) -> None:
        if self.position != len(self.events):
            raise ValueError("Workflow recording has unconsumed native events")
        if self.pdus is not None:
            self.pdus.assert_complete()


def replay_workflow(
    profile: VehicleProfile,
    recording_path: Path,
    *,
    cancelled: Callable[[], bool] = lambda: False,
    psd_module: Path | None = None,
) -> dict[str, object]:
    """Replay an explicit selected workflow without opening a device/provider."""
    path = recording_path.resolve(strict=True)
    raw = read_regular(path, limit=WORKFLOW_MAX_BYTES)
    document = json.loads(raw, object_pairs_hook=_workflow_object)
    recording = WorkflowRecording(profile, document, cancelled=cancelled)
    workflow = ToyotaWorkflows.from_profile(
        profile,
        recording.exchange,
        ecu=recording.ecu,
        observations=recording.observations,
        native_send=recording.native_send,
        native_get_mode=recording.get_mode,
        native_set_mode=recording.set_mode,
        native_cleanup_set_mode=recording.cleanup_set_mode,
        support_exchange=recording.support,
        support_stream=recording,
        cancelled=cancelled,
        limits=recording.limits,
    )
    methods = {
        "clear_dtc": workflow.clear_dtc,
        "clear_dtc_mazda": workflow.clear_dtc_mazda,
        "clear_dtc_psa": workflow.clear_dtc_psa,
        "clear_dtc_p4": workflow.clear_dtc_p4,
        "clear_dtc_vgrs": workflow.clear_dtc_vgrs,
        "is_absolute_freeze": workflow.is_absolute_freeze,
        "is_absolute_freeze_p4": workflow.is_absolute_freeze_p4,
        "is_absolute_freeze_dk": workflow.is_absolute_freeze_dk,
        "is_multi_freeze": workflow.is_multi_freeze,
        "is_multi_freeze_v2": workflow.is_multi_freeze_v2,
        "multi_freeze_p4": workflow.multi_freeze_p4,
        "active_test_monitors": workflow.active_test_monitors,
        "operation_freeze_p4": workflow.operation_freeze_p4,
        "operation_freeze_ics02": workflow.operation_freeze_ics02,
    }
    arguments = recording.arguments
    if not isinstance(arguments, dict):
        raise TypeError("Workflow arguments must be an explicit object")
    failure = None
    result: dict[str, object] = {}
    try:
        if recording.operation == "is_psd_freeze":
            if arguments:
                raise ValueError("PSD recording does not supply arbitrary source paths")
            result = workflow.is_psd_freeze(
                native_label=None if psd_module is None else load_psd_label(psd_module)
            )
        else:
            method = methods.get(recording.operation)
            if method is None:
                raise ValueError("Unimplemented/unknown selected workflow operation")
            if recording.operation == "multi_freeze_p4" and "frame_filter" in arguments:
                arguments["frame_filter"] = _workflow_hex(
                    arguments["frame_filter"], 255
                )
            result = method(**arguments)
        recording.assert_complete()
    # Session cleanup completes before provider failures cross this JSON boundary.
    except (Exception, KeyboardInterrupt, BaseExceptionGroup) as error:  # noqa: BLE001
        result = {"native_output": dict(workflow.native_output)}
        failure = {
            "type": type(error).__name__,
            "message": str(error)[:512],
            "native_code": error.code if isinstance(error, ToyotaCodecError) else None,
        }
        if isinstance(error, BaseExceptionGroup):
            failure["children"] = [
                {
                    "type": type(child).__name__,
                    "message": str(child)[:512],
                    "native_code": child.code
                    if isinstance(child, ToyotaCodecError)
                    else None,
                }
                for child in error.exceptions[:16]
            ]
    return {
        "schema": "techstream-toyota-workflow-report-v1",
        "source": recording.source,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "operation": recording.operation,
        "result": result,
        "status": "ok"
        if failure is None
        else "cancelled"
        if failure["type"] in ("Cancelled", "KeyboardInterrupt")
        else "failed",
        "error": failure,
        "event_count": recording.position,
        "events_remaining": len(recording.events) - recording.position,
        "recording_sha256": hashlib.sha256(raw).hexdigest(),
        "recording_size": len(raw),
        "database_sha256": profile.database.sha256,
        "management_sha256": profile.catalog.management.sha256,
        "source_paths": [
            str(path),
            str(profile.catalog.root / "Toyota.ddb"),
            str(profile.catalog.root / profile.filename),
            str(profile.catalog.root / "M_English.ddb"),
        ]
        + ([] if psd_module is None else [str(psd_module.resolve())]),
    }


def create_example_files(directory: Path) -> dict[str, str | int]:
    """Write a wholly authored profile and clear-workflow recording, without overwrite."""
    root = directory.resolve()
    root.mkdir(parents=True, exist_ok=True)

    def database(kind: int, sections: dict[int, tuple[int, bytes]]) -> bytes:
        header = bytearray(36 + 4 * (max(sections) + 1))
        header[8:10] = bytes((kind, max(sections) + 1))
        header[10:28] = b"DiagTool DataCtrl\0"
        struct.pack_into("<I", header, 28, 0x0100032F)
        body = bytearray()
        for slot, (count, payload) in sorted(sections.items()):
            struct.pack_into("<I", header, 36 + slot * 4, len(header) + len(body))
            body += struct.pack("<BBII", slot, 0, count, len(payload)) + payload
        return bytes(header + body)

    category, settings = bytearray(76), bytearray(16)
    category[:18] = "demo.ddb\0".encode("utf-16le")
    struct.pack_into("<H", category, 68, 42)
    struct.pack_into("<I", settings, 0, 0x11223344)
    struct.pack_into("<H", settings, 10, 1)
    management = database(
        1,
        {
            0: (1, struct.pack("<IH", 0, 2) + bytes.fromhex("14aa")),
            16: (1, bytes(category)),
            17: (1, struct.pack("<4H", 1, 1, 0, 0)),
            18: (1, struct.pack("<8H", 42, 1, 1, 1, 0, 0, 0, 0)),
            25: (1, struct.pack("<I4H", 0, 42, 1, 0, 0)),
            29: (1, bytes(settings)),
        },
    )
    ecu = database(2, {10: (0, b"")})
    recording = {
        "schema": WORKFLOW_SCHEMA,
        "source": "authored_synthetic",
        "operation": "clear_dtc",
        "arguments": {},
        "context": {
            "ecu": "authored-ecu",
            "category": 42,
            "category_record": category.hex(),
            "exceptions": [],
            "database_sha256": hashlib.sha256(ecu).hexdigest(),
            "management_sha256": hashlib.sha256(management).hexdigest(),
            "native_id": 42,
            "bus_id": 7,
            "source_build": 18,
            "functions": [],
            "targets": [],
            "pid_positions": None,
            "mode_seed": None,
            "limits": {"seconds": 2, "exchanges": 16},
        },
        "events": [
            {
                "operation": "exchange",
                "arguments": {
                    "ecu": "authored-ecu",
                    "request": "14aa",
                },
                "status": 0,
                "response": "54aa",
            }
        ],
    }
    files = {
        "Toyota.ddb": management,
        "M_English.ddb": database(4, {0: (0, b"")}),
        "demo.ddb": ecu,
        "workflow.json": (_workflow_json(recording) + "\n").encode(),
    }
    if any((root / name).exists() or (root / name).is_symlink() for name in files):
        raise FileExistsError(
            "Authored workflow demo will not overwrite existing inputs"
        )
    for name, raw in files.items():
        with (root / name).open("xb") as output:
            output.write(raw)
    return {
        "region_root": str(root),
        "recording": str(root / "workflow.json"),
        "category": 42,
    }
