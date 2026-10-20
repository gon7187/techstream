"""Strict captured application-PDU exchange for native Toyota engines.

Unlike standard OBD replay, this format carries receive-only continuations and
native transport errors. Resource selection and decoding belong to the caller.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path

from scripts.local_files import read_regular
from scripts.profiles import VehicleProfile
from scripts.readiness import ReadinessSession
from scripts.toyota_session import CommandSpec, NativeStatus, ToyotaSession

SCHEMA = "techstream-native-exchange-v1"
MAX_FILE = 16 * 1024 * 1024
MAX_TRANSACTIONS = 100000


def _object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate native replay key: {key}")
        result[key] = value
    return result


def _hex(value: object, *, max_bytes: int = 0xFFFF) -> bytes:
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_FILE:
        raise ValueError(
            "Native byte bound must be positive and within the file budget"
        )
    if (
        not isinstance(value, str)
        or len(value) > max_bytes * 2
        or len(value) % 2
        or re.fullmatch("[0-9a-fA-F]*", value) is None
    ):
        raise ValueError(
            f"Native data must be even hexadecimal within {max_bytes} bytes"
        )
    return bytes.fromhex(value)


def _lengths(value: object) -> dict[int, int] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or len(value) > 256:
        raise ValueError("Native support observations must be a byte-keyed object")
    result = {}
    for key, length in value.items():
        if (
            not isinstance(key, str)
            or re.fullmatch("[0-9a-f]{2}", key) is None
            or type(length) is not int
            or not 0 <= length <= 255
        ):
            raise ValueError(
                "Support observations require lowercase hex byte keys and byte lengths"
            )
        result[int(key, 16)] = length
    return result


class NativeReplay:
    """Immutable ordered evidence; no service allowlist, ECU or hardware guessing."""

    def __init__(
        self,
        document: dict,
        cancelled: Callable[[], bool] | None = None,
        *,
        max_pdu_bytes: int = 0xFFFF,
    ):
        if type(max_pdu_bytes) is not int or not 1 <= max_pdu_bytes <= MAX_FILE:
            raise ValueError(
                "Native byte bound must be positive and within the file budget"
            )
        if not isinstance(document, dict) or set(document) != {
            "schema",
            "source",
            "ecus",
            "transactions",
            "support",
        }:
            raise ValueError("Unexpected native exchange document fields")
        if document["schema"] != SCHEMA or document["source"] not in (
            "authored_synthetic",
            "recorded_unverified",
        ):
            raise ValueError("Unsupported native exchange schema/source")
        ecus = document["ecus"]
        if (
            not isinstance(ecus, list)
            or not 1 <= len(ecus) <= 64
            or any(
                not isinstance(ecu, str)
                or re.fullmatch("[A-Za-z0-9_.:-]{1,64}", ecu) is None
                for ecu in ecus
            )
            or len(set(ecus)) != len(ecus)
        ):
            raise ValueError("Invalid explicit native ECU labels")
        observations = document["support"]
        if not isinstance(observations, dict) or any(
            ecu not in ecus for ecu in observations
        ):
            raise ValueError("Support observations must belong to configured ECUs")
        self._observations = {}
        for ecu, values in observations.items():
            if not isinstance(values, dict) or set(values) != {
                "pid_lengths",
                "did_lengths",
            }:
                raise ValueError(
                    "Support observations require PID and DID length fields"
                )
            self._observations[ecu] = (
                _lengths(values["pid_lengths"]),
                _lengths(values["did_lengths"]),
            )
        rows = document["transactions"]
        if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_TRANSACTIONS:
            raise ValueError("Invalid native exchange count")
        transactions = []
        retained = 0
        for row in rows:
            if not isinstance(row, dict) or set(row) not in (
                {"ecu", "request", "response"},
                {"ecu", "request", "status", "partial_response"},
            ):
                raise ValueError("Invalid native transaction fields")
            if not isinstance(row["ecu"], str) or row["ecu"] not in ecus:
                raise ValueError("Transaction ECU is not configured")
            request = _hex(row["request"], max_bytes=max_pdu_bytes)
            status = 0
            if "status" in row:
                status = row["status"]
                if type(status) is not int or not 0 < status <= 0xFFFFFFFF:
                    raise ValueError("Native status must be a nonzero uint32")
                response = _hex(row["partial_response"], max_bytes=max_pdu_bytes)
            else:
                response = _hex(row["response"], max_bytes=max_pdu_bytes)
            retained += len(request) + len(response) + len(row["ecu"]) + 32
            if retained > MAX_FILE:
                raise ValueError("Native exchange aggregate byte budget exceeded")
            transactions.append((row["ecu"], request, response, status))
        self._transactions = tuple(transactions)
        self.ecus, self.source = tuple(ecus), document["source"]
        self.cancelled, self.position = cancelled, 0

    @classmethod
    def load(
        cls, path: str | Path, cancelled: Callable[[], bool] | None = None
    ) -> NativeReplay:
        return cls.loads(read_regular(path, limit=MAX_FILE), cancelled)

    @classmethod
    def loads(
        cls, raw: bytes, cancelled: Callable[[], bool] | None = None
    ) -> NativeReplay:
        if not isinstance(raw, bytes):
            raise TypeError("Native recording input must be bytes")
        if len(raw) > MAX_FILE:
            raise ValueError("Native exchange file exceeds 16 MiB")
        try:
            document = json.loads(raw, object_pairs_hook=_object)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise ValueError(f"Invalid native exchange JSON: {error}") from error
        return cls(document, cancelled)

    @property
    def remaining(self) -> int:
        return len(self._transactions) - self.position

    def observations(
        self, ecu: str
    ) -> tuple[dict[int, int] | None, dict[int, int] | None]:
        pid, did = self._observations.get(ecu, (None, None))
        return (
            dict(pid) if pid is not None else None,
            dict(did) if did is not None else None,
        )

    def exchange(self, ecu: str, request: bytes) -> bytes:
        if self.cancelled is not None and self.cancelled():
            raise InterruptedError("Native replay cancelled")
        if not self.remaining:
            raise ValueError("Native replay exhausted")
        expected_ecu, expected_request, response, status = self._transactions[
            self.position
        ]
        if not isinstance(request, bytes) or (ecu, request) != (
            expected_ecu,
            expected_request,
        ):
            raise ValueError(f"Native replay mismatch at transaction {self.position}")
        self.position += 1
        if status:
            raise NativeStatus(status, response)
        return response

    def assert_complete(self) -> None:
        if self.remaining:
            raise ValueError(f"Native replay has {self.remaining} unconsumed exchanges")


def replay_profile(
    profile: VehicleProfile,
    path: str | Path,
    *,
    operation: str = "readiness",
    ecu: str | None = None,
    function_id: int | None = None,
    signal_keys: tuple[int, ...] = (),
    cancelled: Callable[[], bool] | None = None,
) -> dict:
    """Join an explicit local vehicle profile to a complete captured exchange."""
    replay = NativeReplay.load(path, cancelled)
    selected = ecu or replay.ecus[0]
    if selected not in replay.ecus:
        raise ValueError("Selected ECU is absent from the native recording")
    if operation in ("readiness", "data_list"):
        pid_lengths, did_lengths = replay.observations(selected)
        if pid_lengths is None:
            raise ValueError(
                "Native GetEnableIdList PID-length observations were not supplied"
            )
        engine = ReadinessSession(
            profile,
            replay.exchange,
            selected,
            pid_lengths,
            did_lengths=did_lengths,
            cancelled=cancelled or (lambda: False),
        )
        result = (
            engine.readiness()
            if operation == "readiness"
            else engine.data_list(signal_keys)
        )
    elif operation == "command":
        if function_id is None:
            raise ValueError("An explicit selected function ID is required")
        frames = profile.frame_records(function_id)
        commands = {
            str(index): CommandSpec(
                frame.frame,
                check="mask" if frame.frame.receive_mask else "raw",
                provenance=frame.provenance,
            )
            for index, frame in enumerate(frames)
        }
        session = ToyotaSession(
            replay.exchange, selected, commands, cancelled=cancelled or (lambda: False)
        )
        responses = session.sequence(tuple(commands))
        result = {
            "function_id": function_id,
            "responses_hex": [response.hex() for response in responses],
            "validation": "selected-masks-and-record-order"
            if any(frame.frame.receive_mask for frame in frames)
            else "record-order-only",
            "semantic_status": "raw-responses-not-decoded",
            "session": session.report(),
        }
    else:
        raise ValueError("Unknown native profile recording operation")
    replay.assert_complete()
    return {
        "source": replay.source,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "operation": operation,
        "profile": profile.report(),
        "ecu": selected,
        "result": result,
    }
