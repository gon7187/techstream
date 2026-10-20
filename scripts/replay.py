"""Strict ordered application-PDU replay and bounded read-only recording."""

import json
import re
from pathlib import Path
from typing import Any

try:
    from .diagnostics import (
        MAX_PDU,
        DiagnosticError,
        Exchange,
        NegativeResponse,
        decode_response,
        validate_ecu,
        validate_request,
    )
    from .local_files import read_regular
except ImportError:
    from diagnostics import (
        MAX_PDU,
        DiagnosticError,
        Exchange,
        NegativeResponse,
        decode_response,
        validate_ecu,
        validate_request,
    )
    from local_files import read_regular

MAX_TRANSACTIONS = 100000
MAX_FILE_BYTES = 16 * 1024 * 1024
SCHEMA = "techstream-native-replay-v1"


class ReplayError(ValueError):
    pass


class ReplayMismatch(ReplayError):
    pass


class ReplayExhausted(ReplayError):
    pass


def _hex(value: Any) -> bytes:
    if (
        not isinstance(value, str)
        or not 2 <= len(value) <= MAX_PDU * 2
        or len(value) % 2
        or re.fullmatch(r"[0-9a-fA-F]+", value) is None
    ):
        raise ReplayError("PDU must be even-length hexadecimal, 1..4095 bytes")
    return bytes.fromhex(value)


def _validate_response(request: bytes, response: bytes) -> None:
    try:
        decode_response(request, response)
    except NegativeResponse:
        # Negative ECU replies are valid evidence; Session reports the failure.
        return
    except DiagnosticError as exc:
        raise ReplayError(f"invalid replay response: {exc}") from exc


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReplayError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


class Replay:
    def __init__(self, document: dict[str, Any]):
        if not isinstance(document, dict) or set(document) != {
            "schema",
            "source",
            "ecus",
            "transactions",
        }:
            raise ReplayError("unexpected replay document fields")
        if document["schema"] != SCHEMA or document["source"] not in (
            "authored_synthetic",
            "recorded_unverified",
        ):
            raise ReplayError("unsupported replay schema/source")
        ecus = document["ecus"]
        if (
            not isinstance(ecus, list)
            or not 1 <= len(ecus) <= 64
            or any(not isinstance(ecu, str) for ecu in ecus)
        ):
            raise ReplayError("invalid configured ECU list")
        if len(set(ecus)) != len(ecus):
            raise ReplayError("duplicate configured ECU")
        for ecu in ecus:
            validate_ecu(ecu)
        rows = document["transactions"]
        if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_TRANSACTIONS:
            raise ReplayError("invalid transaction count")
        self.ecus: list[str] = list(ecus)
        self.source: str = document["source"]
        self.transactions: list[tuple[str, bytes, bytes]] = []
        for row in rows:
            if (
                not isinstance(row, dict)
                or set(row) != {"ecu", "request", "response"}
                or row["ecu"] not in ecus
            ):
                raise ReplayError("invalid transaction fields/ECU")
            request, response = _hex(row["request"]), _hex(row["response"])
            validate_request(request)
            _validate_response(request, response)
            self.transactions.append((row["ecu"], request, response))
        self.position = 0

    @classmethod
    def load(cls, path: str | Path) -> "Replay":
        try:
            raw = read_regular(path, limit=MAX_FILE_BYTES)
        except ValueError as error:
            raise ReplayError(str(error)) from error
        try:
            document = json.loads(raw, object_pairs_hook=_object)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise ReplayError(f"invalid replay JSON: {exc}") from exc
        return cls(document)

    @property
    def remaining(self) -> int:
        return len(self.transactions) - self.position

    def exchange(self, ecu: str, request: bytes) -> bytes:
        validate_ecu(ecu)
        validate_request(request)
        if not self.remaining:
            raise ReplayExhausted("replay exhausted")
        expected_ecu, expected_request, response = self.transactions[self.position]
        if ecu != expected_ecu or request != expected_request:
            raise ReplayMismatch(
                f"transaction {self.position}: expected {expected_ecu}/{expected_request.hex()}, received {ecu}/{request.hex()}"
            )
        self.position += 1
        return response

    def assert_complete(self) -> None:
        if self.remaining:
            raise ReplayMismatch(f"{self.remaining} replay transactions remain")


class Recorder:
    def __init__(self, exchange: Exchange):
        self._exchange = exchange
        self._encoded_size = 256
        self._ecus: set[str] = set()
        self.transactions: list[dict[str, str]] = []

    def exchange(self, ecu: str, request: bytes) -> bytes:
        validate_ecu(ecu)
        validate_request(request)
        if len(self.transactions) >= MAX_TRANSACTIONS:
            raise ReplayError("recording transaction limit reached")
        if ecu not in self._ecus and len(self._ecus) >= 64:
            raise ReplayError("recording ECU limit reached")
        response = self._exchange(ecu, request)
        if not isinstance(response, bytes) or not 1 <= len(response) <= MAX_PDU:
            raise ReplayError("invalid recorded response PDU")
        _validate_response(request, response)
        encoded_size = len(ecu) + 2 * (len(request) + len(response)) + 128
        if self._encoded_size + encoded_size > MAX_FILE_BYTES:
            raise ReplayError("recording exceeds replay file limit")
        self._encoded_size += encoded_size
        self._ecus.add(ecu)
        self.transactions.append(
            {"ecu": ecu, "request": request.hex(), "response": response.hex()}
        )
        return response

    def save(self, path: str | Path) -> None:
        document = {
            "schema": SCHEMA,
            "source": "recorded_unverified",
            "ecus": list(dict.fromkeys(row["ecu"] for row in self.transactions)),
            "transactions": self.transactions,
        }
        Replay(document)
        data = json.dumps(document, indent=2) + "\n"
        if len(data.encode()) > MAX_FILE_BYTES:
            raise ReplayError("recording exceeds replay file limit")
        # Exclusive creation prevents accidental replacement of an existing recording.
        with Path(path).open("x", encoding="utf-8") as stream:
            stream.write(data)
