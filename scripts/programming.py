"""Recovered native programming codecs and an explicit authored host simulator.

All transport and authorization providers are injected. No backend is created
implicitly and no USB, subprocess, network or vendor DLL is opened. Native
fragments and authored simulator checkpoints remain separate contracts.
"""

from __future__ import annotations

import configparser
import hashlib
import json
import math
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import date
from functools import cached_property
from typing import Protocol

from scripts.calibration import (
    CalibrationContainer,
    bind_native_cpu_records,
    bind_native_logical_records,
    decode_cuw_text,
    materialize_native_srecord_area,
)

PHASES = ("preflight", "prepare", "erase", "transfer", "verify", "finish")
DESTRUCTIVE = frozenset(("erase", "transfer", "verify", "finish"))


@dataclass(frozen=True)
class ProgramPlan:
    ecu: str
    current_id: str
    target_id: str
    blocks: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if not all(
            isinstance(x, str) and 0 < len(x) <= 128
            for x in (self.ecu, self.current_id, self.target_id)
        ):
            raise ValueError("Bounded ECU/current/target identity required")
        if self.current_id == self.target_id:
            raise ValueError("Target already installed")
        if not isinstance(self.blocks, tuple) or not 0 < len(self.blocks) <= 4096:
            raise ValueError("One to 4096 immutable blocks required")
        if any(
            not isinstance(b, bytes) or not 0 < len(b) <= 1024 * 1024
            for b in self.blocks
        ):
            raise ValueError("Blocks must be nonempty bytes within 1 MiB")
        if sum(map(len, self.blocks)) > 64 * 1024 * 1024:
            raise ValueError("Plan exceeds 64 MiB")

    @cached_property
    def digest(self) -> str:
        metadata = json.dumps(
            (self.ecu, self.current_id, self.target_id), separators=(",", ":")
        ).encode()
        digest = hashlib.sha256(metadata)
        for block in self.blocks:
            digest.update(len(block).to_bytes(4, "big"))
            digest.update(block)
        return digest.hexdigest()

    @cached_property
    def operations(self) -> tuple[tuple[str, int | None], ...]:
        return (
            (("preflight", None), ("prepare", None), ("erase", None))
            + tuple(("transfer", i) for i in range(len(self.blocks)))
            + (("verify", None), ("finish", None))
        )


@dataclass(frozen=True)
class Checkpoint:
    plan_sha256: str
    next_operation: int
    uncertain: bool

    def report(self) -> dict:
        return {
            "plan_sha256": self.plan_sha256,
            "next_operation": self.next_operation,
            "uncertain": self.uncertain,
        }


class Backend(Protocol):
    """Each call must return within timeout or raise; the caller cannot kill I/O.

    reconcile must independently prove the checkpoint against backend state. A
    real provider needs separately recovered protocol, voltage/identity/security
    rules and physical acceptance; merely implementing this protocol is no proof.
    """

    def execute(
        self, phase: str, index: int | None, plan: ProgramPlan, timeout: float
    ) -> None: ...

    def reconcile(
        self, plan: ProgramPlan, checkpoint: Checkpoint, timeout: float
    ) -> int: ...


class Programmer:
    def __init__(
        self, backend: Backend, *, clock: Callable[[], float] = time.monotonic
    ):
        self.backend = backend
        self.clock = clock

    def run(
        self,
        plan: ProgramPlan,
        *,
        timeout: float = 30.0,
        cancelled: Callable[[], bool] = lambda: False,
        checkpoint: Checkpoint | None = None,
    ) -> dict:
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("A finite positive deadline is required")
        deadline = self.clock() + timeout
        operations = plan.operations
        cursor = 0
        touched = False
        history = []

        def remaining() -> float:
            value = deadline - self.clock()
            if value <= 0:
                raise TimeoutError("Programming deadline expired")
            return value

        def result(
            state: str, error: str | None = None, uncertain: bool = False
        ) -> dict:
            return {
                "state": state,
                "error": error,
                "history": history,
                "checkpoint": Checkpoint(plan.digest, cursor, uncertain).report(),
                "provenance": "authored-injected-backend-lifecycle",
                "physical_status": "PHYSICAL_UNCONFIRMED",
            }

        if checkpoint is not None:
            if (
                checkpoint.plan_sha256 != plan.digest
                or type(checkpoint.next_operation) is not int
                or not 0 <= checkpoint.next_operation <= len(operations)
                or type(checkpoint.uncertain) is not bool
            ):
                raise ValueError("Checkpoint does not match plan")
            cursor = checkpoint.next_operation
            if cancelled():
                return result(
                    "recovery_required"
                    if cursor >= 3
                    or (
                        checkpoint.uncertain
                        and cursor < len(operations)
                        and operations[cursor][0] in DESTRUCTIVE
                    )
                    else "cancelled",
                    uncertain=checkpoint.uncertain,
                )
            try:
                cursor = self.backend.reconcile(plan, checkpoint, remaining())
                remaining()
                if type(
                    cursor
                ) is not int or not checkpoint.next_operation <= cursor <= min(
                    checkpoint.next_operation + int(checkpoint.uncertain),
                    len(operations),
                ):
                    raise ValueError("Backend did not prove a valid recovery position")
                touched = cursor >= 3
            except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - preserve recovery state
                cursor = checkpoint.next_operation
                return result("recovery_required", str(exc), checkpoint.uncertain)
        while cursor < len(operations):
            phase, index = operations[cursor]
            if cancelled():
                return result("recovery_required" if touched else "cancelled")
            try:
                budget = remaining()
            except TimeoutError as exc:
                return result("recovery_required" if touched else "failed", str(exc))
            destructive = phase in DESTRUCTIVE
            touched |= destructive
            try:
                self.backend.execute(phase, index, plan, budget)
                # A late response is uncertain until independently reconciled.
                remaining()
            except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - preserve recovery state
                return result(
                    "recovery_required" if touched else "failed", str(exc), True
                )
            history.append({"phase": phase, "block": index})
            cursor += 1
        return result("completed")


class SimulatorBackend:
    """Volatile in-memory fake with identity checks and independently checked journal.

    Instances represent one simulated ECU. Reuse the same instance for recovery;
    a fresh fake cannot prove an earlier write. Failures can be injected by subclass.
    """

    def __init__(self, ecu: str, current_id: str):
        self.ecu = ecu
        self.current_id = current_id
        self.plan_sha256: str | None = None
        self.journal: list[tuple[str, int | None]] = []
        self.image: dict[int, bytes] = {}

    def execute(
        self, phase: str, index: int | None, plan: ProgramPlan, timeout: float
    ) -> None:
        if timeout <= 0 or self.ecu != plan.ecu:
            raise ValueError("ECU mismatch or deadline expired")
        if phase == "preflight":
            if self.current_id != plan.current_id or self.journal:
                raise ValueError("Calibration mismatch or simulation already started")
            self.plan_sha256 = plan.digest
        elif self.plan_sha256 != plan.digest:
            raise ValueError("Different programming plan")
        if len(self.journal) >= len(plan.operations) or plan.operations[
            len(self.journal)
        ] != (phase, index):
            raise ValueError("Out-of-order operation")
        if phase == "erase":
            self.image.clear()
        elif phase == "transfer":
            if index is None:
                raise ValueError("Transfer requires block index")
            self.image[index] = plan.blocks[index]
        elif phase == "verify":
            if self.image != dict(enumerate(plan.blocks)):
                raise ValueError("Readback mismatch")
        elif phase == "finish":
            self.current_id = plan.target_id
        self.journal.append((phase, index))

    def reconcile(
        self, plan: ProgramPlan, checkpoint: Checkpoint, timeout: float
    ) -> int:
        if (
            timeout <= 0
            or self.ecu != plan.ecu
            or self.plan_sha256 != plan.digest
            or self.journal != list(plan.operations[: len(self.journal)])
        ):
            raise ValueError("Recovery identity/journal mismatch")
        cursor = len(self.journal)
        low = checkpoint.next_operation
        if not low <= cursor <= low + int(checkpoint.uncertain):
            raise ValueError("Recovery journal position mismatch")
        expected = {
            index: plan.blocks[index]
            for phase, index in self.journal
            if phase == "transfer" and index is not None
        }
        if self.image != expected:
            raise ValueError("Recovery image mismatch")
        expected_id = (
            plan.target_id if cursor == len(plan.operations) else plan.current_id
        )
        if self.current_id != expected_id:
            raise ValueError("Recovery calibration identity mismatch")
        return cursor


def inspect_recovery_info(data: bytes) -> dict:
    """Inspect plaintext RecoveryInfo.ini fields observed in CUW 18.

    No path is opened and these fields cannot be imported as a host checkpoint.
    The native nibble-text representation is decoded, but these fields alone
    do not establish safe vehicle recovery or checkpoint authenticity.
    """
    if (
        not isinstance(data, bytes)
        or not 0 < len(data) <= 1024 * 1024
        or b"\x00" in data
    ):
        raise ValueError("Bounded plaintext recovery data required")
    encoded = len(data) % 2 == 0 and all(0x20 <= byte <= 0x5F for byte in data)
    if encoded:
        data = decode_cuw_text(data)
        if b"\x00" in data:
            raise ValueError("NUL in decoded recovery information")
    parser = configparser.ConfigParser(
        interpolation=None, delimiters=("=",), strict=True
    )
    try:
        parser.read_string(data.decode("cp1252"))
    except (configparser.Error, UnicodeError) as exc:
        raise ValueError("Invalid recovery INI") from exc
    sections = {section.casefold(): section for section in parser.sections()}
    if (
        len(sections) != len(parser.sections())
        or parser.defaults()
        or "recoveryinfo" not in sections
    ):
        raise ValueError("Unambiguous RecoveryInfo section required")
    source = parser[sections["recoveryinfo"]]
    if len(source) > 16384 or any(
        len(key) > 128 or len(value) > 4096 for key, value in source.items()
    ):
        raise ValueError("Recovery field limits exceeded")
    values = {}
    integer_keys = {
        "cidnum",
        "cidnodenum",
        "writecpuindex",
        "passthruerrorcode",
        "assynonum",
        "vehicleinfoforupdateavailableflagnum",
        "reprocheckresult",
    }
    boolean_keys = {
        "writing",
        "usenewsoftwarepassword",
        "iscentralgwexist",
        "writingendblock",
    }
    for key in integer_keys | boolean_keys:
        if key not in source:
            continue
        try:
            value = int(source[key], 10)
        except ValueError as exc:
            raise ValueError("Invalid recovery integer") from exc
        if not 0 <= value <= 0xFFFFFFFF or (
            key in boolean_keys and value not in (0, 1)
        ):
            raise ValueError("Recovery integer outside bounds")
        if key in ("reprocheckresult", "passthruerrorcode") and value > 255:
            raise ValueError("Recovery integer exceeds native byte field")
        if key.endswith("num") and value > 4096:
            raise ValueError("Recovery count outside bounds")
        values[key] = value
    for count_key, prefix in (
        ("cidnum", "cid"),
        ("cidnodenum", "cidnode"),
        ("assynonum", "assyno"),
        ("vehicleinfoforupdateavailableflagnum", "vehicleinfoforupdateavailableflag"),
    ):
        if count_key in values:
            count = values[count_key]
            for index in range(1, count + 1):
                key = f"{prefix}{index}"
                if key not in source:
                    raise ValueError("Missing indexed recovery identity")
                if prefix == "cidnode":
                    try:
                        node = int(source[key], 10)
                    except ValueError as exc:
                        raise ValueError("Invalid indexed recovery node") from exc
                    if not 0 <= node <= 255:
                        raise ValueError(
                            "Indexed recovery node outside native byte bounds"
                        )
                    values[key] = node
                elif prefix == "vehicleinfoforupdateavailableflag":
                    if source[key] not in ("0", "1"):
                        raise ValueError("Invalid indexed recovery boolean")
                    values[key] = int(source[key])
                else:
                    values[key] = source[key]
    for key in ("savedcalibrationfilepath", "selectedj2534device", "vin"):
        if key in source:
            values[key] = source[key]
    return {
        "format": "CUW18-RecoveryInfo",
        "encoded": encoded,
        "fields": values,
        "integrity_validated": False,
        "resume_authorized": False,
        "provenance": "native field names; strict host inspection only",
    }


def reprostd_download_request(address: int, size: int, selector: int = 1) -> bytes:
    """Recovered CUW18 ReproStd 0x34 request, fixed address/length width4.

    Selector1 is whole/routine, 0x21 delta and 0x11 compressed in this writer.
    This encoding alone establishes neither compatibility nor an authorized write.
    """
    if (
        type(address) is not int
        or type(size) is not int
        or type(selector) is not int
        or not 0 <= address <= 0xFFFFFFFF
        or not 1 <= size <= 64 * 1024 * 1024
        or address + size > 0x100000000
        or selector not in (1, 0x21, 0x11)
    ):
        raise ValueError("Invalid bounded ReproStd download parameters")
    return (
        b"\x34"
        + bytes((selector, 0x44))
        + address.to_bytes(4, "big")
        + size.to_bytes(4, "big")
    )


def reprostd_block_size(response: bytes) -> int:
    """Decode 0x74 maxNumberOfBlockLength and subtract service/counter bytes.

    Native caps its transport message to4095 bytes. Host additionally rejects
    missing length bytes and zero-width lengths. Native ignores the low nibble
    and accepts positive response parameters after the declared length.
    """
    if not isinstance(response, bytes) or len(response) < 3 or response[0] != 0x74:
        raise ValueError("Expected positive RequestDownload response")
    width = response[1] >> 4
    if not 1 <= width <= 15 or len(response) < 2 + width:
        raise ValueError("Malformed download block length")
    maximum = min(int.from_bytes(response[2 : 2 + width], "big"), 0xFFF)
    if maximum < 3:
        raise ValueError("Download block length cannot contain data")
    return maximum - 2


class NativeNegativeResponse(ValueError):
    """A matched native7f/service/NRC reply, retaining bytes for exact policy."""

    def __init__(self, service: int, code: int, response: bytes):
        super().__init__(f"Native negative response {service:02x}/{code:02x}")
        self.service, self.code, self.response = service, code, response


class NativeTransportError(ConnectionError):
    """Explicit native transport error code supplied by a fake/replay provider."""

    def __init__(self, code: int):
        if type(code) is not int or not 0 <= code <= 0xFFFFFFFF:
            raise ValueError("Native transport error code must be uint32")
        super().__init__(f"Native transport error {code}")
        self.code = code


class NativeRecoveryTransportError(NativeTransportError):
    """Captured reconnect exception with both native code and detail fields."""

    def __init__(self, code: int, detail: int):
        super().__init__(code)
        if type(detail) is not int or not 0 <= detail <= 0xFFFFFFFF:
            raise ValueError("Native recovery transport detail must be uint32")
        self.detail = detail


class NativePendingTimeout(TimeoutError):
    """Native P5 elapsed-pending exception, distinct from a host deadline."""

    def __init__(
        self,
        message: str,
        *,
        request: bytes | None = None,
        response: bytes | None = None,
    ):
        if (request is None) != (response is None) or any(
            value is not None
            and (not isinstance(value, bytes) or not 0 < len(value) <= 4116)
            for value in (request, response)
        ):
            raise ValueError("Bounded paired native pending request/response required")
        super().__init__(message)
        self.request, self.response = request, response


class NativeDiagnosticError(ValueError):
    """A source-typed native diagnostic failure, distinct from host validation."""


class NativeUnexpectedResponse(NativeDiagnosticError):
    """Bounded native positive-prefix mismatch, separate from host validation."""

    def __init__(self, request: bytes, response: bytes):
        if (
            not isinstance(request, bytes)
            or not isinstance(response, bytes)
            or not 0 < len(request) <= 4116
            or not 0 < len(response) <= 4116
        ):
            raise ValueError("Bounded native request and response required")
        super().__init__("Unexpected native positive response prefix")
        self.request = request
        self.response = response


class NativeProgrammingChannel:
    """Bounded native CUW CAN exchange seam for explicit fake/replay providers.

    Positive responses match a prefix; callers enforce operation-specific minimum
    lengths. Matched7f/SID/78 is receive-only. There is no retry, transport factory,
    native timeout cleanup, device discovery or implicit authorization.
    """

    def __init__(
        self,
        exchange: Callable[[str, bytes], bytes],
        ecu: str,
        timeout: float = 30,
        cancelled: Callable[[], bool] = lambda: False,
        clock: Callable[[], float] = time.monotonic,
        receive: Callable[[str], bytes] | None = None,
        *,
        message_limit: int = 4095,
        pending_response_timeout_seconds: float | None = None,
        pending_timeout_write: Callable[[str, bytes], None] | None = None,
        response_budget: int = 1024 * 1024,
        retain_payload_history: bool = True,
    ):
        if (
            not isinstance(ecu, str)
            or not 0 < len(ecu) <= 128
            or isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("Bounded ECU and finite positive timeout required")
        if type(message_limit) is not int or message_limit not in (4095, 4116):
            raise ValueError("Recovered native CAN/Ethernet message limit required")
        if pending_response_timeout_seconds is not None and (
            isinstance(pending_response_timeout_seconds, bool)
            or not isinstance(pending_response_timeout_seconds, (int, float))
            or not math.isfinite(pending_response_timeout_seconds)
            or not 0 <= pending_response_timeout_seconds <= 0xFFFFFFFF
        ):
            raise ValueError("Finite native pending elapsed seconds required")
        if pending_timeout_write is not None and not callable(pending_timeout_write):
            raise TypeError("Explicit pending-expiry raw write provider required")
        if (
            type(response_budget) is not int
            or not 0 < response_budget <= 128 * 1024 * 1024
        ):
            raise ValueError("Bounded native response budget up to128MiB required")
        if type(retain_payload_history) is not bool:
            raise TypeError("Explicit native history retention flag required")
        self.response_budget = response_budget
        self.retain_payload_history = retain_payload_history
        self.pending_timeout_write = pending_timeout_write
        self.pending_response_timeout_seconds = pending_response_timeout_seconds
        self.message_limit = message_limit
        self.exchange, self.ecu, self.cancelled, self.clock, self.receive = (
            exchange,
            ecu,
            cancelled,
            clock,
            receive,
        )
        self.deadline = clock() + timeout
        self.attempted = False
        self.history: list[dict] = []
        self.response_bytes = 0
        self.received_count = 0
        self.attempt_count = 0

    def _invoke(self, callback: Callable, *args):
        try:
            result = callback(*args)
        except (Exception, KeyboardInterrupt):
            self._check_boundary()
            raise
        self._check_boundary()
        return result

    def _check_boundary(self) -> None:
        if self.cancelled():
            raise InterruptedError("Transfer cancelled at callback boundary")
        if self.clock() >= self.deadline:
            raise TimeoutError("Transfer callback exceeded deadline")

    def call(self, request: bytes, expected: bytes | None) -> bytes:
        if (
            not isinstance(request, bytes)
            or not 0 < len(request) <= self.message_limit
            or (
                expected is not None
                and (
                    not isinstance(expected, bytes)
                    or not 0 < len(expected) <= self.message_limit
                )
            )
        ):
            raise ValueError(
                "Bounded immutable native request/response prefix required"
            )
        if self.cancelled():
            raise InterruptedError("Transfer cancelled between exchanges")
        if self.clock() >= self.deadline:
            raise TimeoutError("Transfer deadline expired")
        if self.received_count >= 65536:
            raise ValueError("Host exchange count budget exceeded")
        if self.attempt_count >= 65536:
            raise ValueError("Host request attempt budget exceeded")
        self.attempt_count += 1
        self.attempted = True
        response = self._invoke(self.exchange, self.ecu, request)
        self.received_count += 1
        pending = 0
        pending_started = None
        while (
            isinstance(response, bytes)
            and len(response) <= self.message_limit
            and response.startswith(bytes((0x7F, request[0], 0x78)))
        ):
            if pending_started is None:
                pending_started = self.clock()
            if (
                self.pending_response_timeout_seconds is not None
                and math.floor(self.clock()) - math.floor(pending_started)
                >= self.pending_response_timeout_seconds
            ):
                self._check_boundary()
                if self.pending_timeout_write is not None:
                    self._invoke(self.pending_timeout_write, self.ecu, b"\x3e")
                raise NativePendingTimeout(
                    "Native response-pending elapsed limit exceeded",
                    request=request,
                    response=response,
                )
            if self.receive is None:
                raise ValueError("Pending response requires explicit receive callback")
            if self.cancelled():
                raise InterruptedError("Transfer cancelled while response pending")
            if self.clock() >= self.deadline or pending >= 4096:
                raise TimeoutError("Pending response deadline or host limit exceeded")
            if self.received_count >= 65536:
                raise ValueError("Host exchange count budget exceeded")
            pending += 1
            response = self._invoke(self.receive, self.ecu)
            self.received_count += 1
        if self.clock() >= self.deadline:
            raise TimeoutError("Transfer response arrived after deadline")
        if (
            isinstance(response, bytes)
            and 3 <= len(response) <= self.message_limit
            and response[:2] == bytes((0x7F, request[0]))
        ):
            raise NativeNegativeResponse(request[0], response[2], response)
        if (
            not isinstance(response, bytes)
            or not response
            or len(response) > self.message_limit
        ):
            raise ValueError("Unexpected transfer response")
        if expected is not None and not response.startswith(expected):
            raise NativeUnexpectedResponse(request, response)
        self.response_bytes += len(response)
        if self.response_bytes > self.response_budget or len(self.history) >= 65536:
            raise ValueError("Host exchange history budget exceeded")
        self.history.append(
            {"request_hex": request[:2].hex(), "response_hex": response.hex()}
            if self.retain_payload_history
            else {
                "request_hex": request[:2].hex(),
                "response_sha256": hashlib.sha256(response).hexdigest(),
                "response_length": len(response),
            }
        )
        return response


def _download_transfer(
    channel: NativeProgrammingChannel,
    request: bytes,
    data: bytes,
    progress: dict,
    configure: Callable[[int], None] | None = None,
    restore: Callable[[], None] | None = None,
    block_size_decoder: Callable[[bytes], int] = reprostd_block_size,
    transport_retries: int = 0,
) -> None:
    block_size = block_size_decoder(channel.call(request, None))
    if (len(data) + block_size - 1) // block_size > 65536:
        raise ValueError("Host transfer operation limit exceeded")
    try:
        if configure is not None:
            configure(block_size)
        progress["phase"] = "transfer"
        while progress["transferred"] < len(data):
            block = data[progress["transferred"] : progress["transferred"] + block_size]
            sequence = progress["next_sequence"]
            for attempt in range(transport_retries + 1):
                try:
                    channel.call(
                        bytes((0x36, sequence)) + block, bytes((0x76, sequence))
                    )
                    break
                except NativeTransportError as exc:
                    if exc.code not in (9, 16) or attempt == transport_retries:
                        raise
            progress["transferred"] += len(block)
            progress["next_sequence"] = (sequence + 1) & 255
    finally:
        if restore is not None:
            restore()
    progress["phase"] = "exit"
    channel.call(b"\x37", b"\x77")


def reprostd_transfer(
    exchange: Callable[[str, bytes], bytes],
    ecu: str,
    address: int,
    data: bytes,
    *,
    selector: int = 1,
    configure_block: Callable[[int], None] | None = None,
    restore_transport: Callable[[], None] | None = None,
    timeout: float = 30,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
    receive: Callable[[str], bytes] | None = None,
    channel_factory: Callable[..., NativeProgrammingChannel] = NativeProgrammingChannel,
    pending_response_timeout_seconds: float | None = None,
    pending_timeout_write: Callable[[str, bytes], None] | None = None,
) -> dict:
    """Run only the statically recovered ReproStd download/transfer/exit fragment.

    The caller supplies an exchange fake/replay; there is no device provider here.
    Preparation, erase, security, verification, power/reset and native recovery are
    separate unresolved contracts. A failed/uncertain fragment is never retried.
    """
    if (
        not isinstance(data, bytes)
        or not data
        or not isinstance(ecu, str)
        or not 0 < len(ecu) <= 128
    ):
        raise ValueError("Bounded ECU and immutable nonempty data required")
    request = reprostd_download_request(address, len(data), selector)
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("Finite positive timeout required")
    progress = {"phase": "download", "transferred": 0, "next_sequence": 1}
    history = []

    channel = channel_factory(
        exchange,
        ecu,
        timeout,
        cancelled,
        clock,
        receive,
        pending_response_timeout_seconds=pending_response_timeout_seconds,
        pending_timeout_write=pending_timeout_write,
    )
    history = channel.history

    try:
        _download_transfer(
            channel, request, data, progress, configure_block, restore_transport
        )
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - preserve uncertain write evidence
        return {
            "state": "recovery_required"
            if channel.attempted
            else ("cancelled" if isinstance(exc, InterruptedError) else "failed"),
            "phase": progress["phase"],
            "error": type(exc).__name__,
            "transferred": progress["transferred"],
            "next_sequence": progress["next_sequence"],
            "automatic_retry": False,
            "history": history,
            "provenance": "static-native-CUW18-ReproStd-fragment",
            "physical_status": "PHYSICAL_UNCONFIRMED",
        }
    return {
        "state": "fragment_completed",
        "phase": "exit",
        "transferred": progress["transferred"],
        "history": history,
        "provenance": "static-native-CUW18-ReproStd-fragment",
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "programming_completed": False,
    }


def reprostd_routine_request(
    operation: str,
    address: int,
    size: int,
    *,
    checksum: bytes | None = None,
    signature: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Recovered CUW18 ReproStd routine fragment and positive response prefix.

    ECU-supplied/calibration-provided checksum/signature bytes are required as-is;
    this function does not calculate authentication material or approve a target.
    """
    # Reuse the exact fixed-width address/size validation from RequestDownload.
    bounds = reprostd_download_request(address, size)[2:]
    identifiers = {
        "routine_check": b"\x10\xf5",
        "erase": b"\xff\x00",
        "verify": b"\x10\xf6",
    }
    if not isinstance(operation, str) or operation not in identifiers:
        raise ValueError("Unknown ReproStd routine operation")
    identifier = identifiers[operation]
    request = b"\x31\x01" + identifier + bounds
    if operation == "erase":
        if checksum is not None or signature is not None:
            raise ValueError("Erase routine has no checksum/signature parameters")
    else:
        if checksum is not None and (
            not isinstance(checksum, bytes) or len(checksum) != 4
        ):
            raise ValueError("Checksum must be four supplied bytes or absent")
        if not isinstance(signature, bytes) or len(signature) not in (16, 256):
            raise ValueError(
                "Native routine requires supplied 16- or 256-byte signature"
            )
        request += b"\x00\xff\xff\xff\xff" if checksum is None else b"\x04" + checksum
        request += len(signature).to_bytes(2, "big") + signature
    return request, b"\x71\x01" + identifier


def reprostd_fingerprint_requests(
    slot: int,
    nonce: bytes,
    tester_info: bytes,
    system_time: tuple[int, int, int, int, int, int, int, int],
) -> tuple[tuple[bytes, bytes], ...]:
    """Encode native ReproStd pre-block fingerprint records, without sending.

    slot is the already-resolved native logical-block metadata index1..16.
    system_time is Windows SYSTEMTIME order: year,month,Sunday-zero weekday,day,
    hour,minute,second,milliseconds. The caller supplies identity/time bytes.
    """
    if type(slot) is not int or not 1 <= slot <= 16:
        raise ValueError("Native fingerprint slot must be 1..16")
    if not isinstance(nonce, bytes) or len(nonce) != 16:
        raise ValueError("Fingerprint calibration ID must contain16 bytes")
    if not isinstance(tester_info, bytes) or len(tester_info) != 32:
        raise ValueError("Native tester information must contain32 bytes")
    if (
        not isinstance(system_time, tuple)
        or len(system_time) != 8
        or any(
            type(value) is not int or not 0 <= value <= 65535 for value in system_time
        )
    ):
        raise ValueError("Eight supplied SYSTEMTIME uint16 values required")
    year, month, weekday, day, hour, minute, second, milliseconds = system_time
    if not (
        1 <= year <= 9999
        and 1 <= month <= 12
        and 0 <= weekday <= 6
        and 1 <= day <= 31
        and 0 <= hour <= 23
        and 0 <= minute <= 59
        and 0 <= second <= 59
        and 0 <= milliseconds <= 999
    ):
        raise ValueError("Invalid SYSTEMTIME fields")
    try:
        calendar_day = date(year, month, day)
    except ValueError as exc:
        raise ValueError("Invalid SYSTEMTIME calendar date") from exc
    if (calendar_day.weekday() + 1) % 7 != weekday:
        raise ValueError("SYSTEMTIME weekday disagrees with calendar date")
    identifiers = (0x0202 if slot == 1 else 0x023F + slot, 0x021F + slot, 0x022F + slot)
    payloads = (
        nonce,
        tester_info + bytes(32),
        b"".join(value.to_bytes(2, "big") for value in system_time),
    )
    return tuple(
        (
            b"\x2e" + identifier.to_bytes(2, "big") + payload,
            b"\x6e" + identifier.to_bytes(2, "big"),
        )
        for identifier, payload in zip(identifiers, payloads, strict=True)
    )


def reprostd_security(
    exchange: Callable[[str, bytes], bytes],
    ecu: str,
    key_provider: Callable[[str, bytes], bytes] | None,
    *,
    timeout: float = 30,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
    receive: Callable[[str], bytes] | None = None,
) -> dict:
    """Replay native ReproStd27/01 seed→injectedkey→27/02 exchange.

    No seed/key algorithm or service-auth secret is implemented. The caller must
    supply an authorized key provider; without it no request is sent. Native
    preparation/gateway/reset/session selection is a separate contract.
    """
    if key_provider is None:
        raise ValueError("Explicit authorized key provider required")
    channel = NativeProgrammingChannel(
        exchange, ecu, timeout, cancelled, clock, receive
    )
    phase = "seed"
    try:
        response = channel.call(b"\x27\x01", b"\x67\x01")
        if len(response) < 18:
            raise ValueError("Native ReproStd seed must contain16 bytes")
        phase = "key_provider"
        key = channel._invoke(key_provider, ecu, response[2:18])
        if not isinstance(key, bytes) or len(key) != 16:
            raise ValueError("Authorized provider must return16 key bytes")
        phase = "key"
        channel.call(b"\x27\x02" + key, b"\x67\x02")
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - retain uncertainty without replay
        return {
            "state": "recovery_required" if channel.attempted else "cancelled",
            "phase": phase,
            "error": type(exc).__name__,
            "automatic_retry": False,
            "exchanges": len(channel.history),
            "provenance": "static-native-CUW18-ReproStd-security-fragment",
            "physical_status": "PHYSICAL_UNCONFIRMED",
        }
    return {
        "state": "security_fragment_completed",
        "exchanges": len(channel.history),
        "programming_completed": False,
        "provenance": "static-native-CUW18-ReproStd-security-fragment",
        "physical_status": "PHYSICAL_UNCONFIRMED",
    }


@dataclass(frozen=True)
class ReproStdPrepareContext:
    """Resolved native inputs; no vehicle identification or gateway guessing.

    emissions_delay_ms is the numeric GetEmissionsRelatedSystem return, used by
    the native function both as a branch and as a millisecond delay.
    """

    wakeup_ms: int
    emissions_delay_ms: int
    gateway_kind: int = 0
    gateway_ids: tuple[bytes, ...] = ()
    charge_bus_id: bytes | None = None
    charge_bus_start_ms: int = 0
    extended_addressing: bool = False
    pending_timeout_seconds: int = 180
    gateway_modes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.pending_timeout_seconds) is not int
            or not 0 <= self.pending_timeout_seconds <= 0xFFFFFFFF
        ):
            raise ValueError("Bounded native preparation pending seconds required")
        if any(
            type(value) is not int or not 0 <= value <= 120000
            for value in (
                self.wakeup_ms,
                self.emissions_delay_ms,
                self.charge_bus_start_ms,
            )
        ):
            raise ValueError("Resolved native delays must be within120000 ms")
        if type(self.gateway_kind) is not int or self.gateway_kind not in (0, 1, 2):
            raise ValueError("Resolved native gateway kind must be0,1,2")
        if (
            not isinstance(self.gateway_ids, tuple)
            or len(self.gateway_ids) > 64
            or any(
                not isinstance(x, bytes) or len(x) not in (2, 3)
                for x in self.gateway_ids
            )
        ):
            raise ValueError("Bounded two/three-byte gateway diagnostic IDs required")
        if (
            not isinstance(self.gateway_modes, tuple)
            or self.gateway_modes
            and len(self.gateway_modes) != len(self.gateway_ids)
            or any(
                not isinstance(mode, str) or len(mode) > 256
                for mode in self.gateway_modes
            )
        ):
            raise ValueError("Original native gateway mode rows required")
        if self.charge_bus_id is not None and (
            not isinstance(self.charge_bus_id, bytes) or len(self.charge_bus_id) != 2
        ):
            raise ValueError("Charge bus diagnostic ID must contain two bytes")
        if type(self.extended_addressing) is not bool:
            raise ValueError("Resolved extended addressing flag must be boolean")


class _CanPrepareActions:
    def __init__(self, gateway_kind: int):
        self.gateway_kind = gateway_kind
        self.actions: list[dict] = []

    def add(self, operation: str, **values: object) -> None:
        self.actions.append({"operation": operation, **values})

    def wait(self, milliseconds: int) -> None:
        self.add("wait", milliseconds=milliseconds)

    def raw(self, identifier: int, payload: bytes, extended: bool = False) -> None:
        self.add(
            "raw_write",
            data_hex=(identifier.to_bytes(4, "big") + payload).hex(),
            tx_flags=0x80 if extended else 0,
        )

    def keepalive(self) -> None:
        self.raw(0x777, b"\x3e\x80")
        self.raw(0x77F, b"\xfe\x3e\x80", True)
        if self.gateway_kind == 2:
            self.raw(0x750, b"\x5f\x3e\x02", True)
        self.add("set_previous_send_time")

    def periodic(self, include_gateway: bool, delay: int) -> None:
        frames = [
            {"data_hex": "000007773e80", "tx_flags": 0},
            {"data_hex": "0000077ffe3e80", "tx_flags": 0x80},
        ]
        if include_gateway:
            frames.append({"data_hex": "000007505f3e02", "tx_flags": 0x80})
        self.add(
            "start_periodic",
            frames=frames,
            period_ms=2000,
            spacing_ms=100,
            delay_ms=delay,
        )


def reprostd_prepare_actions(context: ReproStdPrepareContext) -> tuple[dict, ...]:
    """Exact CUW18 ReproStd preparation order with injected platform operations.

    Raw packets include the four-byte J2534 CAN identifier. Platform actions are
    explicit dependencies, not invented packet implementations. In particular,
    gateway authorization and ignition control remain supplied native contracts.
    No action is performed by this builder and no wait actually sleeps.
    """
    if not isinstance(context, ReproStdPrepareContext):
        raise TypeError("Resolved native preparation context required")
    if (
        context.gateway_kind == 0
        and context.gateway_ids[:1] == (b"\x07\x50\x5f",)
        and context.gateway_modes[:1] in (("01",), ("02",))
    ):
        from dataclasses import replace

        variants = {
            kind: reprostd_prepare_actions(replace(context, gateway_kind=kind))[2:]
            for kind in (1, 2)
        }
        return (
            {"operation": "set_previous_send_time"},
            {"operation": "wait", "milliseconds": context.wakeup_ms},
            {"operation": "judge_reprogramming_gateway", "continuations": variants},
        )
    builder = _CanPrepareActions(context.gateway_kind)
    actions = builder.actions
    add, wait, raw, keepalive, periodic = (
        builder.add,
        builder.wait,
        builder.raw,
        builder.keepalive,
        builder.periodic,
    )

    def communication_control() -> None:
        raw(0x777, b"\x28\x81\x01")
        if not context.emissions_delay_ms:
            wait(1000)
            keepalive()
            wait(1000)
        raw(0x77F, b"\xfe\x28\x81\x01", True)
        remaining = context.emissions_delay_ms
        if remaining:
            while remaining > 2000:
                wait(2000)
                keepalive()
                remaining -= 2000
            wait(remaining)
        else:
            wait(1000)
            keepalive()
            wait(1000)
        raw(0x777, b"\x28\x83\x01")
        if not context.emissions_delay_ms:
            wait(1000)
            keepalive()
            wait(1000)
        raw(0x77F, b"\xfe\x28\x83\x01", True)
        if context.emissions_delay_ms:
            spacing = 2000 - remaining
            remaining = context.emissions_delay_ms
            while spacing < remaining:
                wait(spacing)
                keepalive()
                remaining -= spacing
                spacing = 2000
            wait(remaining)
        else:
            wait(1000)

    add("set_previous_send_time")
    wait(context.wakeup_ms)
    raw(0x777, b"\x10\x83")
    wait(1000)
    raw(0x77F, b"\xfe\x10\x83", True)
    wait(1000)
    periodic(False, 1000)
    if context.charge_bus_id is not None:
        add(
            "charge_local_bus",
            diagnostic_id_hex=context.charge_bus_id.hex(),
            mode=0,
            enable=True,
        )
        wait(context.charge_bus_start_ms)
    add("cancel_automatic_ig_off", enable=False)
    for gateway in context.gateway_ids:
        if gateway == b"\x07\x50\x5f":
            if context.gateway_kind == 1:
                add("authorize_p5_central_gateway")
                add("p5_central_gateway_routine", mode=0)
                wait(1500)
                add("p5_central_gateway_routine", mode=1)
            elif context.gateway_kind == 2:
                add("authorize_central_gateway")
    add("stop_periodic")
    raw(0x777, b"\x85\x82")
    wait(1000)
    keepalive()
    wait(1000)
    raw(0x77F, b"\xfe\x85\x82", True)
    wait(1000)
    if not context.emissions_delay_ms:
        keepalive()
        wait(1000)
        communication_control()
    periodic(False, 1000)
    # Native's local gateway-done byte is initialized to zero and never changed:
    # every matching entry executes, including duplicate gateway IDs.
    for gateway in context.gateway_ids:
        if gateway == b"\x07\x50\x5f":
            if context.gateway_kind == 1:
                add("p5_central_gateway_routine", mode=2)
                wait(1500)
                add("p5_central_gateway_routine", mode=3)
            elif context.gateway_kind == 2:
                add("change_central_gateway_mode")
                wait(1500)
    add("stop_periodic")
    if context.emissions_delay_ms:
        communication_control()
    periodic(context.gateway_kind == 2, 0 if context.emissions_delay_ms else 1000)
    add("start_flow_control_filter")
    if context.extended_addressing:
        add("set_ecu_block_size", size=1)
    add(
        "programming_session",
        request_hex="1002",
        response_prefix_hex="5002",
        minimum_response_bytes=6,
    )
    if not context.emissions_delay_ms:
        add("stop_periodic")
        periodic(context.gateway_kind == 2, 0)
    wait(context.wakeup_ms)
    add("security")
    return tuple(actions)


def reprostd_prepare(
    action: Callable[[dict, float], object],
    exchange: Callable[[str, bytes], bytes],
    ecu: str,
    context: ReproStdPrepareContext,
    key_provider: Callable[[str, bytes], bytes] | None,
    *,
    timeout: float = 30,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
    receive: Callable[[str], bytes] | None = None,
    channel_factory: Callable[..., NativeProgrammingChannel] = NativeProgrammingChannel,
    pending_response_timeout_seconds: int | None = None,
) -> dict:
    """Run recovered preparation against explicit fake/replay dependencies.

    action handles each named platform operation within its supplied seconds.
    Wait actions are injected too; this module never opens a device or sleeps.
    Exceptions/cancellation preserve the operation index, without automatic retry
    or cleanup. A checkpoint is diagnostic evidence, not permission to resume.
    """
    actions = reprostd_prepare_actions(context)
    channel = channel_factory(
        exchange,
        ecu,
        timeout,
        cancelled,
        clock,
        receive,
        pending_response_timeout_seconds=context.pending_timeout_seconds
        if pending_response_timeout_seconds is None
        else pending_response_timeout_seconds,
        pending_timeout_write=lambda target, payload: action(
            {"operation": "write_diagnostic", "payload_hex": payload.hex()},
            channel.deadline - clock(),
        ),
    )
    return _run_prepare_actions(
        action,
        exchange,
        ecu,
        actions,
        key_provider,
        None,
        "static-native-CUW18-ReproStd-prepare",
        timeout,
        cancelled,
        clock,
        receive,
        channel,
    )


def _prepare_native_error_details(error: BaseException) -> dict:
    """Retain native codes without provider messages or diagnostic buffers."""
    from scripts.programming_vendor import _native_error_info

    def bounded(info):
        if not isinstance(info, dict):
            return {}
        domain, code = info.get("native_error_domain"), info.get("native_error_code")
        if (
            domain
            not in (
                "CPassThruException",
                "CJ2534Exception",
                "diagnostic_response",
                None,
            )
            or code is not None
            and (type(code) is not int or not 0 <= code <= 0xFFFFFFFF)
        ):
            return {}
        return {"native_error_domain": domain, "native_error_code": code}

    code = getattr(error, "native_cuw_code", None)
    if type(code) is int and 0 <= code <= 0xFFFFFFFF:
        result = {
            "native_error_domain": "CPassThruException",
            "native_error_code": code,
            "native_cuw_code": code,
        }
    elif isinstance(error, (InterruptedError, TimeoutError)) and not isinstance(
        error, NativePendingTimeout
    ):
        result = {}
    else:
        result = bounded(_native_error_info(error))
    current, seen = error, set()
    for _ in range(16):
        if id(current) in seen:
            break
        seen.add(id(current))
        observed = bounded(getattr(current, "observed_native_error", None))
        if observed and "observed_native_error" not in result:
            result["observed_native_error"] = observed
        cleanup = getattr(current, "cleanup_error_details", None)
        if isinstance(cleanup, (list, tuple)):
            details = result.setdefault("cleanup_error_details", [])
            details.extend(
                detail
                for value in cleanup[: 64 - len(details)]
                if (detail := bounded(value))
            )
        following = current.__cause__ or current.__context__
        if following is None:
            break
        current = following
    return result


def _run_prepare_actions(
    action: Callable[[dict, float], object],
    exchange: Callable[[str, bytes], bytes],
    ecu: str,
    actions: tuple[dict, ...],
    key_provider: Callable[[str, bytes], bytes] | None,
    auth_key: bytes | None,
    provenance: str,
    timeout: float,
    cancelled: Callable[[], bool],
    clock: Callable[[], float],
    receive: Callable[[str], bytes] | None,
    channel: NativeProgrammingChannel | None = None,
) -> dict:
    if key_provider is None:
        raise ValueError("Explicit authorized key provider required before preparation")
    if channel is None:
        channel = NativeProgrammingChannel(
            exchange, ecu, timeout, cancelled, clock, receive
        )
    pending_actions = list(actions)
    gateway_kind = None
    index = 0
    attempted = False
    cleanup: list[dict] = []
    try:
        for index, entry in enumerate(pending_actions):
            if cancelled():
                raise InterruptedError("Preparation cancelled")
            budget = channel.deadline - clock()
            if budget <= 0:
                raise TimeoutError("Preparation deadline expired")
            attempted = True
            operation = entry["operation"]
            if operation == "start_flow_control_filter":
                cleanup.append({"operation": "stop_flow_control_filter"})
            elif operation == "set_ecu_block_size" and entry.get("size") == 1:
                cleanup.insert(0, {"operation": "set_ecu_block_size", "size": 0})
            if operation == "judge_reprogramming_gateway":
                kind = channel._invoke(action, {"operation": operation}, budget)
                if type(kind) is not int or kind not in (1, 2):
                    raise ValueError("Actual native gateway probe must return enum1/2")
                gateway_kind = kind
                pending_actions[index + 1 :] = entry["continuations"][kind]
            elif operation in ("programming_session", "read_software_id"):
                try:
                    response = channel.call(
                        bytes.fromhex(entry["request_hex"]),
                        bytes.fromhex(entry["response_prefix_hex"]),
                    )
                    if len(response) < entry["minimum_response_bytes"]:
                        raise NativeUnexpectedResponse(
                            bytes.fromhex(entry["request_hex"]), response
                        )
                except NativePendingTimeout:
                    if operation != "read_software_id" or not entry.get(
                        "allow_failure"
                    ):
                        raise
                except (InterruptedError, TimeoutError):
                    raise
                except (
                    NativeNegativeResponse,
                    NativeTransportError,
                    NativeDiagnosticError,
                ):
                    if operation != "read_software_id" or not entry.get(
                        "allow_failure"
                    ):
                        raise
            elif operation == "security":
                response = channel.call(b"\x27\x01" + (auth_key or b""), b"\x67\x01")
                if len(response) < 18:
                    raise ValueError("Native seed must contain16 bytes")
                key = channel._invoke(key_provider, ecu, response[2:18])
                if not isinstance(key, bytes) or len(key) != 16:
                    raise ValueError("Authorized provider must return16 key bytes")
                channel.call(b"\x27\x02" + key, b"\x67\x02")
            else:
                channel._invoke(action, dict(entry), budget)
            if clock() >= channel.deadline:
                raise TimeoutError("Preparation action exceeded deadline")
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - no blind replay after interruption
        result = {
            "state": "recovery_required"
            if attempted
            else ("cancelled" if isinstance(exc, InterruptedError) else "failed"),
            "operation_index": index,
            "operation": actions[index]["operation"],
            "error": type(exc).__name__,
            "automatic_retry": False,
            "resume_authorized": False,
            "provenance": provenance,
            "physical_status": "PHYSICAL_UNCONFIRMED",
        }
        result.update(_prepare_native_error_details(exc))
    else:
        result = {
            "state": "preparation_completed",
            "operations": len(actions),
            "programming_completed": False,
            "provenance": provenance,
            "physical_status": "PHYSICAL_UNCONFIRMED",
        }
    if gateway_kind is not None:
        result["gateway_kind"] = gateway_kind
    # Native SEH restores BS and releases the temporary flow filter on both paths.
    # Cleanup has a fresh host budget and remains possible after cancellation.
    cleanup_errors = []
    cleanup_details = []
    cleanup_deadline = clock() + timeout
    for entry in cleanup:
        try:
            budget = cleanup_deadline - clock()
            if budget <= 0:
                raise TimeoutError("Preparation cleanup deadline expired")
            action(entry, budget)
            if clock() >= cleanup_deadline:
                raise TimeoutError("Preparation cleanup exceeded deadline")
        except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - keep remaining cleanup attempts
            cleanup_errors.append(type(error).__name__)
            cleanup_details.append(_prepare_native_error_details(error))
    if cleanup_errors:
        result.setdefault("cleanup_error_details", []).extend(cleanup_details)
        result["cleanup_errors"] = cleanup_errors
        result["state"] = "recovery_required"
    return result


@dataclass(frozen=True)
class ReproStdSegment:
    """Already-resolved transmitted image and original verification metadata."""

    address: int
    data: bytes = field(repr=False)
    signature: bytes = field(repr=False)
    checksum: bytes | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes) or not self.data:
            raise ValueError("Resolved immutable nonempty segment bytes required")
        reprostd_routine_request(
            "verify",
            self.address,
            len(self.data),
            signature=self.signature,
            checksum=self.checksum,
        )


@dataclass(frozen=True)
class ReproStdLogicalBlock:
    method: str
    slot: int
    nonce: bytes = field(repr=False)
    tester_info: bytes
    system_time: tuple[int, int, int, int, int, int, int, int]
    image: ReproStdSegment | None
    routine_package: ReproStdSegment | None = None
    ecu_index: int = 0
    pending_timeout_seconds: int = 180

    def __post_init__(self) -> None:
        if (
            type(self.pending_timeout_seconds) is not int
            or not 0 <= self.pending_timeout_seconds <= 0xFFFFFFFF
        ):
            raise ValueError("Bounded native logical pending seconds required")
        if type(self.ecu_index) is not int or not 0 <= self.ecu_index <= 4095:
            raise ValueError("Resolved native ECU index required")
        if self.method not in ("whole", "delta", "compressed"):
            raise ValueError("Resolved native repro method required")
        if self.image is None and self.method != "delta":
            raise ValueError("Whole/compressed native blocks require an image")
        if self.image is not None and not isinstance(self.image, ReproStdSegment):
            raise ValueError("Resolved native image segment required")
        if self.routine_package is not None and not isinstance(
            self.routine_package, ReproStdSegment
        ):
            raise ValueError("Resolved native routine package required")
        reprostd_fingerprint_requests(
            self.slot, self.nonce, self.tester_info, self.system_time
        )


def reprostd_write(
    action: Callable[[dict, float], None],
    exchange: Callable[[str, bytes], bytes],
    ecu: str,
    blocks: tuple[ReproStdLogicalBlock, ...],
    *,
    extended_addressing: bool = False,
    charge_bus_id: bytes | None = None,
    charge_bus_enable: bool = False,
    timeout: float = 30,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
    receive: Callable[[str], bytes] | None = None,
    channel_factory: Callable[..., NativeProgrammingChannel] = NativeProgrammingChannel,
) -> dict:
    """Recovered ReproStd logical-block writer against explicit fake/replay I/O.

    Caller must separately validate metadata/vehicle selection and preparation.
    Delta/compressed bytes and original signatures are opaque supplied material;
    this function neither generates nor decompresses/reconstructs them. Native
    UI callbacks, charge-bus control and send-timeout configuration are injected.
    Failures preserve position and never authorize a blind resume.
    """
    if (
        not isinstance(blocks, tuple)
        or not 1 <= len(blocks) <= 4096
        or any(not isinstance(block, ReproStdLogicalBlock) for block in blocks)
    ):
        raise ValueError("One to4096 resolved immutable logical blocks required")
    total = sum(
        len(segment.data)
        for block in blocks
        for segment in (block.image, block.routine_package)
        if segment is not None
    )
    if total > 64 * 1024 * 1024:
        raise ValueError("Native writer host limit is64 MiB")
    if charge_bus_id is not None and (
        not isinstance(charge_bus_id, bytes) or len(charge_bus_id) != 2
    ):
        raise ValueError("Resolved two-byte charge bus ID required")
    if type(extended_addressing) is not bool:
        raise ValueError("Resolved native extended addressing flag required")
    if type(charge_bus_enable) is not bool:
        raise ValueError("Resolved native charge bus enable flag required")
    original_exchange = exchange
    original_receive = receive
    operation_count = 0
    response_bytes = 0

    def bounded_exchange(target: str, request: bytes) -> bytes:
        nonlocal operation_count, response_bytes
        if operation_count >= 65536:
            raise ValueError("Host writer exchange limit exceeded")
        return retain_response(original_exchange(target, request))

    def retain_response(response: bytes) -> bytes:
        nonlocal response_bytes, operation_count
        operation_count += 1
        if isinstance(response, bytes):
            response_bytes += len(response)
            if response_bytes > 1024 * 1024:
                raise ValueError("Host writer response budget exceeded")
        return response

    def bounded_receive(target: str) -> bytes:
        if original_receive is None:
            raise ValueError("Explicit receive callback required")
        if operation_count >= 65536:
            raise ValueError("Host writer exchange limit exceeded")
        return retain_response(original_receive(target))

    exchange = bounded_exchange
    receive = bounded_receive if original_receive is not None else None
    channel = channel_factory(
        exchange,
        ecu,
        timeout,
        cancelled,
        clock,
        receive,
        pending_response_timeout_seconds=blocks[0].pending_timeout_seconds,
        pending_timeout_write=lambda target, payload: action(
            {"operation": "write_diagnostic", "payload_hex": payload.hex()},
            channel.deadline - clock(),
        ),
    )
    phase, index = "filter", 0
    attempted = False
    history: list[dict] = []

    def platform(operation: str, *, cleanup: bool = False, **values: object) -> None:
        nonlocal attempted
        if not cleanup and cancelled():
            raise InterruptedError("Writer cancelled")
        budget = channel.deadline - clock()
        if budget <= 0 and not cleanup:
            raise TimeoutError("Writer deadline expired")
        attempted = True
        action({"operation": operation, **values}, max(budget, 0))
        if not cleanup and clock() >= channel.deadline:
            raise TimeoutError("Writer platform action exceeded deadline")

    def routine(operation: str, segment: ReproStdSegment) -> None:
        request, expected = reprostd_routine_request(
            operation,
            segment.address,
            len(segment.data),
            checksum=None if operation == "erase" else segment.checksum,
            signature=None if operation == "erase" else segment.signature,
        )
        channel.call(request, expected)

    def transfer(segment: ReproStdSegment, selector: int) -> None:
        # Native gets the previous transport timeout before RequestDownload.
        platform("save_send_timeout")
        frame_payload = 6 if extended_addressing else 7

        def configure(block_size: int) -> None:
            milliseconds = (
                (block_size + 2 + frame_payload - 1) // frame_payload
            ) * 161 + 1000
            platform("set_send_timeout", milliseconds=milliseconds)

        # Preserve the shared deadline; the fragment itself never retries.
        report = reprostd_transfer(
            exchange,
            ecu,
            segment.address,
            segment.data,
            selector=selector,
            configure_block=configure,
            restore_transport=lambda: platform("restore_send_timeout", cleanup=True),
            timeout=max(channel.deadline - clock(), 1e-12),
            cancelled=cancelled,
            clock=clock,
            receive=receive,
            channel_factory=channel_factory,
            pending_response_timeout_seconds=channel.pending_response_timeout_seconds,
            pending_timeout_write=channel.pending_timeout_write,
        )
        history.append(report)
        if report["state"] != "fragment_completed":
            raise ValueError(report.get("error", "Transfer fragment failed"))

    try:
        platform("start_flow_control_filter")
        for index, block in enumerate(blocks):
            channel.pending_response_timeout_seconds = block.pending_timeout_seconds
            phase = "fingerprint"
            platform("select_logical_block", index=index)
            for request, expected in reprostd_fingerprint_requests(
                block.slot, block.nonce, block.tester_info, block.system_time
            ):
                channel.call(request, expected)
            if block.routine_package is not None:
                phase = "routine_package"
                transfer(block.routine_package, 1)
                routine("routine_check", block.routine_package)
            platform("set_reprogramming_active", active=True)
            if block.image is not None:
                if block.method != "delta":
                    phase = "erase"
                    routine("erase", block.image)
                phase = "transfer"
                transfer(
                    block.image,
                    {"whole": 1, "delta": 0x21, "compressed": 0x11}[block.method],
                )
                phase = "verify"
                routine("verify", block.image)
            if (
                index + 1 < len(blocks)
                and block.ecu_index != blocks[index + 1].ecu_index
            ):
                platform("logical_block_boundary", index=index)
        phase = "reset"
        channel.pending_response_timeout_seconds = 180
        channel.call(b"\x11\x01", b"\x51\x01")
        phase = "finish"
        if charge_bus_id is not None:
            platform(
                "charge_local_bus",
                diagnostic_id_hex=charge_bus_id.hex(),
                mode=1,
                enable=charge_bus_enable,
            )
        platform("stop_periodic")
        platform("raw_write", data_hex="000007771081", tx_flags=0)
        platform("raw_write", data_hex="0000077ffe1081", tx_flags=0x80)
        platform("set_reprogramming_active", active=False)
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - retain uncertainty, never restart erase
        return {
            "state": "recovery_required"
            if attempted or channel.attempted
            else ("cancelled" if isinstance(exc, InterruptedError) else "failed"),
            "phase": phase,
            "logical_block": index,
            "error": type(exc).__name__,
            "automatic_retry": False,
            "resume_authorized": False,
            "transfers": history,
            "provenance": "static-native-CUW18-ReproStd-writer",
            "physical_status": "PHYSICAL_UNCONFIRMED",
        }
    return {
        "state": "writer_completed",
        "logical_blocks": len(blocks),
        "transfers": history,
        "programming_completed": False,
        "provenance": "static-native-CUW18-ReproStd-writer",
        "physical_status": "PHYSICAL_UNCONFIRMED",
    }


def unified_fingerprint_requests(
    offset_address: bytes, calibration_key: bytes, nonce: bytes
) -> tuple[tuple[bytes, bytes], ...]:
    """Recovered CUW18 Unified2e records, using supplied calibration material.

    No key/nonce is generated or included in a report. This pure builder performs
    no exchange; the caller owns authorization for the supplied original values.
    """
    for value, size in ((offset_address, 5), (calibration_key, 16), (nonce, 16)):
        if not isinstance(value, bytes) or len(value) != size:
            raise ValueError("Supplied native Unified offset/key/nonce widths required")
    return tuple(
        (b"\x2e\x02" + bytes((did,)) + value, b"\x6e\x02" + bytes((did,)))
        for did, value in ((3, offset_address), (1, calibration_key), (2, nonce))
    )


def unified_routine_request(
    operation: str, offset_address: int, address: int, size: int
) -> tuple[bytes, bytes]:
    """Unified routine uses40-bit offset+address and32-bit size (format45)."""
    operations = {
        "stub_check": b"\x10\xf0",
        "erase": b"\xff\x00",
        "routine_check": b"\x10\xf1",
        "verify": b"\x10\xf2",
    }
    if not isinstance(operation, str) or operation not in operations:
        raise ValueError("Unknown native Unified routine operation")
    reprostd_download_request(address, size)
    if type(offset_address) is not int or not 0 <= offset_address <= 0xFFFFFFFFFF:
        raise ValueError("Native Unified offset address must be uint40")
    combined = offset_address + address
    if combined > 0xFFFFFFFFFF:
        raise ValueError("Native Unified absolute address overflow")
    identifier = operations[operation]
    return (
        b"\x31\x01"
        + identifier
        + b"\x45"
        + combined.to_bytes(5, "big")
        + size.to_bytes(4, "big"),
        b"\x71\x01" + identifier,
    )


def unified_download_request(
    offset_address: int, address: int, size: int, *, encrypted: bool, memory_type: int
) -> bytes:
    """Native Unified format46 includes memory type and40-bit absolute address."""
    _, _ = unified_routine_request("erase", offset_address, address, size)
    if (
        type(encrypted) is not bool
        or type(memory_type) is not int
        or memory_type not in (0, 1)
    ):
        raise ValueError("Resolved Unified encryption bit and memory type0/1 required")
    return (
        b"\x34"
        + bytes((int(encrypted), 0x46, memory_type))
        + (offset_address + address).to_bytes(5, "big")
        + size.to_bytes(4, "big")
    )


@dataclass(frozen=True)
class UnifiedArea:
    address: int
    data: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes) or not self.data:
            raise ValueError("Resolved native Unified area bytes required")
        reprostd_download_request(self.address, len(self.data))


@dataclass(frozen=True)
class UnifiedProgram:
    """Resolved native Unified headers/material for one CPU image, not approval."""

    offset_address: bytes
    calibration_key: bytes = field(repr=False)
    nonce: bytes = field(repr=False)
    security_property: int
    stub: tuple[UnifiedArea, ...]
    routine: tuple[UnifiedArea, ...]
    image: tuple[UnifiedArea, ...]
    erase: tuple[tuple[int, int], ...]
    last_cpu_in_node: bool
    wakeup_ms: int
    extended_addressing: bool = False

    def __post_init__(self) -> None:
        unified_fingerprint_requests(
            self.offset_address, self.calibration_key, self.nonce
        )
        if (
            type(self.security_property) is not int
            or not 0 <= self.security_property <= 255
        ):
            raise ValueError("Original native security property byte required")
        if (
            type(self.last_cpu_in_node) is not bool
            or type(self.extended_addressing) is not bool
        ):
            raise ValueError("Resolved native CPU-boundary/address flags required")
        if (
            type(self.wakeup_ms) is not int
            or not 0 <= self.wakeup_ms <= 120000
            or self.wakeup_ms % 50
        ):
            # Native decrements until exactly zero; nonmultiples would never finish.
            raise ValueError("Unified wake-up delay must be bounded multiples of50 ms")
        total, count = 0, 0
        offset = int.from_bytes(self.offset_address, "big")
        for areas in (self.stub, self.routine, self.image):
            if not isinstance(areas, tuple) or len(areas) > 4096:
                raise ValueError("Bounded immutable native area lists required")
            for area in areas:
                if not isinstance(area, UnifiedArea):
                    raise TypeError("Resolved native Unified area required")
                unified_routine_request("verify", offset, area.address, len(area.data))
                total += len(area.data)
                count += 1
        if not self.image or count > 4096 or total > 64 * 1024 * 1024:
            raise ValueError("Nonempty image within4096 areas/64 MiB required")
        if not isinstance(self.erase, tuple) or len(self.erase) > 4096:
            raise ValueError("Bounded explicit erase area list required")
        for span in self.erase:
            if not isinstance(span, tuple) or len(span) != 2:
                raise ValueError("Explicit native erase address/size pair required")
            unified_routine_request("erase", offset, *span)


def unified12_block_size(response: bytes) -> int:
    """CUW12 fixed LFID20 download response; reject native zero/negative capacity."""
    if (
        not isinstance(response, bytes)
        or not 4 <= len(response) <= 4095
        or response[:2] != b"\x74\x20"
    ):
        raise ValueError("Native CUW12 download requires7420 plus two-byte capacity")
    maximum = int.from_bytes(response[2:4], "big")
    if maximum < 3:
        raise ValueError("Native CUW12 capacity cannot make bounded progress")
    return min(maximum, 4095) - 2


def native_unified_pending_timeout(
    container: CalibrationContainer, cpu_index: int, *, native_build: int = 18
) -> int:
    """Native P5 elapsed seconds: build12 constant180, build18 CPU minutes*60."""
    if type(native_build) is not int or native_build not in (12, 18):
        raise ValueError("Explicit recovered native build12/18 required")
    cpus = bind_native_cpu_records(container)
    if type(cpu_index) is not int or not 0 <= cpu_index < len(cpus):
        raise ValueError("Selected native CPU index does not exist")
    if native_build == 12:
        return 180
    try:
        minutes = int(cpus[cpu_index].values.get("p4servermaxtime", "03"), 10)
    except ValueError as error:
        raise ValueError("Native P4ServerMaxTime requires decimal minutes") from error
    if not 0 <= minutes <= 0xFFFFFFFF // 60:
        raise ValueError("Native P4ServerMaxTime exceeds bounded seconds")
    return minutes * 60


def native_unified_program(
    container: CalibrationContainer,
    cpu_index: int,
    observed_cids: tuple[str, ...],
    *,
    extended_addressing: bool,
) -> UnifiedProgram:
    """Bind native Unified headers and S-record areas without inferred geometry.

    All three transmitted area groups come from the selected CPU image archive,
    as in native MakeSendData; FlashCode is not substituted for a routine area.
    """
    cpus = bind_native_cpu_records(container)
    if type(cpu_index) is not int or not 0 <= cpu_index < len(cpus):
        raise ValueError("Selected native CPU index does not exist")
    if (
        not isinstance(observed_cids, tuple)
        or not 0 < len(observed_cids) <= 4096
        or any(
            not isinstance(cid, str) or not cid or len(cid) > 256
            for cid in observed_cids
        )
    ):
        raise ValueError("Explicit bounded native CID observations required")
    cpu = cpus[cpu_index]
    if cpu.node == 0:
        raise ValueError("Unified writing requires populated native node metadata")
    values = cpu.values
    try:
        count = int(values.get("numberoftargets", "0"))
        if not 1 <= count <= 4096:
            raise ValueError("Bounded native target count required")
        targets = tuple(
            values[f"{index:02}_targetcalibration"] for index in range(1, count + 1)
        )
        offset = bytes.fromhex(values["offsetaddress"])
        key = bytes.fromhex(values["seedkey"])
        nonce = bytes.fromhex(values["nonce"])
        security = bytes.fromhex(values["securityproperty2"])
    except (KeyError, ValueError) as error:
        raise ValueError("Missing or invalid original Unified CPU metadata") from error
    if not set(targets).intersection(observed_cids):
        raise ValueError("Observed CID does not match selected native CPU targets")
    if len(security) != 1 or cpu.image is None:
        raise ValueError("Original Unified security byte and CPU archive required")

    source = cpu.image.data
    geometry_groups = (
        cpu.erase_routine_areas,
        cpu.write_routine_areas,
        cpu.image_areas,
    )
    if (
        sum(len(group) for group in geometry_groups) > 4096
        or sum(size for group in geometry_groups for _, size in group)
        > 64 * 1024 * 1024
    ):
        raise ValueError(
            "Unified materialization exceeds4096 areas/64MiB before allocation"
        )

    def areas(geometry):
        return tuple(
            UnifiedArea(address, materialize_native_srecord_area(source, address, size))
            for address, size in geometry
        )

    wake = _native_prepare_values(cpu.node_values)["wakeup_ms"]
    return UnifiedProgram(
        offset,
        key,
        nonce,
        security[0],
        areas(cpu.erase_routine_areas),
        areas(cpu.write_routine_areas),
        areas(cpu.image_areas),
        cpu.image_areas,
        not any(other.node == cpu.node for other in cpus[cpu_index + 1 :]),
        wake,
        extended_addressing,
    )


def unified_write(
    action: Callable[[dict, float], None],
    exchange: Callable[[str, bytes], bytes],
    ecu: str,
    program: UnifiedProgram,
    *,
    each_area: bool = False,
    native_build: int = 18,
    pending_response_timeout_seconds: float | None = None,
    timeout: float = 30,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
    receive: Callable[[str], bytes] | None = None,
    channel_factory: Callable[..., NativeProgrammingChannel] = NativeProgrammingChannel,
) -> dict:
    """CUW18 Unified CPU writer, using explicit fake/replay and platform actions.

    Supplied calibration key/nonce are forwarded verbatim, never computed or
    reported. Resolved area bytes and erase geometry must come from a validated
    calibration context; this runner does not select a vehicle or resume a write.
    """
    if not isinstance(program, UnifiedProgram):
        raise TypeError("Resolved native Unified program required")
    if type(native_build) is not int or native_build not in (12, 18):
        raise ValueError("Explicit recovered native build12/18 required")
    if native_build == 12 and each_area:
        raise ValueError("Native EachArea writer exists only in recovered build18")
    if type(each_area) is not bool:
        raise ValueError("Explicit native EachArea mode required")
    if each_area and (
        len(program.stub) not in (0, len(program.image))
        or len(program.routine) not in (0, len(program.image))
        or program.erase
        != tuple((area.address, len(area.data)) for area in program.image)
    ):
        raise ValueError(
            "Native EachArea requires parallel headers and image erase geometry"
        )
    channel = channel_factory(
        exchange,
        ecu,
        timeout,
        cancelled,
        clock,
        receive,
        pending_response_timeout_seconds=180
        if native_build == 12
        else pending_response_timeout_seconds,
        pending_timeout_write=lambda target, payload: action(
            {"operation": "write_diagnostic", "payload_hex": payload.hex()},
            channel.deadline - clock(),
        ),
    )
    offset = int.from_bytes(program.offset_address, "big")
    phase, area_index = "filter", 0
    image_index = 0
    attempted = False
    transferred = 0

    def platform(operation: str, *, cleanup: bool = False, **values: object) -> None:
        nonlocal attempted
        if not cleanup and cancelled():
            raise InterruptedError("Unified writer cancelled")
        budget = channel.deadline - clock()
        if budget <= 0 and not cleanup:
            raise TimeoutError("Unified writer deadline expired")
        attempted = True
        action({"operation": operation, **values}, max(budget, 0))
        if not cleanup and clock() >= channel.deadline:
            raise TimeoutError("Unified platform action exceeded deadline")

    def routines(operation: str, spans: tuple[tuple[int, int], ...]) -> None:
        nonlocal area_index
        for area_index, (address, size) in enumerate(spans):
            channel.call(*unified_routine_request(operation, offset, address, size))

    def download(areas: tuple[UnifiedArea, ...], memory_type: int) -> None:
        nonlocal area_index, transferred
        platform("save_send_timeout")
        frame_payload = 6 if program.extended_addressing else 7

        def configure(block_size: int) -> None:
            milliseconds = (
                (block_size + 2 + frame_payload - 1) // frame_payload
            ) * 161 + 1000
            platform("set_send_timeout", milliseconds=milliseconds)

        for area_index, area in enumerate(areas):
            progress = {"phase": "download", "transferred": 0, "next_sequence": 1}
            request = unified_download_request(
                offset,
                area.address,
                len(area.data),
                encrypted=bool(program.security_property & 8),
                memory_type=memory_type,
            )
            try:
                _download_transfer(
                    channel,
                    request,
                    area.data,
                    progress,
                    configure,
                    lambda: platform("restore_send_timeout", cleanup=True),
                    block_size_decoder=unified12_block_size
                    if native_build == 12
                    else reprostd_block_size,
                )
            finally:
                transferred += progress["transferred"]

    try:
        platform("start_flow_control_filter")
        if each_area:
            for image_index, area in enumerate(program.image):
                phase = "fingerprint"
                for request, expected in unified_fingerprint_requests(
                    program.offset_address, program.calibration_key, program.nonce
                ):
                    channel.call(request, expected)
                if program.stub:
                    phase = "stub_download"
                    download((program.stub[image_index],), 1)
                    phase = "stub_check"
                    routines(
                        "stub_check",
                        (
                            (
                                program.stub[image_index].address,
                                len(program.stub[image_index].data),
                            ),
                        ),
                    )
                platform("set_reprogramming_active", active=True)
                phase = "erase"
                routines("erase", ((area.address, len(area.data)),))
                if program.routine:
                    phase = "routine_download"
                    download((program.routine[image_index],), 1)
                    phase = "routine_check"
                    routines(
                        "routine_check",
                        (
                            (
                                program.routine[image_index].address,
                                len(program.routine[image_index].data),
                            ),
                        ),
                    )
                phase = "image_download"
                download((area,), 0)
                phase = "verify"
                routines("verify", ((area.address, len(area.data)),))
        else:
            phase = "fingerprint"
            for request, expected in unified_fingerprint_requests(
                program.offset_address, program.calibration_key, program.nonce
            ):
                channel.call(request, expected)
            phase = "stub_download"
            download(program.stub, 1)
            phase = "stub_check"
            routines(
                "stub_check", tuple((a.address, len(a.data)) for a in program.stub)
            )
            platform("set_reprogramming_active", active=True)
            phase = "erase"
            routines("erase", program.erase)
            phase = "routine_download"
            download(program.routine, 1)
            phase = "routine_check"
            routines(
                "routine_check",
                tuple((a.address, len(a.data)) for a in program.routine),
            )
            phase = "image_download"
            download(program.image, 0)
            phase = "verify"
            routines("verify", tuple((a.address, len(a.data)) for a in program.image))
        if program.last_cpu_in_node:
            phase = "reset"
            channel.pending_response_timeout_seconds = 180
            channel.call(b"\x11\x01", b"\x51\x01")
            platform("stop_periodic")
            for _ in range(program.wakeup_ms // 50):
                platform("wait", milliseconds=50)
                platform("wake_up_progress")
            phase = "finish"
            platform("raw_write", data_hex="000007771081", tx_flags=0)
            platform("raw_write", data_hex="0000077ffe1081", tx_flags=0x80)
        else:
            platform("cpu_boundary")
        platform("set_reprogramming_active", active=False)
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - never restart after uncertain programming
        return {
            "state": "recovery_required"
            if attempted or channel.attempted
            else ("cancelled" if isinstance(exc, InterruptedError) else "failed"),
            "phase": phase,
            "area": image_index if each_area else area_index,
            "transferred": transferred,
            "error": type(exc).__name__,
            "automatic_retry": False,
            "resume_authorized": False,
            "provenance": f"static-native-CUW{native_build}-Unified-writer",
            "physical_status": "PHYSICAL_UNCONFIRMED",
        }
    return {
        "state": "writer_completed",
        "transferred": transferred,
        "programming_completed": False,
        "provenance": f"static-native-CUW{native_build}-Unified-writer",
        "physical_status": "PHYSICAL_UNCONFIRMED",
    }


@dataclass(frozen=True)
class UnifiedPrepareContext:
    wakeup_ms: int
    emissions_delay_ms: int
    ecu_auth_key: bytes = field(repr=False)
    gateway_kind: int = 0
    gateway_ids: tuple[bytes, ...] = ()
    diag_id: bytes = b""
    native_flag_724: bool = False
    extended_addressing: bool = False
    gateway_id_texts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        ReproStdPrepareContext(
            self.wakeup_ms,
            self.emissions_delay_ms,
            self.gateway_kind,
            self.gateway_ids,
            extended_addressing=self.extended_addressing,
        )
        if not isinstance(self.ecu_auth_key, bytes) or len(self.ecu_auth_key) != 16:
            raise ValueError(
                "Original native ECU authorization key must contain16 bytes"
            )
        if not isinstance(self.diag_id, bytes) or len(self.diag_id) not in (0, 2, 3):
            raise ValueError("Resolved native diagnostic ID required")
        if type(self.native_flag_724) is not bool:
            raise ValueError("Explicit native caller flag+724 required")
        if (
            not isinstance(self.gateway_id_texts, tuple)
            or self.gateway_id_texts
            and len(self.gateway_id_texts) != len(self.gateway_ids)
        ):
            raise ValueError("Original native gateway string rows required")
        for text, identifier in zip(self.gateway_id_texts, self.gateway_ids):
            if (
                not isinstance(text, str)
                or len(text) != len(identifier) * 2
                or bytes.fromhex(text) != identifier
            ):
                raise ValueError("Native gateway text and decoded ID differ")


def unified_prepare_actions(
    context: UnifiedPrepareContext, *, native_build: int = 18
) -> tuple[dict, ...]:
    """Unified native preparation; flag+724 retains its proven offset name."""
    if not isinstance(context, UnifiedPrepareContext):
        raise TypeError("Resolved native Unified preparation context required")
    if type(native_build) is not int or native_build not in (12, 18):
        raise ValueError("Explicit recovered native build12/18 required")
    if native_build == 12:
        return _unified12_prepare_actions(context)
    gateway_texts = context.gateway_id_texts or tuple(
        value.hex().upper() for value in context.gateway_ids
    )
    if context.gateway_kind == 0 and gateway_texts[:1] == ("07505F",):
        from dataclasses import replace

        variants = {
            kind: unified_prepare_actions(
                replace(context, gateway_kind=kind), native_build=18
            )[2:]
            for kind in (1, 2)
        }
        return (
            {"operation": "set_previous_send_time"},
            {"operation": "wait", "milliseconds": context.wakeup_ms},
            {"operation": "judge_reprogramming_gateway", "continuations": variants},
        )
    builder = _CanPrepareActions(context.gateway_kind)
    add, wait, raw, keepalive, periodic = (
        builder.add,
        builder.wait,
        builder.raw,
        builder.keepalive,
        builder.periodic,
    )

    def communication_control() -> None:
        raw(0x777, b"\x28\x81\x01")
        if not context.emissions_delay_ms:
            wait(1000)
            keepalive()
            wait(1000)
        raw(0x77F, b"\xfe\x28\x81\x01", True)
        remaining = context.emissions_delay_ms
        if remaining:
            while remaining > 2000:
                wait(2000)
                keepalive()
                remaining -= 2000
            wait(remaining)
        else:
            wait(1000)

    add("set_previous_send_time")
    wait(context.wakeup_ms)
    for gateway in gateway_texts:
        if gateway == "07505F" and context.gateway_kind == 2:
            add("authorize_central_gateway")
    raw(0x777, b"\x10\x83")
    wait(1000)
    keepalive()
    wait(1000)
    raw(0x77F, b"\xfe\x10\x83", True)
    wait(1000)
    periodic(context.gateway_kind == 2, 1000)
    add(
        "cancel_automatic_ig_off",
        enable=context.native_flag_724 and context.diag_id == b"\x07\x50\xe9",
    )
    if context.gateway_kind == 1:
        add("authorize_p5_central_gateway")
        add("p5_central_gateway_routine", mode=0)
        wait(1500)
        add("p5_central_gateway_routine", mode=1)
    add("stop_periodic")
    raw(0x777, b"\x85\x82")
    wait(1000)
    keepalive()
    wait(1000)
    raw(0x77F, b"\xfe\x85\x82", True)
    wait(1000)
    keepalive()
    wait(1000)
    add("diagnostic_mask")
    wait(900)
    if not context.emissions_delay_ms:
        keepalive()
        wait(1000)
        communication_control()
    periodic(context.gateway_kind == 2, 1000)
    add("start_flow_control_filter")
    if context.extended_addressing:
        add("set_ecu_block_size", size=1)
    add(
        "read_software_id",
        request_hex="22f181",
        response_prefix_hex="62f181",
        minimum_response_bytes=4,
        allow_failure=context.native_flag_724,
    )
    add("stop_periodic")
    periodic(False, 1000)
    for gateway in gateway_texts:
        if gateway == "07505F":
            if context.gateway_kind == 1:
                add("p5_central_gateway_routine", mode=2)
                wait(1500)
                add("p5_central_gateway_routine", mode=3)
            else:
                add("change_central_gateway_mode")
                wait(1500)
    add("stop_periodic")
    if context.emissions_delay_ms:
        communication_control()
    periodic(context.gateway_kind == 2, 0 if context.emissions_delay_ms else 1000)
    add(
        "programming_session",
        request_hex="1002",
        response_prefix_hex="5002",
        minimum_response_bytes=6,
    )
    if not context.emissions_delay_ms:
        add("stop_periodic")
        periodic(context.gateway_kind == 2, 0)
    wait(2000)
    add("security")
    return tuple(builder.actions)


def _unified12_prepare_actions(context: UnifiedPrepareContext) -> tuple[dict, ...]:
    gateway_texts = context.gateway_id_texts or tuple(
        value.hex().upper() for value in context.gateway_ids
    )
    # Native12 always includes the extended central gateway in keepalive lists.
    builder = _CanPrepareActions(2)
    add, wait, raw = builder.add, builder.wait, builder.raw
    add("set_previous_send_time")
    wait(context.wakeup_ms)
    for gateway in gateway_texts:
        if gateway == "07505F":
            add("authorize_central_gateway")
    if context.extended_addressing:
        add("set_ecu_block_size", size=1)
    add("start_flow_control_filter")
    for payload in (b"\x10\x83", b"\x85\x82"):
        raw(0x777, payload)
        wait(1000)
        builder.keepalive()
        wait(1000)
        raw(0x77F, b"\xfe" + payload, True)
        wait(1000)
        builder.keepalive()
        wait(1000)
    add("diagnostic_mask")
    wait(900)
    builder.keepalive()
    wait(1000)
    raw(0x777, b"\x28\x81\x01")
    wait(1000)
    builder.keepalive()
    wait(1000)
    raw(0x77F, b"\xfe\x28\x81\x01", True)
    wait(1000)
    builder.periodic(True, 1000)
    add(
        "read_software_id",
        request_hex="22f181",
        response_prefix_hex="62f181",
        minimum_response_bytes=4,
        allow_failure=context.native_flag_724,
    )
    add("stop_periodic")
    builder.periodic(False, 1000)
    for gateway in gateway_texts:
        if gateway == "07505F":
            add("change_central_gateway_mode")
            wait(1500)
    add("stop_periodic")
    builder.periodic(True, 1000)
    add(
        "programming_session",
        request_hex="1002",
        response_prefix_hex="5002",
        minimum_response_bytes=6,
    )
    add("stop_periodic")
    builder.periodic(True, 0)
    wait(2000)
    add("security")
    return tuple(builder.actions)


def unified_prepare(
    action: Callable[[dict, float], object],
    exchange: Callable[[str, bytes], bytes],
    ecu: str,
    context: UnifiedPrepareContext,
    key_provider: Callable[[str, bytes], bytes] | None,
    *,
    native_build: int = 18,
    pending_response_timeout_seconds: float | None = None,
    timeout: float = 30,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
    receive: Callable[[str], bytes] | None = None,
    channel_factory: Callable[..., NativeProgrammingChannel] = NativeProgrammingChannel,
) -> dict:
    """Recovered Unified preparation with supplied ECU auth key and key provider.

    Native caller flag+724 conditionally permits software-ID read failure; its
    semantic name is not guessed. Host cancellation/deadline failures always stop.
    No secret is calculated or included in action plans or returned reports.
    """
    actions = unified_prepare_actions(context, native_build=native_build)
    channel = channel_factory(
        exchange,
        ecu,
        timeout,
        cancelled,
        clock,
        receive,
        pending_response_timeout_seconds=180
        if native_build == 12
        else pending_response_timeout_seconds,
        pending_timeout_write=lambda target, payload: action(
            {"operation": "write_diagnostic", "payload_hex": payload.hex()},
            channel.deadline - clock(),
        ),
    )
    return _run_prepare_actions(
        action,
        exchange,
        ecu,
        actions,
        key_provider,
        context.ecu_auth_key,
        f"static-native-CUW{native_build}-Unified-prepare",
        timeout,
        cancelled,
        clock,
        receive,
        channel,
    )


_NATIVE_DATA = {
    "slave_cid": (b"\x22\x01\x28", b"\x62\x01\x28", 17, "p5"),
    "assembly_p5": (b"\x22\x01\x05", b"\x62\x01\x05", 3, "p5"),
    "assembly_p4": (b"\x1a\x89", b"\x5a", 1, "old"),
    "serial": (b"\x22\xf1\x8c", b"\x62\xf1\x8c", 3, "p5"),
    "cbest": (b"\x22\x02\x10", b"\x62\x02\x10", 3, "p5"),
}


def native_data_request(name: str) -> dict:
    """Recovered CanDiagCommUtils helper request and required utility policy."""
    if not isinstance(name, str) or name not in _NATIVE_DATA:
        raise ValueError("Unknown native CAN data helper")
    request, prefix, minimum, policy = _NATIVE_DATA[name]
    return {
        "request_hex": request.hex(),
        "response_prefix_hex": prefix.hex(),
        "minimum_response_bytes": minimum,
        "utility_policy": policy,
    }


def decode_native_data(name: str, response: bytes) -> str | list[dict]:
    """Decode only native helper data; no request is sent or vehicle inferred.

    Native ignores trailing partial slave records and filters invalid ASCII. The
    assembly helper replaces leading NUL bytes with literal'I', then C-string
    truncates; this unusual native behavior is retained, not normalized away.
    """
    native_data_request(name)
    _, prefix, minimum, _ = _NATIVE_DATA[name]
    if (
        not isinstance(response, bytes)
        or not minimum <= len(response) <= 4116
        or not response.startswith(prefix)
    ):
        raise ValueError("Malformed native CAN data helper response")
    if name == "slave_cid":
        result = []
        for index in range((len(response) - 4) // 13):
            record = response[4 + 13 * index : 17 + 13 * index]
            text = record[1:]
            if text[0] and all(byte == 0 or 0x20 <= byte <= 0x7E for byte in text):
                result.append(
                    {"node": record[0], "cid": text.split(b"\0", 1)[0].decode("ascii")}
                )
        return result
    payload = response[len(prefix) :]
    if name == "cbest":
        return payload[:50].hex().upper()
    payload = payload[: 256 if name == "serial" else 12]
    if any(byte != 0 and not 0x20 <= byte <= 0x7E for byte in payload):
        return ""
    if name.startswith("assembly"):
        leading = len(payload) - len(payload.lstrip(b"\0"))
        if leading == len(payload):
            return ""
        payload = b"I" * leading + payload[leading:]
    return payload.split(b"\0", 1)[0].decode("ascii")


def ethernet_request(target: bytes, payload: bytes) -> bytes:
    """Recovered CUW18 diagnostic TCP frame, tester0e80 and type8001.

    The injected J2534-style read callback returns address[4]+UDS, as native
    ReadMsgForTCP does, while this builder returns the complete written frame.
    """
    if (
        not isinstance(target, bytes)
        or len(target) != 2
        or not isinstance(payload, bytes)
        or not 0 < len(payload) <= 4116
    ):
        raise ValueError(
            "Two-byte Ethernet logical target and bounded UDS bytes required"
        )
    body = b"\x0e\x80" + target + payload
    return b"\x02\xfd\x80\x01" + len(body).to_bytes(4, "big") + body


def ethernet_block_size(response: bytes) -> int:
    """Native Ethernet writer caps total transfer message at0x1014 bytes.

    Preserve native x86 modulo32 shift positions for widths beyond four bytes;
    interpreting the field as an arbitrary-precision integer would differ.
    """
    if not isinstance(response, bytes) or len(response) < 3 or response[0] != 0x74:
        raise ValueError("Expected native Ethernet download response")
    width = response[1] >> 4
    if not 1 <= width <= 15 or len(response) < 2 + width:
        raise ValueError("Malformed native Ethernet download block length")
    maximum = 0
    for index, byte in enumerate(reversed(response[2 : 2 + width])):
        maximum += byte << ((index * 8) & 31)
        maximum &= 0xFFFFFFFF
        if maximum > 0x1014:
            maximum = 0x1014
            break
    if maximum < 3:
        raise ValueError("Native Ethernet block cannot contain data")
    return maximum - 2


class NativeEthernetChannel(NativeProgrammingChannel):
    """Recovered Ethernet address filtering/frame wrapper around bounded UDS.

    exchange receives full diagnostic TCP frame. Its response and receive return
    the native J2534 ReadMsgForTCP result: source[2],target[2],UDS. The caller must
    explicitly provide fake/replay callbacks and link/routing platform actions.
    No socket, UDP discovery, network interface or J2534 provider is opened.
    """

    def __init__(
        self,
        exchange: Callable[[str, bytes], bytes],
        ecu: str,
        target: bytes,
        timeout: float = 30,
        cancelled: Callable[[], bool] = lambda: False,
        clock: Callable[[], float] = time.monotonic,
        receive: Callable[[str], bytes] | None = None,
    ):
        ethernet_request(target, b"\x3e")
        self.target = target
        self.raw_messages = 0
        self.raw_response_bytes = 0

        def matched(response: bytes) -> bytes:
            for _ in range(4096):
                self.raw_messages += 1
                if not isinstance(response, bytes) or not 5 <= len(response) <= 4120:
                    raise ValueError("Malformed native Ethernet addressed response")
                self.raw_response_bytes += len(response)
                if self.raw_messages > 65536 or self.raw_response_bytes > 1024 * 1024:
                    raise ValueError("Native Ethernet host response budget exceeded")
                if response[:4] == target + b"\x0e\x80":
                    return response[4:]
                if receive is None:
                    raise ValueError(
                        "Unmatched Ethernet address requires explicit receive callback"
                    )
                if cancelled():
                    raise InterruptedError("Ethernet address filtering cancelled")
                if clock() >= self.deadline:
                    raise TimeoutError("Ethernet address filtering deadline expired")
                response = receive(ecu)
            raise ValueError("Native Ethernet address filtering limit exceeded")

        def wrapped_exchange(target_ecu: str, request: bytes) -> bytes:
            return matched(exchange(target_ecu, ethernet_request(target, request)))

        def wrapped_receive(target_ecu: str) -> bytes:
            if receive is None:
                raise ValueError("Explicit Ethernet receive callback required")
            return matched(receive(target_ecu))

        super().__init__(
            wrapped_exchange,
            ecu,
            timeout,
            cancelled,
            clock,
            wrapped_receive if receive is not None else None,
            message_limit=4116,
        )


def ethernet_write(
    action: Callable[[dict, float], None],
    exchange: Callable[[str, bytes], bytes],
    ecu: str,
    target: bytes,
    blocks: tuple[ReproStdLogicalBlock, ...],
    *,
    wakeup_ms: int = 0,
    timeout: float = 30,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
    receive: Callable[[str], bytes] | None = None,
) -> dict:
    """Recovered CUW18 Ethernet ReproStd whole-image writer against fake/replay.

    Distinct Ethernet frame/block/error policies are retained. Only explicit
    NativeTransportError codes9/16 permit up to two native36-block retransmits;
    arbitrary timeout/connection exceptions stop without retry. The provider
    supplies native utility-level error observations, never guessed from Python.
    """
    if (
        not isinstance(blocks, tuple)
        or not 1 <= len(blocks) <= 4096
        or any(
            not isinstance(b, ReproStdLogicalBlock)
            or b.method != "whole"
            or b.image is None
            for b in blocks
        )
    ):
        raise ValueError("Native Ethernet writer requires resolved whole-image blocks")
    if type(wakeup_ms) is not int or not 0 <= wakeup_ms <= 120000 or wakeup_ms % 50:
        raise ValueError("Ethernet wake-up delay must be bounded multiples of50 ms")
    if (
        sum(
            len(segment.data)
            for block in blocks
            for segment in (block.image, block.routine_package)
            if segment is not None
        )
        > 64 * 1024 * 1024
    ):
        raise ValueError("Ethernet writer host image budget exceeded")
    channel = NativeEthernetChannel(
        exchange, ecu, target, timeout, cancelled, clock, receive
    )
    phase, index = "fingerprint", 0
    attempted = False
    transferred = 0
    cleanup_errors: list[str] = []

    def platform(operation: str, *, cleanup: bool = False, **values: object) -> None:
        nonlocal attempted
        if not cleanup and cancelled():
            raise InterruptedError("Ethernet writer cancelled")
        budget = channel.deadline - clock()
        if budget <= 0 and not cleanup:
            raise TimeoutError("Ethernet writer deadline expired")
        attempted = True
        action({"operation": operation, **values}, max(budget, 0))
        if not cleanup and clock() >= channel.deadline:
            raise TimeoutError("Ethernet writer action exceeded deadline")

    def routine(operation: str, segment: ReproStdSegment) -> None:
        channel.call(
            *reprostd_routine_request(
                operation,
                segment.address,
                len(segment.data),
                checksum=None if operation == "erase" else segment.checksum,
                signature=None if operation == "erase" else segment.signature,
            )
        )

    def transfer(segment: ReproStdSegment) -> None:
        nonlocal transferred
        progress = {"phase": "download", "transferred": 0, "next_sequence": 1}
        try:
            _download_transfer(
                channel,
                reprostd_download_request(segment.address, len(segment.data)),
                segment.data,
                progress,
                block_size_decoder=ethernet_block_size,
                transport_retries=2,
            )
        finally:
            transferred += progress["transferred"]

    try:
        for index, block in enumerate(blocks):
            phase = "fingerprint"
            platform("select_logical_block", index=index)
            if target == b"\x01\x03":
                platform(
                    "set_wakeup_progress",
                    milliseconds=wakeup_ms
                    if block.ecu_index == blocks[-1].ecu_index
                    else 0,
                )
            for request, expected in reprostd_fingerprint_requests(
                block.slot, block.nonce, block.tester_info, block.system_time
            ):
                channel.call(request, expected)
            if block.routine_package is not None:
                phase = "routine_package"
                transfer(block.routine_package)
                routine("routine_check", block.routine_package)
            platform("set_reprogramming_active", active=True)
            # Constructor validation above proves the whole image is present.
            assert block.image is not None
            phase = "erase"
            routine("erase", block.image)
            phase = "transfer"
            transfer(block.image)
            phase = "verify"
            routine("verify", block.image)
            if (
                index + 1 < len(blocks)
                and block.ecu_index != blocks[index + 1].ecu_index
            ):
                platform("logical_block_boundary", index=index)
        phase = "reset"
        channel.call(b"\x11\x01", b"\x51\x01")
        platform("stop_periodic")
        if target == b"\x01\x03":
            platform("finish_diag_comm")
            for _ in range(wakeup_ms // 50):
                platform("wait", milliseconds=50)
                platform("wake_up_progress")
            platform("prepare_diag_comm")
        phase = "finish"
        platform(
            "ethernet_functional_write",
            data_hex=ethernet_request(b"\xe4\x00", b"\x10\x81").hex(),
            immediate=True,
        )
        platform("finish_diag_comm")
        platform("set_reprogramming_active", active=False)
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - preserve uncertainty, no reset after failure
        if attempted or channel.attempted:
            for operation in ("stop_periodic", "finish_diag_comm"):
                try:
                    platform(operation, cleanup=True)
                except (Exception, KeyboardInterrupt) as cleanup_exc:  # noqa: BLE001 - retain original fault
                    cleanup_errors.append(type(cleanup_exc).__name__)
        return {
            "state": "recovery_required"
            if attempted or channel.attempted
            else ("cancelled" if isinstance(exc, InterruptedError) else "failed"),
            "phase": phase,
            "logical_block": index,
            "transferred": transferred,
            "error": type(exc).__name__,
            "cleanup_errors": cleanup_errors,
            "resume_authorized": False,
            "provenance": "static-native-CUW18-Ethernet-ReproStd-writer",
            "physical_status": "PHYSICAL_UNCONFIRMED",
        }
    return {
        "state": "writer_completed",
        "transferred": transferred,
        "logical_blocks": len(blocks),
        "programming_completed": False,
        "provenance": "static-native-CUW18-Ethernet-ReproStd-writer",
        "physical_status": "PHYSICAL_UNCONFIRMED",
    }


def native_reprostd_blocks(
    container: CalibrationContainer,
    node: int,
    observed_cids: tuple[str, ...],
    tester_info: bytes,
    system_time: tuple[int, int, int, int, int, int, int, int],
) -> tuple[ReproStdLogicalBlock, ...]:
    """Build CUW18 ReproStd writer inputs from native metadata/embedded records.

    CID observations, tester identity and clock observation are explicit inputs.
    Native target lists are combined per NewCID/CPU as in404c56c. This selection
    does not authorize a real write or prove vehicle identity/address binding.
    """
    if (
        type(node) is not int
        or not 1 <= node <= 9
        or not isinstance(observed_cids, tuple)
        or not 0 < len(observed_cids) <= 4096
        or any(
            not isinstance(cid, str) or not cid or len(cid) > 256
            for cid in observed_cids
        )
    ):
        raise ValueError("Explicit bounded native node/CID observations required")
    logical = tuple(
        block for block in bind_native_logical_records(container) if block.node == node
    )
    if not logical:
        raise ValueError("Selected native node has no logical blocks")
    groups: dict[int, set[str]] = {}
    for block in logical:
        groups.setdefault(block.ecu_index, set()).update(block.targets)
    if any(not targets.intersection(observed_cids) for targets in groups.values()):
        raise ValueError("Observed CID does not match every selected native CPU target")
    kinds = {
        "01": ("whole", "ReproData", "EraseAndReproRoutine"),
        "05": ("whole", "ReproData", None),
        "07": ("delta", "DeltaReproData", "DeltaEraseAndReproRoutine"),
        "08": ("delta", "DeltaReproData", None),
        "09": ("compressed", "CompressionReproData", "CompressionEraseAndReproRoutine"),
        "0A": ("compressed", "CompressionReproData", None),
    }
    result = []
    for block in logical:
        method, image_kind, routine_kind = kinds[block.method]
        areas = {area.kind: area for area in block.areas}

        def segment(kind: str | None, areas=areas, block=block):
            if kind is None or kind not in areas:
                return None
            area = areas[kind]
            signature = (
                area.cmac if block.required_spec == "03" else area.digital_signature
            )
            if len(signature) != (16 if block.required_spec == "03" else 256):
                raise ValueError(
                    "Selected native area lacks its original verification signature"
                )
            return ReproStdSegment(area.address, area.data, signature, area.crc)

        image = segment(image_kind)
        routine = segment(routine_kind)
        if routine_kind is not None and routine is None:
            raise ValueError(
                "Selected native package requires a separately bound routine record"
            )
        result.append(
            ReproStdLogicalBlock(
                method,
                block.slot,
                block.nonce,
                tester_info,
                system_time,
                image,
                routine,
                block.ecu_index,
                int(block.values.get("p4servermaxtime", "03"), 10) * 60,
            )
        )
    return tuple(result)


def ethernet_prepare_actions(
    target: bytes, *, gateway_target: bytes | None = None, wakeup_ms: int = 0
) -> tuple[dict, ...]:
    """CUW18 Ethernet preparation order; all host effects remain explicit."""
    ethernet_request(target, b"\x10\x02")
    if gateway_target is not None:
        ethernet_request(gateway_target, b"\x10\x02")
    if type(wakeup_ms) is not int or not 0 <= wakeup_ms <= 120000:
        raise ValueError("Bounded native Ethernet wake time required")
    actions: list[dict] = []

    def add(operation: str, **values):
        actions.append({"operation": operation, **values})

    def wait(milliseconds: int):
        add("wait", milliseconds=milliseconds)

    def functional(payload: bytes, immediate: bool = True):
        add(
            "ethernet_functional_write",
            data_hex=ethernet_request(b"\xe4\x00", payload).hex(),
            immediate=immediate,
        )

    def keepalive(immediate: bool = True):
        functional(b"\x3e\x80", immediate)
        add("set_previous_send_time")

    add("set_previous_send_time")
    add("prepare_diag_comm")
    functional(b"\x10\x83")
    wait(1000)
    add("start_ethernet_periodic", delay_ms=1000, privileged=False)
    if gateway_target == b"\x01\x03":
        add("esw1_security")
        add("esw1_routine", mode=0)
        wait(1500)
        add("esw1_routine", mode=1)
    add("stop_periodic")
    functional(b"\x85\x82")
    wait(1000)
    keepalive()
    wait(1000)
    functional(b"\x28\x81\x01")
    wait(1000)
    keepalive()
    wait(1000)
    functional(b"\x28\x83\x01")
    wait(1000)
    for delay in (2000, 1000, 1000):
        keepalive(False)
        wait(delay)
    add("control_io0500", ioctl=8)
    add("start_ethernet_periodic", delay_ms=1000, privileged=False)
    add(
        "programming_session",
        request_hex="1002",
        response_prefix_hex="5002",
        minimum_response_bytes=6,
    )
    add("stop_periodic")
    add("start_ethernet_periodic", delay_ms=0, privileged=False)
    wait(wakeup_ms)
    add("security")
    return tuple(actions)


def ethernet_prepare(
    action: Callable[[dict, float], None],
    exchange: Callable[[str, bytes], bytes],
    ecu: str,
    target: bytes,
    key_provider: Callable[[str, bytes], bytes] | None,
    *,
    gateway_target: bytes | None = None,
    gateway_key_provider: Callable[[str, bytes], bytes] | None = None,
    wakeup_ms: int = 0,
    timeout: float = 30,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
    receive: Callable[[str], bytes] | None = None,
) -> dict:
    """Run native Ethernet prepare over supplied routing and authorization I/O.

    prepare_diag_comm must establish the actual recovered host lifecycle. Its
    connection remains owned by the caller across preparation and writing.
    ESW1 authorization receives16 seed bytes and returns256 supplied bytes;
    target authorization receives16 seed bytes and returns16 supplied bytes.
    """
    actions = ethernet_prepare_actions(
        target, gateway_target=gateway_target, wakeup_ms=wakeup_ms
    )
    if gateway_target == b"\x01\x03" and gateway_key_provider is None:
        raise ValueError(
            "Explicit authorized ESW1 provider required before preparation"
        )
    channel = NativeEthernetChannel(
        exchange, ecu, target, timeout, cancelled, clock, receive
    )

    def host(entry: dict, budget: float):
        operation = entry["operation"]
        if operation not in ("esw1_security", "esw1_routine"):
            return action(entry, budget)
        gateway = NativeEthernetChannel(
            exchange, "ESW1", b"\x01\x03", budget, cancelled, clock, receive
        )
        if operation == "esw1_routine":
            subfunction = 1 if entry["mode"] == 0 else 3
            request = bytes((0x31, subfunction, 0x10, 0x11))
            expected = bytes((0x71, subfunction, 0x10, 0x11)) + (
                b"\x01" if subfunction == 3 else b""
            )
            gateway.call(request, expected)
            return None
        response = gateway.call(b"\x27\x21", b"\x67\x21")
        if len(response) < 18:
            raise ValueError("Native ESW1 seed must contain16 bytes")
        gateway._invoke(
            action, {"operation": "stop_periodic"}, max(0.0, channel.deadline - clock())
        )
        gateway._invoke(
            action,
            {
                "operation": "start_ethernet_periodic",
                "delay_ms": 1000,
                "privileged": True,
            },
            max(0.0, channel.deadline - clock()),
        )
        assert gateway_key_provider is not None
        key = gateway._invoke(gateway_key_provider, "ESW1", response[2:18])
        if not isinstance(key, bytes) or len(key) != 256:
            raise ValueError("Authorized ESW1 provider must return256 bytes")
        gateway._invoke(
            action, {"operation": "stop_periodic"}, max(0.0, channel.deadline - clock())
        )
        gateway._invoke(
            action,
            {
                "operation": "start_ethernet_periodic",
                "delay_ms": 1000,
                "privileged": False,
            },
            max(0.0, channel.deadline - clock()),
        )
        gateway.call(b"\x27\x22" + key, b"\x67\x22")
        return None

    return _run_prepare_actions(
        host,
        exchange,
        ecu,
        actions,
        key_provider,
        None,
        "static-native-CUW18-Ethernet-prepare",
        timeout,
        cancelled,
        clock,
        receive,
        channel,
    )


def _native_prepare_values(values: Mapping[str, str]) -> dict:
    def scaled(name: str, factor: int) -> int:
        try:
            value = int(values.get(name, "0"))
        except ValueError as error:
            raise ValueError("Invalid native preparation time") from error
        if not 0 <= value * factor <= 120000:
            raise ValueError("Native preparation time outside host bounds")
        return value * factor

    def identifier(name: str, widths: tuple[int, ...]) -> bytes:
        value = values.get(name, "")
        try:
            result = bytes.fromhex(value)
        except ValueError as error:
            raise ValueError("Invalid native preparation identifier") from error
        if len(result) not in widths or len(value) != 2 * len(result):
            raise ValueError("Native preparation identifier width mismatch")
        return result

    try:
        count = int(values.get("numberofgateway", "0"))
    except ValueError as error:
        raise ValueError("Invalid native gateway count") from error
    if not 0 <= count <= 64:
        raise ValueError("Native gateway count outside host bounds")
    gateways = tuple(
        identifier(f"{index:02}_gatewaydiagid", (2, 3)) for index in range(1, count + 1)
    )
    charge = (
        identifier("chargelocalbuspoweroncontrollingecudiagid", (2,))
        if values.get("chargelocalbusecureprogrammingflow", "") == "01"
        else None
    )
    return {
        "wakeup_ms": scaled("wakeuptimeafterreset", 50),
        "emissions_delay_ms": scaled("emissionsrelatedsystem", 10),
        "gateway_ids": gateways,
        "gateway_modes": tuple(
            values.get(f"{index:02}_gatewaymode", "") for index in range(1, count + 1)
        ),
        "charge_bus_id": charge,
        "charge_bus_start_ms": scaled("chargelocalbusecustarttimeafterpoweron", 50),
    }


def native_reprostd_prepare_context(
    container: CalibrationContainer,
    node: int,
    *,
    gateway_kind: int,
    extended_addressing: bool,
) -> ReproStdPrepareContext:
    """Build native ReproStd preparation fields from CUW node metadata.

    Only gateway classification and actual addressing mode are observations;
    native wake/emissions/charge timing and gateway rows come from the file.
    """
    if type(node) is not int or not 1 <= node <= 9:
        raise ValueError("Bounded native node required")
    blocks = bind_native_logical_records(container)
    values = next((block.node_values for block in blocks if block.node == node), None)
    if values is None:
        raise ValueError("Selected native preparation node does not exist")
    return ReproStdPrepareContext(
        **_native_prepare_values(values),
        gateway_kind=gateway_kind,
        extended_addressing=extended_addressing,
        pending_timeout_seconds=int(
            next(block for block in blocks if block.node == node).values.get(
                "p4servermaxtime", "03"
            ),
            10,
        )
        * 60,
    )


def native_unified_prepare_context(
    container: CalibrationContainer,
    node: int,
    *,
    gateway_kind: int,
    extended_addressing: bool,
    native_flag_724: bool,
) -> UnifiedPrepareContext:
    """Build Unified preparation from original metadata and explicit runtime flags."""
    if type(node) is not int or not 0 <= node <= 9:
        raise ValueError("Bounded native node required")
    cpus = bind_native_cpu_records(container)
    cpu = next((cpu for cpu in cpus if cpu.node == node), None)
    if cpu is None:
        raise ValueError("Selected native Unified node does not exist")
    if cpu.node == 0:
        raise ValueError("Unified preparation requires populated native node metadata")
    values = cpu.node_values
    fields = _native_prepare_values(values)
    try:
        auth = bytes.fromhex(values.get("ecuauthkey", ""))
        diag = bytes.fromhex(values.get("diagid", ""))
    except ValueError as error:
        raise ValueError(
            "Invalid native Unified authorization/diagnostic field"
        ) from error
    if len(auth) != 16:
        raise ValueError(
            "Original native sixteen-byte ECU authorization field required"
        )
    return UnifiedPrepareContext(
        fields["wakeup_ms"],
        fields["emissions_delay_ms"],
        auth,
        gateway_kind,
        fields["gateway_ids"],
        diag,
        native_flag_724,
        extended_addressing,
        tuple(
            values.get(f"{index:02}_gatewaydiagid", "")
            for index in range(1, len(fields["gateway_ids"]) + 1)
        ),
    )


def native_ethernet_prepare_inputs(container: CalibrationContainer, node: int) -> dict:
    """Original node target/gateway/wake arguments for ethernet_prepare."""
    if type(node) is not int or not 1 <= node <= 9:
        raise ValueError("Bounded native Ethernet node required")
    blocks = bind_native_logical_records(container)
    values = next((block.node_values for block in blocks if block.node == node), None)
    if values is None:
        raise ValueError("Selected native Ethernet node does not exist")
    try:
        target = bytes.fromhex(values.get("logicaladdress", ""))
        count = int(values.get("numberofgateway", "0"))
        gateway = (
            bytes.fromhex(values.get("01_gatewaylogicaladdress", "")) if count else None
        )
        wake = int(values.get("wakeuptimeafterreset", "0")) * 50
    except ValueError as error:
        raise ValueError("Invalid native Ethernet preparation metadata") from error
    if (
        len(target) != 2
        or not 0 <= count <= 64
        or (gateway is not None and len(gateway) != 2)
        or not 0 <= wake <= 120000
    ):
        raise ValueError("Native Ethernet preparation fields outside bounds")
    return {"target": target, "gateway_target": gateway, "wakeup_ms": wake}


@dataclass(frozen=True)
class NativeRecoveryState:
    """Native ControlCommPhase pointer fields, retaining unproved offset names."""

    active_610: bool
    phase_738: int
    flag_724: bool = False
    flag_728: bool = False
    flag_72c: bool = False
    flag_730: bool = False
    flag_740: bool = False
    flag_5f8: bool = False
    error_608: int = 0
    error_60c: int = 0
    error_kind_604: int = 0

    def __post_init__(self) -> None:
        for name in (
            "active_610",
            "flag_724",
            "flag_728",
            "flag_72c",
            "flag_730",
            "flag_740",
            "flag_5f8",
        ):
            if type(getattr(self, name)) is not bool:
                raise ValueError("Explicit native recovery pointer flags required")
        for name in ("phase_738", "error_608", "error_60c", "error_kind_604"):
            if (
                type(getattr(self, name)) is not int
                or not 0 <= getattr(self, name) <= 0xFFFFFFFF
            ):
                raise ValueError("Bounded native recovery numeric fields required")
        if self.phase_738 > 255:
            raise ValueError("Native recovery phase exceeds its byte storage")


def native_recovery(
    action: Callable[[dict, float], object],
    state: NativeRecoveryState,
    parameter: Callable[[str], str],
    prepare_retry: Callable[[float], bool],
    resolve_addresses: Callable[[float], tuple],
    is_finished: Callable[[tuple, float], bool],
    *,
    ethernet: bool,
    native_build: int = 18,
    timeout: float = 30,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> dict:
    """CUW18 ControlCommPhase7750 recovery, over explicit host/module providers.

    Callback slot numbers and native field offsets are preserved. Callback
    results may explicitly update pointer fields through a mapping; omitted
    values retain their state. No user choice, reconnect, address or module
    success is fabricated. A bounded host deadline replaces the native unbounded
    retry loop; this is independent of authored simulator checkpoints.
    """
    from dataclasses import asdict, replace

    if (
        type(native_build) is not int
        or native_build not in (12, 18)
        or (native_build == 12 and ethernet)
    ):
        raise ValueError(
            "Recovered native build12/18 and matching contact type required"
        )
    if not isinstance(state, NativeRecoveryState) or type(ethernet) is not bool:
        raise TypeError("Resolved native recovery state and contact type required")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or not 0 < timeout <= 86400
    ):
        raise ValueError("Finite bounded recovery timeout required")
    deadline = clock() + timeout
    saved_errors = state.error_608, state.error_60c
    events = 0
    retries = 0
    confirmed = False

    def remaining():
        if cancelled():
            raise InterruptedError("Native recovery cancelled")
        budget = deadline - clock()
        if budget <= 0:
            raise TimeoutError("Native recovery deadline expired")
        return budget

    def invoke(callback, *args):
        nonlocal events
        remaining()
        events += 1
        if events > 65536:
            raise ValueError("Native recovery event limit exceeded")
        try:
            result = callback(*args)
        except (Exception, KeyboardInterrupt):
            remaining()
            raise
        remaining()
        return result

    def host(operation, **values):
        return invoke(action, {"operation": operation, **values}, remaining())

    def callback(slot, **values):
        nonlocal state
        result = host("native_recovery_callback", slot=slot, **values)
        if isinstance(result, Mapping):
            if not set(result).issubset(asdict(state)):
                raise ValueError("Unknown native recovery pointer field")
            state = replace(state, **result)
            return None
        return result

    def boolean(name, default=False):
        value = invoke(parameter, name)
        if value == "":
            return default
        if value not in ("0", "1"):
            raise ValueError("Original native boolean parameter0/1 required")
        return value == "1"

    def strict_bool(value):
        if type(value) is not bool:
            raise TypeError("Explicit observed native callback boolean required")
        return value

    def reconnect():
        nonlocal state
        callback(5)
        callback(6)
        opened = strict_bool(host("get_opened_device"))
        callback(24, opened=opened)
        state = replace(state, active_610=False)
        for slot in (7, 3, 8):
            callback(slot)
        host("set_opened_device", opened=strict_bool(callback(25)))
        if not state.active_610:
            state = replace(state, flag_5f8=True)
            return
        state = replace(state, error_608=0, error_60c=0)
        try:
            host("disconnect")
        except NativeTransportError:
            # Native disconnect catch-all proceeds to the new connection.
            pass
        try:
            host(
                "connect0500" if ethernet else "connect",
                protocol=0x800F if ethernet else 6,
            )
        except NativeRecoveryTransportError as error:
            state = replace(
                state, error_608=error.code, error_60c=error.detail, error_kind_604=3
            )
            callback(5)

    try:
        igoff_retriable = boolean("IGOffRetriableFlag")
        reconnect()
        callback(8)
        while state.active_610 and state.phase_738 == 2:
            remaining()
            permitted = True
            if not igoff_retriable:
                if native_build == 18:
                    host("export_driver_data")
                    callback(29)
                    if boolean("FlagToCancelAutomaticIGOFF"):
                        permitted = strict_bool(callback(28))
                if permitted and state.flag_740:
                    permitted = strict_bool(callback(14))
            if permitted:
                state = replace(state, flag_724=True)
                if not boolean("PrepareRetryFlag"):
                    break
                state = replace(
                    state, error_608=saved_errors[0], error_60c=saved_errors[1]
                )
                raw_timeout = invoke(parameter, "ReceiveTimeoutBeforePrepareRetry")
                native_timeout = int(raw_timeout or "0", 10)
                if not 0 <= native_timeout <= 0x7FFFFFFF:
                    raise ValueError("Bounded native prepare retry timeout required")
                if native_timeout:
                    host("set_timeout", milliseconds=native_timeout)
                retries += 1
                if strict_bool(invoke(prepare_retry, remaining())):
                    state = replace(state, error_608=0, error_60c=0)
                    break
                if native_build == 12 or not boolean("FlagToNonSetEerrorKindConnect"):
                    state = replace(state, error_kind_604=3)
                callback(5)
            else:
                state = replace(state, error_kind_604=3)
            reconnect()
            callback(8)
        if (
            state.active_610
            and state.phase_738 == 2
            and boolean("ConfirmAfterEndOfFlashingFlag")
            and (not boolean("IGOffRetriableFlag") or state.flag_730)
        ):
            host("wait", milliseconds=5000)
            if state.flag_730:
                addresses = invoke(resolve_addresses, remaining())
                if not isinstance(addresses, tuple) or not 0 < len(addresses) <= 4096:
                    raise ValueError("Resolved native communication addresses required")
                if strict_bool(invoke(is_finished, addresses, remaining())):
                    state = replace(state, active_610=False)
                    confirmed = True
                    callback(7)
                    state = replace(state, flag_728=False, flag_72c=False)
        outcome = "recovery_completed" if confirmed else "recovery_required"
        error = None
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - preserve uncertainty without exposing provider values
        outcome = "recovery_required"
        error = type(exc).__name__
    return {
        "state": outcome,
        "native_state": asdict(state),
        "prepare_retries": retries,
        "events": events,
        "error": error,
        "resume_authorized": False,
        "programming_completed": False,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "provenance": f"static-native-CUW{native_build}-ControlCommPhase-recovery",
    }


@dataclass(frozen=True)
class NativeExecuteStep:
    """Observed native export return and resulting caller phase/CPU pointers."""

    succeeded: bool
    phase: int
    cpu_index: int

    def __post_init__(self) -> None:
        if (
            type(self.succeeded) is not bool
            or type(self.phase) is not int
            or not 0 <= self.phase <= 3
            or type(self.cpu_index) is not int
            or not 0 <= self.cpu_index < 4096
        ):
            raise ValueError("Explicit bounded native export result/phase/CPU required")


def native_execute(
    action: Callable[[dict, float], None],
    container: CalibrationContainer,
    step: NativeExecuteStep,
    run_phase: Callable[[str, NativeExecuteStep, float], NativeExecuteStep],
    parameter: Callable[[int, str], str],
    *,
    native_build: int = 18,
    timeout: float = 30,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> dict:
    """Recovered12/18 ControlCommPhase.Execute outer dispatch and CPU loop.

    run_phase binds actual source-identified family exports, their catalog rows
    and native recovery. Its returned state is the observed caller memory update,
    not a default success. A phase1 export may change phase to2/3, and native
    Execute dispatches that phase in the same invocation. No stage is automatic
    outside this explicitly invoked controller.
    """
    if (
        type(native_build) is not int
        or native_build not in (12, 18)
        or not isinstance(step, NativeExecuteStep)
    ):
        raise ValueError("Explicit recovered native build and caller state required")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or not 0 < timeout <= 86400
    ):
        raise ValueError("Bounded native execution deadline required")
    from scripts.calibration import native_selection_metadata

    # Native base dispatch uses CPU0; per-CPU parameter rows remain independent.
    metadata = native_selection_metadata(container)
    contact = metadata["contact_type"]
    if native_build == 12 and contact == "Ethernet":
        raise ValueError("Native build12 has no Ethernet controller policy")
    step = NativeExecuteStep(False, step.phase, step.cpu_index)
    modern = contact == "P5-Unified" or native_build == 18 and contact == "Ethernet"
    try:
        cpus = bind_native_cpu_records(container)
        cpu_count = len(cpus)
    except ValueError:
        if native_build == 12:
            raise ValueError(
                "Native build12 has no logical archive controller policy"
            ) from None
        logical = bind_native_logical_records(container)
        cpu_count = len({block.ecu_index for block in logical})
    if not 0 <= step.cpu_index < cpu_count:
        raise ValueError("Native caller CPU index exceeds imported calibration")
    deadline = clock() + timeout
    executed = []

    def remaining():
        if cancelled():
            raise InterruptedError("Native phase controller cancelled")
        budget = deadline - clock()
        if budget <= 0:
            raise TimeoutError("Native phase controller deadline expired")
        return budget

    def invoke(callback, *args):
        remaining()
        try:
            result = callback(*args)
        except (Exception, KeyboardInterrupt):
            remaining()
            raise
        remaining()
        return result

    def run(stage):
        nonlocal step
        result = invoke(run_phase, stage, step, remaining())
        if not isinstance(result, NativeExecuteStep) or result.cpu_index > cpu_count:
            raise ValueError("Native export returned invalid caller state")
        step = result
        executed.append(stage)

    def boolean(index, key):
        value = invoke(parameter, index, key)
        if value not in ("", "0", "1"):
            raise ValueError("Native controller parameter requires boolean0/1")
        return value == "1"

    try:
        invoke(action, {"operation": "import_driver_data"}, remaining())
        if step.phase == 0:
            run("get_cid")
        elif modern:
            if step.phase == 1:
                run("prepare")
            if step.phase == 2:
                run("write")
        else:
            final = (
                cpu_count
                if boolean(step.cpu_index, "CpuLoopBetweenPrepareAndWriteFlag")
                else step.cpu_index + 1
            )
            initial = step.cpu_index
            for next_cpu in range(initial + 1, final + 1):
                step = NativeExecuteStep(True, step.phase, step.cpu_index)
                if step.phase == 1:
                    run("prepare")
                if step.phase == 3:
                    run("gateway")
                if step.phase == 2:
                    run("write")
                if not step.succeeded:
                    break
                if next_cpu < final:
                    if boolean(next_cpu, "FlagToDoIGOFFONAtCPUTypeChange"):
                        break
                    step = NativeExecuteStep(step.succeeded, 1, step.cpu_index)
        invoke(action, {"operation": "export_driver_data"}, remaining())
        state, error = (
            ("phase_completed" if step.succeeded else "recovery_required"),
            None,
        )
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - preserve uncertain native state without provider buffers
        state, error = "recovery_required", type(exc).__name__
    return {
        "state": state,
        "native_phase": step.phase,
        "cpu_index": step.cpu_index,
        "native_return": step.succeeded,
        "phases_executed": executed,
        "error": error,
        "programming_completed": False,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "provenance": f"static-native-CUW{native_build}-ControlCommPhase-Execute",
    }


def native_modern_phase(
    container: CalibrationContainer,
    step: NativeExecuteStep,
    recovery_state: NativeRecoveryState,
    run_export: Callable[[str, int, float], dict],
    recover: Callable[[NativeRecoveryState, float], dict],
    *,
    native_build: int = 18,
    timeout: float = 30,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> dict:
    """Native Unified/Ethernet9350/9c90 caller transitions and node CPU loop.

    run_export invokes the actual source-bound prepare/write algorithm; recover
    invokes native_recovery with that caller state. Their results carry native
    state mappings when an algorithm changed pointer fields. Missing error details
    are never manufactured. Catalog/module/address validation is caller-owned and
    must precede these providers, as in the native dispatcher's setup pass.
    """
    from dataclasses import asdict, replace

    from scripts.calibration import native_selection_metadata

    if (
        native_build not in (12, 18)
        or type(native_build) is not int
        or not isinstance(step, NativeExecuteStep)
        or not isinstance(recovery_state, NativeRecoveryState)
        or step.phase not in (1, 2)
        or recovery_state.phase_738 != step.phase
    ):
        raise ValueError("Source-bound modern caller phase and native state required")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or not 0 < timeout <= 86400
    ):
        raise ValueError("Bounded native modern phase deadline required")
    contact = native_selection_metadata(container)["contact_type"]
    if contact not in ("P5-Unified", "Ethernet") or (
        native_build == 12 and contact == "Ethernet"
    ):
        raise ValueError("Modern phase does not match the imported contact policy")
    logical_mode = False
    try:
        cpus = bind_native_cpu_records(container)
        nodes = tuple(cpu.node for cpu in cpus)
    except ValueError:
        if native_build == 12:
            raise ValueError("Native build12 has no logical modern caller") from None
        blocks = bind_native_logical_records(container)
        grouped = {}
        for block in blocks:
            grouped[block.ecu_index] = block.node
        nodes = tuple(grouped[index] for index in range(len(grouped)))
        logical_mode = True
    if not 0 <= step.cpu_index < len(nodes):
        raise ValueError("Native modern CPU index exceeds imported calibration")
    node = nodes[step.cpu_index]
    final = sum(value <= node for value in nodes)
    deadline = clock() + timeout
    called = []
    error = None

    def budget():
        if cancelled():
            raise InterruptedError("Native modern caller cancelled")
        remaining = deadline - clock()
        if remaining <= 0:
            raise TimeoutError("Native modern caller deadline expired")
        return remaining

    def invoke(callback, *args):
        nonlocal recovery_state
        budget()
        try:
            result = callback(*args)
        except (Exception, KeyboardInterrupt):
            budget()
            raise
        budget()
        if not isinstance(result, dict):
            raise TypeError("Native stage result mapping required")
        state = result.get("native_state")
        if state is not None:
            if not isinstance(state, Mapping) or set(state) != set(
                asdict(recovery_state)
            ):
                raise ValueError("Complete typed native stage pointer state required")
            candidate = NativeRecoveryState(**state)
            if candidate.phase_738 > 3:
                raise ValueError("Native caller phase outside recovered dispatch")
            recovery_state = candidate
        return result

    try:
        if step.phase == 1:
            called.append(("prepare", step.cpu_index))
            result = invoke(run_export, "prepare", step.cpu_index, budget())
            success = result.get("state") == "preparation_completed"
            if success:
                recovery_state = replace(recovery_state, phase_738=2)
                step = NativeExecuteStep(True, 2, step.cpu_index)
            else:
                recovered = invoke(recover, recovery_state, budget())
                if "native_state" not in recovered:
                    raise ValueError("Native recovery must return its pointer state")
                if not recovery_state.active_610:
                    recovery_state = replace(recovery_state, flag_5f8=True)
                step = NativeExecuteStep(
                    False, recovery_state.phase_738, step.cpu_index
                )
        else:
            current = nodes.index(node) if logical_mode else step.cpu_index
            while current < final:
                called.append(("write", step.cpu_index))
                result = invoke(run_export, "write", step.cpu_index, budget())
                success = result.get("state") == "writer_completed"
                if not success:
                    recovered = invoke(recover, recovery_state, budget())
                    if "native_state" not in recovered:
                        raise ValueError(
                            "Native recovery must return its pointer state"
                        )
                    step = NativeExecuteStep(
                        not recovery_state.active_610 and not recovery_state.flag_5f8,
                        recovery_state.phase_738,
                        step.cpu_index,
                    )
                    break
                current += 1
                recovery_state = replace(
                    recovery_state,
                    error_608=0,
                    error_60c=0,
                    flag_728=False if current == final else recovery_state.flag_728,
                    flag_72c=False,
                    flag_724=False,
                    active_610=False,
                )
                if logical_mode:
                    step = NativeExecuteStep(
                        True, recovery_state.phase_738, step.cpu_index
                    )
                    break
                step = NativeExecuteStep(True, recovery_state.phase_738, current)
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - retain native uncertainty without provider payloads
        error = type(exc).__name__
        step = NativeExecuteStep(False, recovery_state.phase_738, step.cpu_index)
    return {
        "state": "phase_completed" if step.succeeded else "recovery_required",
        "native_step": step,
        "native_state": asdict(recovery_state),
        "exports_called": called,
        "error": error,
        "programming_completed": False,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "provenance": f"static-native-CUW{native_build}-modern-phase-caller",
    }


def native_legacy_phase(
    container: CalibrationContainer,
    step: NativeExecuteStep,
    recovery_state: NativeRecoveryState,
    run_export: Callable[[str, int, float], dict],
    recover: Callable[[NativeRecoveryState, float], dict],
    parameter: Callable[[int, str], str],
    prepare_result_enum: Callable[[float], int],
    *,
    native_build: int = 18,
    timeout: float = 30,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> dict:
    """Recovered6bc0/8170/87b0 legacy caller transitions (12:6b50/7fd0/8610).

    Providers bind the actual export and complete source/module/address setup
    before entry. Gateway results MUST expose its seventh bool* output as
    gateway_result_valid plus gateway_result. The numeric prepare callback18
    remains explicit: only comparison with2 is established by the caller.
    """
    from dataclasses import asdict, replace

    from scripts.calibration import native_selection_metadata

    if (
        type(native_build) is not int
        or native_build not in (12, 18)
        or not isinstance(step, NativeExecuteStep)
        or not isinstance(recovery_state, NativeRecoveryState)
        or step.phase not in (1, 2, 3)
        or recovery_state.phase_738 != step.phase
    ):
        raise ValueError("Source-bound legacy phase and pointer state required")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or not 0 < timeout <= 86400
    ):
        raise ValueError("Bounded native legacy phase deadline required")
    if native_selection_metadata(container)["contact_type"] in (
        "P5-Unified",
        "Ethernet",
    ):
        raise ValueError("Legacy phase does not match the imported contact policy")
    cpus = bind_native_cpu_records(container)
    if not 0 <= step.cpu_index < len(cpus):
        raise ValueError("Legacy CPU index exceeds imported calibration")
    deadline = clock() + timeout
    called = []
    error = None
    attempts = 0

    def budget():
        if cancelled():
            raise InterruptedError("Native legacy caller cancelled")
        remaining = deadline - clock()
        if remaining <= 0:
            raise TimeoutError("Native legacy caller deadline expired")
        return remaining

    def invoke(callback, *args):
        budget()
        try:
            result = callback(*args)
        except (Exception, KeyboardInterrupt):
            budget()
            raise
        budget()
        return result

    def result_state(result):
        nonlocal recovery_state
        if not isinstance(result, dict):
            raise TypeError("Native stage result mapping required")
        state = result.get("native_state")
        if state is not None:
            if not isinstance(state, Mapping) or set(state) != set(
                asdict(recovery_state)
            ):
                raise ValueError("Complete native stage pointer state required")
            candidate = NativeRecoveryState(**state)
            if candidate.phase_738 > 3:
                raise ValueError("Native caller phase outside recovered dispatch")
            recovery_state = candidate
        return result

    def export(stage):
        called.append((stage, step.cpu_index))
        return result_state(invoke(run_export, stage, step.cpu_index, budget()))

    def recovery():
        result = result_state(invoke(recover, recovery_state, budget()))
        if "native_state" not in result:
            raise ValueError("Recovery must return complete native pointer state")

    def boolean(index, key):
        value = invoke(parameter, index, key)
        if value not in ("", "0", "1"):
            raise ValueError("Native controller parameter requires boolean0/1")
        return value == "1"

    try:
        if step.phase == 1:
            result = export("prepare")
            enum = invoke(prepare_result_enum, budget())
            if type(enum) is not int or not 0 <= enum <= 0xFFFFFFFF:
                raise ValueError("Explicit native callback18 uint32 enum required")
            phase = 3 if enum != 2 else recovery_state.phase_738
            recovery_state = replace(recovery_state, phase_738=phase)
            step = NativeExecuteStep(
                result.get("state") == "preparation_completed", phase, step.cpu_index
            )
        elif step.phase == 3:
            success = step.succeeded
            if success:
                result = export("gateway")
                valid = result.get("gateway_result_valid")
                if (
                    type(valid) is not bool
                    or type(result.get("gateway_result")) is not bool
                ):
                    raise ValueError("Actual gateway BOOL and bool* out required")
                if valid:
                    success = result["gateway_result"]
            if success:
                recovery_state = replace(recovery_state, phase_738=2)
                step = NativeExecuteStep(True, 2, step.cpu_index)
            else:
                recovery()
                if not recovery_state.active_610:
                    recovery_state = replace(recovery_state, flag_5f8=True)
                step = NativeExecuteStep(
                    False, recovery_state.phase_738, step.cpu_index
                )
        else:
            # Native writer has its own bound, opposite to Execute's outer loop.
            final = (
                step.cpu_index + 1
                if boolean(step.cpu_index, "CpuLoopBetweenPrepareAndWriteFlag")
                else len(cpus)
            )
            while step.cpu_index < final:
                if attempts >= 65536:
                    raise ValueError("Host legacy recovery retry budget exceeded")
                attempts += 1
                result = export("write")
                if result.get("state") != "writer_completed":
                    recovery()
                    if not recovery_state.active_610:
                        step = NativeExecuteStep(
                            not recovery_state.flag_5f8,
                            recovery_state.phase_738,
                            step.cpu_index,
                        )
                        break
                    stop = boolean(step.cpu_index, "IGOffRetriableFlag")
                    step = NativeExecuteStep(
                        False, recovery_state.phase_738, step.cpu_index
                    )
                    if step.phase == 1 or stop:
                        break
                    continue
                current = step.cpu_index + 1
                recovery_state = replace(
                    recovery_state,
                    error_608=0,
                    error_60c=0,
                    flag_728=False if current == final else recovery_state.flag_728,
                    flag_72c=False,
                    flag_724=False,
                    active_610=False,
                )
                step = NativeExecuteStep(True, recovery_state.phase_738, current)
                if current < final and boolean(
                    current, "FlagToDoIGOFFONAtCPUTypeChange"
                ):
                    break
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - bounded report without provider payloads
        error = type(exc).__name__
        step = NativeExecuteStep(False, recovery_state.phase_738, step.cpu_index)
    return {
        "state": "phase_completed" if step.succeeded else "recovery_required",
        "native_step": step,
        "native_state": asdict(recovery_state),
        "exports_called": called,
        "error": error,
        "programming_completed": False,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "provenance": f"static-native-CUW{native_build}-legacy-phase-caller",
    }


@dataclass(frozen=True)
class NativeSavedRecovery:
    """Saved GUI recovery fields bound to explicitly supplied source/device data.

    This is neither a simulator checkpoint nor proof of ECU state. In particular
    writing_end_block is the GUI's bool argument, never a transfer-block cursor.
    """

    calibration_sha256: str
    selected_device_index: int
    write_cpu_index: int
    writing: bool
    writing_end_block: bool
    use_new_software_password: bool
    fields: Mapping[str, object] = field(repr=False)


def bind_native_saved_recovery(
    data: bytes,
    container: CalibrationContainer,
    *,
    supplied_source_path: str,
    enumerated_devices: tuple[str, ...],
) -> NativeSavedRecovery:
    """Recover44f568/472df4/49b3d0 source/device/CPU association without I/O.

    The caller supplies an already inspected CUW and the actual original path
    label; no saved pathname is opened. Native device matching uses the first
    exact list match. RecoveryInfo has no source hash or ECU-state attestation,
    so importing these fields never authorizes resume or emits programming I/O.
    """
    from types import MappingProxyType

    if (
        not isinstance(container, CalibrationContainer)
        or not isinstance(supplied_source_path, str)
        or not 0 < len(supplied_source_path) <= 4096
        or "\x00" in supplied_source_path
        or not isinstance(enumerated_devices, tuple)
        or not 0 < len(enumerated_devices) <= 4096
        or any(
            not isinstance(device, str)
            or not 0 < len(device) <= 4096
            or "\x00" in device
            for device in enumerated_devices
        )
    ):
        raise ValueError("Explicit bounded source path and actual device list required")
    values = inspect_recovery_info(data)["fields"]
    required = {
        "savedcalibrationfilepath",
        "selectedj2534device",
        "writecpuindex",
        "writing",
        "writingendblock",
        "usenewsoftwarepassword",
    }
    if not required <= values.keys():
        raise ValueError("Complete native saved recovery association required")
    if values["savedcalibrationfilepath"] != supplied_source_path:
        raise ValueError("Saved recovery calibration source path mismatch")
    try:
        device = enumerated_devices.index(values["selectedj2534device"])
    except ValueError:
        raise ValueError(
            "Saved recovery device absent from supplied device list"
        ) from None
    try:
        count = len(bind_native_cpu_records(container))
    except ValueError:
        count = len(
            {block.ecu_index for block in bind_native_logical_records(container)}
        )
    index = values["writecpuindex"]
    if not 0 <= index < count:
        raise ValueError("Saved recovery CPU index exceeds imported calibration")
    return NativeSavedRecovery(
        container.digest,
        device,
        index,
        bool(values["writing"]),
        bool(values["writingendblock"]),
        bool(values["usenewsoftwarepassword"]),
        MappingProxyType(dict(values)),
    )


@dataclass(frozen=True)
class NativeCIDExportResult:
    """Actual StartGetCID vector and seventh BOOL* output, not compatibility."""

    software_ids: tuple[str, ...]
    native_result: bool

    def __post_init__(self):
        if (
            type(self.native_result) is not bool
            or not isinstance(self.software_ids, tuple)
            or len(self.software_ids) > 32
            or any(
                not isinstance(cid, str)
                or not cid.isascii()
                or not 0 < len(cid) < 32
                or "\x00" in cid
                for cid in self.software_ids
            )
        ):
            raise ValueError(
                "Actual native BOOL and bounded32x31-byte CID vector required"
            )


def native_cid_phase(
    step: NativeExecuteStep,
    recovery_state: NativeRecoveryState,
    run_export: Callable[[float], NativeCIDExportResult],
    *,
    current_software_ids: tuple[str, ...],
    current_get_cid_failed_734: bool,
    native_build: int = 18,
    timeout: float = 30,
    cancelled: Callable[[], bool] = lambda: False,
    clock: Callable[[], float] = time.monotonic,
) -> dict:
    """Native6470 GetCID caller result-copy/BOOL return, after dispatch preflight.

    The native caller leaves phase and CPU index unchanged. Its fixed context has
    32-byte slots at e8 through4e8; unsafe native buffer overflow is rejected at
    the host boundary. No software-ID observation is converted into compatibility
    or a fabricated successful BOOL. Only a source-typed native_cuw_code exception
    follows the native608/734/5f8 catch continuation.
    """
    from dataclasses import asdict, replace

    if (
        type(native_build) is not int
        or native_build not in (12, 18)
        or not isinstance(step, NativeExecuteStep)
        or step.phase != 0
        or not isinstance(recovery_state, NativeRecoveryState)
        or recovery_state.phase_738 != 0
    ):
        raise ValueError("Source-bound native GetCID phase and pointer state required")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or not 0 < timeout <= 86400
    ):
        raise ValueError("Bounded native GetCID caller deadline required")
    deadline = clock() + timeout
    cids = NativeCIDExportResult(current_software_ids, False).software_ids
    if type(current_get_cid_failed_734) is not bool:
        raise ValueError("Actual prior native GetCID failure flag required")
    native_failed = current_get_cid_failed_734
    error = None

    def budget():
        if cancelled():
            raise InterruptedError("Native GetCID caller cancelled")
        value = deadline - clock()
        if value <= 0:
            raise TimeoutError("Native GetCID caller deadline expired")
        return value

    try:
        try:
            result = run_export(budget())
        except (Exception, KeyboardInterrupt):
            budget()
            raise
        budget()
        if not isinstance(result, NativeCIDExportResult):
            raise TypeError("Actual native GetCID vector/BOOL pair required")
        cids = result.software_ids
        step = NativeExecuteStep(result.native_result, step.phase, step.cpu_index)
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - no provider payload in reports
        error = type(exc).__name__
        code = getattr(exc, "native_cuw_code", None)
        if (
            not isinstance(exc, InterruptedError)
            and type(code) is int
            and 0 <= code <= 0xFFFFFFFF
        ):
            recovery_state = replace(recovery_state, error_608=code, flag_5f8=True)
            native_failed = True
        step = NativeExecuteStep(False, step.phase, step.cpu_index)
    return {
        "state": "phase_completed" if step.succeeded else "recovery_required",
        "native_step": step,
        "native_state": asdict(recovery_state),
        "get_cid_failed_734": native_failed,
        "software_ids": cids,
        "cid_count_4e8": len(cids),
        "error": error,
        "programming_completed": False,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "provenance": f"static-native-CUW{native_build}-GetCID-caller",
    }
