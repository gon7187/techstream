"""Native utility CALLFUNC contracts with explicitly selected host providers.

No OEM library is loaded and no transport is opened. Native statuses are values;
missing dependencies, cancellation and deadlines remain host exceptions.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from scripts.profiles import VehicleProfile
from scripts.support import correspondence_rows, word
from scripts.toyota import CommandFrame, ToyotaCodecError
from scripts.toyota_session import (
    Cancelled,
    CommandSpec,
    NativeStatus,
    SessionError,
    ToyotaSession,
)

Value = int | bytes
Operations = Mapping[str, str | tuple[str, ...]]


@dataclass(frozen=True)
class NativeUtilityCommand(CommandSpec):
    """Recovered native response predicates, before a wrapper returns its status."""

    minimum: int = 0
    exact: int = 0
    echo: int | None = None

    def validate(self, reply: bytes) -> bytes:
        value = super().validate(reply)
        if len(value) < self.minimum or (self.exact and len(value) != self.exact):
            raise NativeStatus(3, value)
        if self.echo is not None and value[1] != self.echo:
            raise NativeStatus(7, value)
        return value


@dataclass(frozen=True)
class SupportRecord:
    """One native cache item: 256 offsets, support bitmap buffer, receive buffer."""

    offsets: tuple[int, ...]
    support: bytes
    received: bytes

    def __post_init__(self) -> None:
        if len(self.offsets) != 256 or any(
            type(offset) is not int or not 0 <= offset <= 0x1020
            for offset in self.offsets
        ):
            raise ValueError("Support offsets must be 256 native bounded uint32 values")
        if not isinstance(self.support, bytes) or not isinstance(self.received, bytes):
            raise TypeError("Support and received buffers must be bytes")
        if max(len(self.support), len(self.received)) > 0x1020:
            raise ValueError("Support cache buffer exceeds native capacity")


class SupportCache:
    """Native d790/dc40/a9c0 cache lookup, using caller-supplied observations.

    Keys retain native order (record kind, key1, protocol, key2). Omitted context
    selectors resolve to the explicitly selected protocol/key1/key2.
    """

    def __init__(
        self,
        records: Mapping[tuple[int, int, int, int], SupportRecord],
        *,
        selected: tuple[int, int, int],
    ):
        if len(selected) != 3 or any(
            type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in selected
        ):
            raise ValueError("Selected cache context requires three uint32 values")
        self.records = dict(records)
        for key, record in self.records.items():
            if (
                len(key) != 4
                or any(
                    type(value) is not int or not 0 <= value <= 0xFFFFFFFF
                    for value in key
                )
                or key[0] > 255
                or key[2] > 255
                or not isinstance(record, SupportRecord)
            ):
                raise ValueError("Invalid native support-cache key or record")
        self.selected = selected

    def _record(
        self, kind: int, context: tuple[int, ...]
    ) -> tuple[int, SupportRecord | None]:
        protocol, key1, key2 = (context + (0, 0, 0))[:3]
        protocol &= 255
        if protocol == 0:
            if key1 or key2:
                return 83, None
            protocol, key1, key2 = self.selected
            protocol &= 255
        elif not key1 or (not key2 if protocol == 8 else bool(key2)):
            return 83, None
        record = self.records.get((kind & 255, key1, protocol, key2))
        return (0, record) if record is not None else (84, None)

    def check(self, arguments: tuple[int, ...]) -> int:
        support_id, position, mask, kind, *context = arguments
        status, record = self._record(kind, tuple(context))
        if record is None:
            return status
        offset = record.offsets[support_id & 255]
        if offset == 0x1020:
            return 22
        if offset + 1 >= len(record.support):
            return 99
        length = record.support[offset + 1]
        if offset + 1 + length > 0x1020:
            return 99
        if length < ((position - 2) & 0xFFFFFFFF):
            return 22
        index = offset + max(2, position - 1)
        if index >= len(record.support):
            return 99
        byte = record.support[index]
        return 0 if byte and byte & (mask & 255) == mask & 255 else 22

    def receive(self, arguments: tuple[int, ...]) -> tuple[int, int]:
        support_id, position, kind, *context = arguments
        _, record = self._record(kind, tuple(context))
        if record is None:
            return 0, 0
        index = record.offsets[support_id & 255] + position
        if index >= len(record.received):
            raise SessionError("Support receive lookup exceeds observed reply")
        return 1, record.received[index]


class UtilityBindings:
    """Callable compatible with UtilityRuntime.library.

    Operation keys select existing session descriptors; their names carry no
    implicit service bytes. Settings require a transport configure provider.
    Exchange must be bounded, as required by ToyotaSession. abort may interrupt
    that transport; Python threads are never forcibly killed or detached.
    """

    def __init__(
        self,
        session: ToyotaSession | None,
        *,
        operations: Operations | None = None,
        ecu_id: int | None = None,
        protocol: int | None = None,
        support: SupportCache | None = None,
        configure: Callable[[str, int], None] | None = None,
        progress: Callable[[], bool] | None = None,
        abort: Callable[[], None] | None = None,
        wait: Callable[[float], None] = time.sleep,
    ):
        for value in (ecu_id, protocol):
            if value is not None and (
                type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            ):
                raise ValueError("Selected ECU metadata must fit uint32")
        self.session = session
        self.operations = dict(operations or {})
        self.ecu_id, self.protocol = ecu_id, protocol
        self.support, self.configure, self.progress = support, configure, progress
        self.abort, self.wait = abort, wait
        self._lock = threading.RLock()
        self._io = threading.Lock()
        self._worker: threading.Thread | None = None
        self._stop = threading.Event()
        self._status = 99
        self._failure: BaseException | None = None
        self._reply = b""
        self._progress_pressed = False
        self._initialize: Callable[[bool], int] | None = None
        self._finalize: Callable[[], int] | None = None
        self._keepalive: Callable[[bool], None] | None = None
        self._native_context: dict[int, int] | None = None
        self._native_mode = 0
        self.provenance: dict[str, object] = {}

    @classmethod
    def from_profile(
        cls,
        profile: VehicleProfile,
        session: ToyotaSession,
        *,
        broker: Mapping[int, int],
        initialize: Callable[[Mapping[int, int], bool], int],
        finalize: Callable[[], int],
        configure: Callable[[str, int], None],
        keepalive: Callable[[bool], None],
        support: SupportCache | None = None,
        abort: Callable[[], None] | None = None,
        wait: Callable[[float], None] = time.sleep,
    ) -> UtilityBindings:
        """Bind proven native templates to a selected profile and broker snapshot.

        Native broker keys are literal: 74/AB addresses, 6F/70 transport selectors,
        73 ECU ID. The caller must recover/select these values; no name heuristic
        converts a vehicle profile into missing runtime protocol observations.
        Native Init/Final are driver lifecycle, not fabricated diagnostic frames.
        """
        required = {0x74, 0xAB, 0x6F, 0x70, 0x73}
        if not required <= broker.keys() or any(
            type(key) is not int
            or type(value) is not int
            or not 0 <= value <= 0xFFFFFFFF
            for key, value in broker.items()
        ):
            raise SessionError(
                "Native utility requires explicit validated broker context"
            )
        if not all(
            callable(provider)
            for provider in (initialize, finalize, configure, keepalive)
        ):
            raise SessionError(
                "Native utility requires actual lifecycle/configuration providers"
            )
        context = dict(broker)
        family, protocol, ecu_id = context[0x6F], context[0x70], context[0x73]
        valid = (
            (protocol == 0x11 and family in (3, 4, 0x12))
            or protocol == 0x21
            or (protocol == 0x51 and family in (3, 4))
            or (family == 0x13 and protocol in (0x1A, 0x4A))
            or (family in (4, 0x14, 0x15) and protocol in (0x12, 0x22))
        )
        if not valid:
            raise SessionError("Native utility transport selector pair is unsupported")

        # UtilityEx builds these requests itself; they have no universal DDB ID.
        requests = {
            "mode_1": (b"\x10\x01", 6, 6, None, "c170"),
            "mode_3": (b"\x10\x03", 6, 6, None, "c170"),
            "extended_base": (b"\x10\x01", 2, 0, 1, "c230/c350"),
            "extended_three": (b"\x10\x03", 2, 0, 3, "c230"),
            "thread_0": (
                bytes.fromhex("31031014" if ecu_id == 0x1F2 else "31031106"),
                0,
                0,
                None,
                "4200",
            ),
            "thread_1": (bytes.fromhex("31031101"), 0, 0, None, "4440"),
            "thread_2": (bytes.fromhex("31031103"), 0, 0, None, "4660"),
            "thread_3": (
                bytes.fromhex("31011106" if ecu_id == 0x1AE else "31011014ffff"),
                0,
                0,
                None,
                "4010",
            ),
        }
        observed: dict[bytes, list[str]] = {}
        functions = {
            word(row, 2)
            for row in correspondence_rows(
                profile.catalog.management, 18, profile.exception_ids
            )
            if word(row, 0) == profile.category
        }
        for function in sorted(functions):
            for selected in profile.frame_records(function):
                observed.setdefault(selected.frame.request, []).append(
                    selected.provenance
                )
        commands = dict(session.commands)
        prefix = f"native-utility:{profile.database.sha256}:{profile.category}"
        operations: dict[str, str | tuple[str, ...]] = {}
        for name, (request, minimum, exact, echo, rva) in requests.items():
            key = f"{prefix}:{name}"
            if key in commands:
                raise SessionError("Native utility descriptor name already exists")
            provenance = f"UtilityExNeoNK:RVA={rva};profile={profile.database.sha256};category={profile.category}"
            if request in observed:
                provenance += ";matching_selected_ddb=" + "|".join(observed[request])
            commands[key] = NativeUtilityCommand(
                CommandFrame(request),
                check="raw",
                provenance=provenance,
                minimum=minimum,
                exact=exact,
                echo=echo,
            )
            operations[name] = key
        for flag in (0, 1):
            operations[f"start_extended_{flag}"] = (
                str(operations["extended_base"]),
                str(operations["extended_three"]),
            )
            operations[f"end_extended_{flag}"] = str(operations["extended_base"])
        selected_session = ToyotaSession(
            session.exchange,
            session.ecu,
            commands,
            limits=session.limits,
            cancelled=session.cancelled,
            clock=session.clock,
        )
        result = cls(
            selected_session,
            operations=operations,
            ecu_id=ecu_id,
            protocol=protocol,
            support=support,
            configure=configure,
            abort=abort,
            wait=wait,
        )
        result._initialize = lambda refresh: initialize(dict(context), refresh)
        result._finalize, result._keepalive = finalize, keepalive
        result._native_context = context
        result.provenance = {
            "profile": profile.report(),
            "broker": {f"{key:X}": value for key, value in context.items()},
            "selection": "native-template-with-explicit-broker-context",
            "physical": "PHYSICAL_UNCONFIRMED",
        }
        return result

    def press_progress(self) -> None:
        """Latch the UI progress button until the next native getter consumes it."""
        with self._lock:
            self._progress_pressed = True

    @staticmethod
    def _integer(token: str, values: dict[str, Value]) -> int:
        value = values.get(token)
        if value is None:
            try:
                value = int(token, 0) if not token.isdecimal() else int(token)
            except ValueError as error:
                raise ValueError(
                    "Native callback requires an integer descriptor"
                ) from error
        if type(value) is not int or not -(1 << 31) <= value <= 0xFFFFFFFF:
            raise ValueError("Native callback integer is outside DWORD bounds")
        return value & 0xFFFFFFFF

    def _names(self, operation: str) -> tuple[str, ...]:
        if self.session is None:
            raise SessionError("Native callback requires a selected Toyota session")
        names = self.operations.get(operation)
        if names is None:
            raise SessionError(f"Native utility operation not selected: {operation}")
        result = (names,) if isinstance(names, str) else names
        if not result or any(name not in self.session.commands for name in result):
            raise SessionError(f"Native utility descriptors unavailable: {operation}")
        return result

    def _execute(self, operation: str, *, cleanup: bool = False) -> tuple[int, bytes]:
        lifecycle: Callable[[], int] | None = None
        initialize = self._initialize
        if operation.startswith("initialize_") and initialize is not None:
            refresh = operation == "initialize_1"
            lifecycle = lambda: initialize(refresh)
        elif operation == "finalize":
            lifecycle = self._finalize
        names = () if lifecycle is not None else self._names(operation)
        assert self.session is not None
        worker = threading.current_thread() is self._worker
        if not worker and not self._io.acquire(blocking=False):
            return 15, b""
        try:
            session = self.session
            previous_mode = self._native_mode
            if self._native_context is not None and (
                lifecycle is not None
                or operation.startswith(("mode_", "start_extended_", "end_extended_"))
            ):
                # An applied request can lose its acknowledgement or host deadline.
                self._native_mode = 0
            if cleanup:
                session = ToyotaSession(
                    session.exchange,
                    session.ecu,
                    session.commands,
                    limits=session.limits,
                    clock=session.clock,
                )
            try:
                if lifecycle is not None:
                    deadline = session.clock() + session.limits.seconds
                    session._begin()
                    session._check()
                    try:
                        status = lifecycle()
                    finally:
                        session._check()
                    if type(status) is not int or not 0 <= status <= 0xFFFFFFFF:
                        raise SessionError(
                            "Native driver lifecycle returned invalid status"
                        )
                    if session.clock() >= deadline:
                        raise SessionError("Native driver lifecycle deadline exceeded")
                    return status, b""
                status = 0
                reply = b""
                try:
                    try:
                        replies = session.sequence(names)
                        if any(len(value) > 0x1020 for value in replies):
                            raise SessionError(
                                "Native utility reply exceeds buffer capacity"
                            )
                        reply = replies[-1]
                    except ToyotaCodecError as error:
                        status, reply = error.code, getattr(error, "reply", b"")
                        if len(reply) > 0x1020:
                            raise SessionError(
                                "Native utility partial reply exceeds buffer capacity"
                            ) from error
                except BaseException as error:
                    if operation == "end_extended_1" and self._keepalive is not None:
                        try:
                            deadline = session.clock() + session.limits.seconds
                            self._keepalive(False)
                            if session.clock() >= deadline:
                                raise SessionError(
                                    "Keepalive release deadline exceeded"
                                )
                        except BaseException as release:  # noqa: BLE001 -- preserve cancellation and release failure
                            raise BaseExceptionGroup(
                                "Utility operation and keepalive release failed",
                                [error, release],
                            ) from None
                    raise
                try:
                    if self._keepalive is not None:
                        if operation == "start_extended_1" and not status:
                            self._keepalive(True)
                        elif operation == "end_extended_1":
                            self._keepalive(False)
                        elif not status and operation in ("mode_1", "mode_3"):
                            mode = int(operation[-1])
                            if mode == 3 or previous_mode == 3:
                                self._keepalive(mode == 3)
                finally:
                    session._check()
                if not status:
                    if operation.startswith("start_extended_"):
                        self._native_mode = 3
                    elif operation.startswith("end_extended_"):
                        self._native_mode = 1
                    elif operation in ("mode_1", "mode_3"):
                        self._native_mode = int(operation[-1])
                return status, reply
            except ToyotaCodecError as error:
                partial = getattr(error, "reply", b"")
                if len(partial) > 0x1020:
                    raise SessionError(
                        "Native utility partial reply exceeds buffer capacity"
                    ) from error
                return error.code, partial
            finally:
                if cleanup:
                    self.session.trace.extend(session.trace)
        finally:
            if not worker:
                self._io.release()

    def _check(self, deadline: float) -> None:
        assert self.session is not None
        if self.session.cancelled():
            raise Cancelled("Utility operation cancelled")
        if self.session.clock() >= deadline:
            raise SessionError("Utility operation deadline exceeded")

    def _sleep(self, seconds: float, *, deadline: float | None = None) -> None:
        if self.session is None:
            raise SessionError("SleepThread requires a bounded selected session")
        deadline = (
            deadline
            if deadline is not None
            else (self.session.clock() + self.session.limits.seconds)
        )
        remaining = seconds
        while remaining > 0:
            self._check(deadline)
            duration = min(remaining, 0.05)
            self.wait(duration)
            remaining -= duration
        self._check(deadline)

    def _thread_work(self, index: int) -> None:
        assert self.session is not None
        deadline = self.session.clock() + min(10.0, self.session.limits.seconds)
        status, reply = 99, b""
        failure: BaseException | None = None
        needs_cleanup = True
        try:
            names = self._names(f"thread_{index}")
            if len(names) != 1:
                raise SessionError(
                    "Native thread requires one selected request descriptor"
                )
            request = self.session.commands[names[0]].frame.request
            if len(request) < 4:
                raise SessionError("Native thread request requires its selected header")
            for _ in range(self.session.limits.exchanges):
                self._check(deadline)
                if self._stop.is_set():
                    break
                if index != 3:
                    self._sleep(0.2, deadline=deadline)
                if self._stop.is_set():
                    break
                status, received = self._execute(f"thread_{index}")
                self._check(deadline)
                if index == 3:
                    needs_cleanup = (
                        bool(status)
                        or len(received) < 4
                        or received[1:4] != request[1:4]
                    )
                    status = 111 if needs_cleanup else 0
                    break
                if status:
                    break
                if len(received) < 5 or received[1:4] != request[1:4]:
                    status = 3
                    break
                if received[4] != 1:
                    reply = received
                    break
            else:
                raise SessionError("Native thread exchange budget exhausted")
        except BaseException as error:  # noqa: BLE001 -- relay worker failure to owner
            failure = error
        if needs_cleanup:
            try:
                cleanup, _ = self._execute("end_extended_1", cleanup=True)
                if cleanup:
                    # Unlike native workers 1/2, host reports failed release as
                    # a host failure rather than hiding a potentially live session.
                    if failure is not None or index in (1, 2):
                        raise ToyotaCodecError("Native thread cleanup failed", cleanup)
                    status = cleanup
            except BaseException as error:  # noqa: BLE001 -- retain both failures
                failure = (
                    BaseExceptionGroup(
                        "Utility worker and cleanup failed", [failure, error]
                    )
                    if failure is not None
                    else error
                )
        self._io.release()
        with self._lock:
            self._status, self._reply, self._failure = status, reply, failure

    def _thread_status(self) -> int:
        with self._lock:
            if self._worker is not None and self._worker.is_alive():
                return 15
            if self._failure is not None:
                raise self._failure
            return 99 if self._status == 15 else self._status

    def _start(self, index: int) -> int:
        with self._lock:
            if self._worker is not None and self._worker.is_alive():
                return 15
            names = self._names(f"thread_{index}")
            assert self.session is not None
            if len(names) != 1:
                raise SessionError(
                    "Native thread requires one selected request descriptor"
                )
            spec = self.session.commands[names[0]]
            if (
                spec.check != "raw"
                or spec.payload_offset
                or len(spec.frame.request) < 4
            ):
                raise SessionError("Native thread requires raw full-header descriptor")
            self._names("end_extended_1")
            if not self._io.acquire(blocking=False):
                return 15
            self._stop.clear()
            self._failure, self._reply, self._status = None, b"", 15
            self._worker = threading.Thread(target=self._thread_work, args=(index,))
            try:
                self._worker.start()
            except RuntimeError:
                self._worker, self._status = None, 99
                self._io.release()
                raise
        if index == 3:
            return self._join(False)
        return 15

    def _join(self, abort: bool, *, request_stop: bool = False) -> int:
        if self.session is None:
            raise SessionError("Native thread requires a selected session")
        if request_stop:
            self._stop.set()
        if abort and self.abort is not None:
            self.abort()
        deadline = self.session.clock() + self.session.limits.seconds
        while self._thread_status() == 15:
            self._check(deadline)
            assert self._worker is not None
            self._worker.join(0.05)
        return self._thread_status()

    def __call__(
        self, name: str, args: tuple[str, ...], values: dict[str, Value]
    ) -> int:
        noargs = {"GetThreadStatus", "GetProgButton"}
        support = {"ChkA8SptInfoForBitWrap", "GetSptTableDataPosRecvData"}
        supported = (
            noargs
            | support
            | {
                "ChangeSessionMode",
                "SetNrLimitTime",
                "SetResponseNoCheck",
                "SetUseReqMode30_3BFuncFlag",
                "InitialCom",
                "FinalCom",
                "SleepThread",
                "StartExtendedSessionP5",
                "EndExtendedSessionP5",
                "StartComThread",
                "StopComThread",
                "GetThreadRecvData",
                "GetEcuId",
                "GetComProtocol",
            }
        )
        if name not in supported:
            raise SessionError(f"Unrecovered native utility callback: {name}")
        if name == "StartComThread":
            with self._lock:
                if self._worker is not None and self._worker.is_alive():
                    return 15
        count = len(args)
        invalid = -1 if name in {"GetEcuId", "GetComProtocol"} else 99
        if (
            (name in noargs and count)
            or (name in support and not 5 <= count <= 8)
            or (name == "GetThreadRecvData" and count != 2)
            or (name not in noargs | support | {"GetThreadRecvData"} and count != 1)
        ):
            return invalid
        try:
            integers = tuple(self._integer(arg, values) for arg in args)
        except ValueError:
            return invalid
        output_count = 2 if name == "GetSptTableDataPosRecvData" else 1
        outputs = {
            "InitialCom",
            "FinalCom",
            "GetEcuId",
            "GetComProtocol",
            "GetThreadRecvData",
        } | support
        if name in outputs and any(
            arg in values and type(values[arg]) is not int
            for arg in args[-output_count:]
        ):
            return invalid

        def write(index: int, value: int) -> None:
            # Literal descriptor arguments own temporary native storage.
            if args[index] in values:
                values[args[index]] = value

        if name in {"GetEcuId", "GetComProtocol"}:
            value = self.ecu_id if name == "GetEcuId" else self.protocol
            if value is None:
                raise SessionError("Native ECU metadata has not been selected")
            write(0, value if name == "GetEcuId" else value & 255)
            return 0
        if name == "GetProgButton":
            with self._lock:
                pressed, self._progress_pressed = self._progress_pressed, False
            return int(pressed or (self.progress is not None and self.progress()))
        if name in support:
            if self.support is None:
                raise SessionError("Native support cache has not been selected")
            if name == "ChkA8SptInfoForBitWrap":
                write(-1, self.support.check(integers[:-1]))
            else:
                result, byte = self.support.receive(integers[:-2])
                write(-2, result)
                write(-1, byte)
            return 0
        if name.startswith("Set"):
            if self.configure is None:
                raise SessionError("Native utility transport configuration unavailable")
            value = integers[0]
            if name == "SetUseReqMode30_3BFuncFlag":
                value = int(bool(value))
            elif name == "SetResponseNoCheck":
                value = int(value == 1)
            if not self._io.acquire(blocking=False):
                return 15
            try:
                if self.session is None:
                    raise SessionError(
                        "Native configuration requires a selected session"
                    )
                self.session._begin()
                self.session._check()
                try:
                    self.configure(name, value)
                finally:
                    self.session._check()
            finally:
                self._io.release()
            return 0
        if name == "SleepThread":
            self._sleep(integers[0] / 1000)
            return 0
        if name == "GetThreadStatus":
            return self._thread_status()
        if name == "StartComThread":
            if integers[0] > 3:
                return 99
            return self._start(integers[0])
        if name == "StopComThread":
            return self._join(bool(integers[0]), request_stop=True)
        if name == "GetThreadRecvData":
            self._thread_status()
            with self._lock:
                if integers[0] >= len(self._reply):
                    raise SessionError(
                        "Native thread receive offset exceeds observed reply"
                    )
                write(1, self._reply[integers[0]])
            return 0
        if name == "ChangeSessionMode":
            mode = integers[0] & 255
            if mode not in (1, 3):
                return 99
            if self._native_context is not None and self._native_mode == mode:
                return 0
            status, reply = self._execute(f"mode_{mode}")
            return status or (0 if len(reply) >= 6 else 3)
        if name == "InitialCom":
            status, _ = self._execute(f"initialize_{int(bool(integers[0]))}")
            write(0, status)
            return 0
        if name == "FinalCom":
            status, _ = self._execute("finalize")
            write(0, status)
            return 0
        if self.session is None:
            return 99
        if self._native_context is not None and not (
            self._native_context[0x70] in (0x12, 0x22)
            and self._native_context[0x6F] != 4
        ):
            return 99
        operation = (
            "start_extended" if name == "StartExtendedSessionP5" else "end_extended"
        )
        status, _ = self._execute(f"{operation}_{int(bool(integers[0]))}")
        return status
