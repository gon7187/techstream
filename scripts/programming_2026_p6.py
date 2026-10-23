"""Source-identified CUW2026 Phase6/DCMPRL primitives over injected communication.

No native binary is executed and no adapter is opened. Physical behavior remains
PHYSICAL_UNCONFIRMED. Runtime bounds are host policy rather than OEM limits.
"""

from __future__ import annotations

import sys
import time
import weakref
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from scripts.calibration import CalibrationContainer
from scripts.calibration_2026 import (
    Native2026Metadata,
    native2026_archive,
    native2026_validate_runtime_metadata,
)
from scripts.cuw_2026 import DCMGetterState2026, DHControllerState2026
from scripts.cuw_large import (
    LargeMaterialization2026,
    LargeSource2026,
    NativeLargeContainer2026,
    validate_large_materialization_2026,
)
from scripts.native_modules import NativeModuleIdentity, identify_native_module
from scripts.programming_2026_common import (
    CanDiag2026,
    CommonResponseError,
    NativeRuntime2026,
    NativeSecurityComposer2026,
    NotificationBool,
    SecretInfoClient,
    is_native_exception2026,
    native2026_metadata,
    native_error_fields2026,
)
from scripts.programming_2026_legacy import writing_error_dispose


@dataclass(frozen=True)
class DCMPRLContext:
    request_id: bytes
    response_id: bytes
    prl: bool
    denso_dcm: bool
    receive_timeout_ms: int
    wait_after_flashing_ms: int
    flash_size: int | None = None

    def __post_init__(self):
        if any(
            not isinstance(x, bytes) or len(x) != 3
            for x in (self.request_id, self.response_id)
        ):
            raise ValueError("Exact native three-byte DCMPRL identifiers required")
        if type(self.prl) is not bool or type(self.denso_dcm) is not bool:
            raise ValueError("Native ECU/CPU classification must be Boolean")
        for x in (self.receive_timeout_ms, self.wait_after_flashing_ms):
            if type(x) is not int or not 0 <= x <= 120000:
                raise ValueError("Native milliseconds outside host bounds")
        if self.flash_size is not None and (
            type(self.flash_size) is not int
            or not 0 < self.flash_size <= 64 * 1024 * 1024
        ):
            raise ValueError("Native materialized archive flash size required")
        if self.wait_after_flashing_ms % 500:
            raise ValueError(
                "Native post-flash countdown must terminate in 500-ms steps"
            )


def dcmprl_key(seed: bytes) -> bytes:
    """DCMPRLPrepare 1040: native byte arithmetic, with no embedded secret."""
    if not isinstance(seed, bytes) or len(seed) != 2:
        raise ValueError("Native two-byte DCMPRL seed required")
    return bytes(((seed[1] + 0x3B) & 255, (seed[0] + seed[1] + 0x13) & 255))


def dcmprl_getter_host_records(
    first_identifier_record: bytes,
    contact_buffer: bytes,
    *,
    first_cpu_percent: int,
    prl: bool,
) -> tuple[bytes, bytes]:
    """Version15b0 host writes after its version helper returns successfully.

    Engine-owned copied records are required. GetString(capacity7) cannot fit
    five bytes as hex plus NUL, so its existing identifier string stays intact.
    This reducer does not manufacture missing engine records or apply on failure.
    """
    if (
        not isinstance(first_identifier_record, bytes)
        or len(first_identifier_record) != 12
        or not isinstance(contact_buffer, bytes)
        or len(contact_buffer) != 33
        or type(first_cpu_percent) is not int
        or not 0 <= first_cpu_percent <= 0xFFFFFFFF
        or type(prl) is not bool
    ):
        raise ValueError(
            "Exact native identifier/contact records and progress required"
        )
    identifier = bytes(4) + first_identifier_record[4:]
    contact = (
        b"CAN\0" + contact_buffer[4:]
        if first_cpu_percent == 0 and prl
        else contact_buffer
    )
    return identifier, contact


def _record_source_error(engine_state, error, kind, *, generic_code=None):
    if engine_state is None or not is_native_exception2026(error):
        return
    try:
        primary, secondary = native_error_fields2026(error)
    except TypeError:
        if generic_code is None:
            return
        primary, secondary = generic_code, None
    engine_state.record_native_error(kind, primary, secondary)


def decode_p6_cids(response: bytes) -> tuple[str, ...]:
    """P6CIDGetter 15b0: count, reserved byte, then flag +16-byte records."""
    if (
        not isinstance(response, bytes)
        or not 22 <= len(response) <= 4124
        or not response.startswith(b"\x62\xf1\x88")
    ):
        raise ValueError("Malformed native Phase6 CID response")
    if len(response) != 5 + response[3] * 17:
        raise ValueError("Native Phase6 CID count/length mismatch")
    return tuple(
        record.split(b"\0", 1)[0].decode("latin1")
        for offset in range(6, len(response), 17)
        if (record := response[offset : offset + 16])[0]
    )


class DCMPRL2026:
    """Actual DCMPRL getter/prepare/flash chronology over primitive providers.

    action carries native address-prefixed read/write primitives through the
    source-recovered CanDiag2026 state machine. Providers enforce remaining
    time while blocked. A failure preserves the last observable programming stage.
    """

    def __init__(
        self,
        context: DCMPRLContext,
        action: Callable | None = None,
        *,
        runtime: NativeRuntime2026 | None = None,
        timeout: float = 60,
        clock: Callable = time.monotonic,
        cancelled: Callable = lambda: False,
        native_cancelled: Callable[[], bool] | None = None,
        getter_state: DCMGetterState2026 | None = None,
        notification: NotificationBool | None = None,
        engine_state: DHControllerState2026 | None = None,
    ):
        if not isinstance(context, DCMPRLContext):
            raise TypeError("Frozen DCMPRL context required")
        self.context = context
        self._operation = None
        self._flash_native_failure = None
        if getter_state is not None and type(getter_state) is not DCMGetterState2026:
            raise TypeError("Engine-issued native DCM getter state required")
        if notification is not None and type(notification) is not NotificationBool:
            raise TypeError("Concrete source-bound native notification required")
        self.getter_state, self.notification = getter_state, notification
        if engine_state is not None and type(engine_state) is not DHControllerState2026:
            raise TypeError("Engine-issued native programming state required")
        self.engine_state = engine_state
        self._started = False
        if runtime is None:
            if action is None:
                raise TypeError("Injected DCMPRL primitive provider required")
            runtime = NativeRuntime2026(
                action,
                timeout=timeout,
                clock=clock,
                cancelled=cancelled,
                native_cancelled=native_cancelled,
            )
        elif not isinstance(runtime, NativeRuntime2026) or action is not None:
            raise TypeError(
                "One concrete DCMPRL runtime or primitive provider required"
            )
        self.runtime = runtime
        self._resources: list[tuple[str, dict]] = []
        self.diag = CanDiag2026(self.runtime)
        self.state = {
            "stage": "initial",
            "transferred": 0,
            "progress": 0,
            "percent": 0,
            "complete": False,
            "cleanup_errors": [],
        }
        if engine_state is not None:
            self.state["progress"] = engine_state.transferred_bytes[
                engine_state.native_cpu_index
            ]
            self.state["percent"] = engine_state.progress[engine_state.native_cpu_index]

    def _begin(self):
        if self._started:
            raise ValueError("A native export instance cannot be reused")
        self._started = True
        self.runtime.check()

    def _wait(self, milliseconds: int):
        self.runtime.call("wait", milliseconds=milliseconds)

    def _getter_complete(self):
        if self.getter_state is not None:
            self.getter_state.apply_success()
            self.state["host_records_applied"] = True
        self.state["complete"] = True

    def _programming_notification(self, value: bool):
        self.state["notification"] = value
        if self.notification is None:
            self.runtime.call("programming_notification", value=value)
        else:
            self.notification.assign(value)

    def _call(
        self, stage: str, request: bytes, expected: bytes, minimum: int | None = None
    ):
        self.state["stage"] = stage
        self.runtime.check()
        code = {
            "version": 3,
            "seed": 0x10,
            "key": 0x11,
            "reset": 0x18,
            "start_routine": 0x19,
            "stop_routine": 0x19,
            "download": 0x1A,
            "transfer": 0x1B,
            "transfer_exit": 0x1C,
        }[stage]
        return self.diag.call(
            self.context.request_id.rjust(5, b"\0"),
            self.context.response_id.rjust(5, b"\0"),
            request,
            expected,
            minimum=len(expected) if minimum is None else minimum,
            error_code=code,
            delay_ms=100,
            check_native_cancel=stage == "version",
        )

    def _filter(self):
        identifier = self.diag.start_filter(
            self.context.request_id.rjust(5, b"\0"),
            self.context.response_id.rjust(5, b"\0"),
        )
        self._resources.append(("stop_filter", {"identifier": identifier}))

    def _timeout(self, milliseconds: int):
        old = self.runtime.call("get_timeout")
        if type(old) is not int or not 0 <= old <= 0xFFFFFFFF:
            raise ValueError("Native prior timeout required")
        self.runtime.own("set_timeout", milliseconds=old)
        self._resources.append(("set_timeout", {"milliseconds": old}))
        self.runtime.call("set_timeout", milliseconds=milliseconds)

    def _finish(self):
        errors = []
        failures = []
        suppressed = []
        while self._resources:
            operation, values = self._resources.pop()
            if operation == "set_timeout":
                if self._flash_native_failure is not None:
                    self._flash_native_failure = None
                    try:
                        self._dispose_flash_progress()
                    except (Exception, KeyboardInterrupt) as error:
                        # Native18c6 is outside the catches; timeout18d4 is not reached.
                        self.state["complete"] = False
                        self.state["native_cleanup_escape"] = True
                        self.state["cleanup_errors"] = errors + [type(error).__name__]
                        self.state["native_suppressed_cleanup_errors"] = suppressed
                        raise
                if (
                    self._operation == "prepare"
                    and self.engine_state is not None
                    and self.engine_state.error_kind == 1
                ):
                    self.engine_state.mark_native_retry()
                    self.state["retry_required"] = True
            if self.runtime.owns_resource(operation, **values):
                try:
                    self.runtime.release(operation, **values)
                except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - release all export-owned resources
                    if operation == "stop_filter" and is_native_exception2026(error):
                        # Prepare15c3/Flash1893/Getter17d9 native cleanup catches
                        # preserve the already-computed business success BOOL.
                        suppressed.append(type(error).__name__)
                    else:
                        errors.append(type(error).__name__)
                        failures.append(error)
        self.state["cleanup_errors"] = errors
        self.state["native_suppressed_cleanup_errors"] = suppressed
        if errors:
            self.state["complete"] = False
            self.state["native_cleanup_escape"] = True
            active_error = sys.exception()
            native_failure = next(
                (failure for failure in failures if is_native_exception2026(failure)),
                None,
            )
            if native_failure is not None and (
                active_error is None or is_native_exception2026(active_error)
            ):
                raise native_failure
            if active_error is None:
                raise failures[0]
            active_error.add_note(
                "DCMPRL resource restoration failed: " + ", ".join(errors)
            )

    def _dispose_flash_progress(self):
        counts, percentages = [self.state["progress"]], [self.state["percent"]]

        def notify(field):
            self.state["progress"] = counts[0]
            self.state["percent"] = percentages[0]
            value = counts[0] if field == "count" else percentages[0]
            if self.engine_state is not None:
                setter = (
                    self.engine_state.set_native_count
                    if field == "count"
                    else self.engine_state.set_native_percentage
                )
                setter(self.engine_state.native_cpu_index, value)
            self.runtime.call("progress", cleanup=True, field=field, value=value)

        writing_error_dispose(0, counts, percentages, notify)

    def get_version(self, *, delay_ms: int = 7000) -> str:
        if type(delay_ms) is not int or not 0 <= delay_ms <= 120000 or delay_ms % 500:
            raise ValueError("Native getter countdown requires bounded 500-ms steps")
        if self.runtime.native_cancelled is None:
            raise ValueError("Native getter cancellation observation must be bound")
        if self.getter_state is not None:
            self.getter_state.validate_current()
        self._operation = "get_cid"
        self._begin()
        try:
            self.runtime.call_owned("connect", "disconnect", protocol=6)
            self._resources.append(("disconnect", {}))
            self.runtime.call(
                "set_timeout", milliseconds=self.context.receive_timeout_ms
            )
            self._wait(1000)
            self._filter()
            for _ in range(delay_ms // 500):
                self._wait(500)
                if self.runtime.native_cancellation_requested():
                    self.state["native_cancelled"] = True
                    self._getter_complete()
                    return ""
            sub = 0x27 if self.context.prl else 0x26
            response = self._call("version", bytes((0x21, sub)), bytes((0x61, sub)), 3)
            result = (
                response[2 : 7 if self.context.prl else 22]
                .split(b"\0", 1)[0]
                .decode("latin1")
            )
            self._getter_complete()
            return result
        except (Exception, KeyboardInterrupt) as error:
            _record_source_error(self.engine_state, error, None, generic_code=9999)
            raise
        finally:
            self._finish()

    def prepare(self, *, retry: bool) -> dict:
        if type(retry) is not bool:
            raise ValueError("Native retry flag required")
        self._operation = "prepare"
        self._begin()
        self.state["retry_required"] = retry
        try:
            self._timeout(10000)
            self._filter()
            if retry:
                self._wait(100)
                seed = self._call("seed", b"\x27\x01", b"\x67\x01", 4)[2:4]
                self._wait(100)
                self._call("key", b"\x27\x02" + dcmprl_key(seed), b"\x67\x02")
            self._wait(100)
            self._call("reset", b"\x11\x01", b"\x51\x01")
            self._wait(15000)
            self.state["complete"] = True
            return self.state
        except (Exception, KeyboardInterrupt) as error:
            if is_native_exception2026(error):
                _record_source_error(self.engine_state, error, 1, generic_code=9999)
                self.state["retry_required"] = True
            raise
        finally:
            self._finish()

    def flash(self, image: bytes) -> dict:
        if not isinstance(image, bytes) or not 0 < len(image) <= 0x1000000:
            raise ValueError("Bounded native 24-bit DCMPRL image required")
        if self.context.flash_size is None:
            raise ValueError("Source-bound native archive flash size required")
        self._operation = "write"
        self._begin()
        try:
            self._timeout(10000)
            self.state["wait_remaining_ms"] = self.context.wait_after_flashing_ms
            self.runtime.call(
                "progress",
                field="wait_remaining_ms",
                value=self.state["wait_remaining_ms"],
            )
            self._filter()
            self._programming_notification(True)
            rid = b"\x02\x01" if self.context.prl else b"\x02\x00"
            self._wait(100)
            self._call("start_routine", b"\x31\x01" + rid, b"\x71\x01" + rid)
            for offset in range(0, len(image), 1024):
                data = image[offset : offset + 1024]
                self._wait(100)
                self._call(
                    "download",
                    b"\x34\x00\x33"
                    + offset.to_bytes(3, "big")
                    + len(data).to_bytes(3, "big"),
                    b"\x74\x30",
                    5,
                )
                for sequence, position in enumerate(range(0, len(data), 60), 1):
                    block = data[position : position + 60]
                    if not self.context.denso_dcm:
                        self._wait(100)
                    self._call("transfer", bytes((0x36, sequence)) + block, b"\x76", 2)
                    self.state["transferred"] += len(block)
                    self.state["progress"] = (
                        self.state["progress"] + len(block) * 2
                    ) & 0xFFFFFFFF
                    if self.engine_state is not None:
                        self.engine_state.set_native_count(
                            self.engine_state.native_cpu_index, self.state["progress"]
                        )
                    self.runtime.call(
                        "progress", field="count", value=self.state["progress"]
                    )
                    self.state["percent"] = int(
                        self.state["progress"] / (self.context.flash_size * 2) * 100
                    )
                    if self.engine_state is not None:
                        self.engine_state.set_native_percentage(
                            self.engine_state.native_cpu_index, self.state["percent"]
                        )
                    self.runtime.call(
                        "progress", field="percent", value=self.state["percent"]
                    )
                self._wait(100)
                self._call(
                    "transfer_exit",
                    b"\x37" + (sum(data) & 65535).to_bytes(2, "big"),
                    b"\x77",
                )
            self._wait(100)
            self._call(
                "stop_routine", b"\x31\x02" + rid + b"\x01", b"\x71\x02" + rid + b"\x01"
            )
            self._wait(100)
            self._call("reset", b"\x11\x01", b"\x51\x01")
            for _ in range(self.context.wait_after_flashing_ms // 500):
                self._wait(500)
                self.state["wait_remaining_ms"] -= 500
                self.runtime.call(
                    "progress",
                    field="wait_remaining_ms",
                    value=self.state["wait_remaining_ms"],
                )
            self._programming_notification(False)
            self.state["complete"] = True
            return self.state
        except (Exception, KeyboardInterrupt) as error:
            if not is_native_exception2026(error):
                raise
            _record_source_error(self.engine_state, error, 2, generic_code=9999)
            self._flash_native_failure = error
            raise
        finally:
            self._finish()


@dataclass(frozen=True)
class DCMPRLPlan:
    context: DCMPRLContext
    image: bytes = field(repr=False)
    cpu_index: int
    module: NativeModuleIdentity


def native_dcmprl_plan(
    container: CalibrationContainer,
    cpu_index: int,
    module: NativeModuleIdentity,
    *,
    request_id: bytes,
    response_id: bytes,
    parameters: Mapping[str, int],
    node: int = 1,
) -> DCMPRLPlan:
    """Bind actual CUW CPU bytes/classifications and resolved host addressing.

    Communication addresses originate in the native host selection table, not
    guessed from a diagnostic number. Parameters preserve their native names.
    """
    if (
        not isinstance(module, NativeModuleIdentity)
        or module.cuw_build != "2026"
        or module.family
        not in (
            "TCUWCanDCMPRLVersionGetter",
            "TCUWCanDCMPRLPrepareWriter",
            "TCUWCanDCMPRLFlashWriter",
        )
    ):
        raise ValueError("Exact source-identified actual2026 DCMPRL module required")
    if identify_native_module(module.sha256, module.module_name) != module:
        raise ValueError("Native DCMPRL identity differs from authenticated registry")
    metadata = native2026_metadata(container, node=node, cpu_index=cpu_index)
    cpu = metadata.cpu
    try:
        receive_timeout = parameters["ReceiveTimeoutBeforeGetCID"]
        wait = parameters["WaitTimeAfterEndOfFlashing"]
    except KeyError as error:
        raise ValueError("Required native DCMPRL metadata/parameter absent") from error
    kind = metadata.vehicle.get("kindofecu", "")
    cpu_type = cpu.values.get("cputype", "")
    image, flash_size = b"", None
    if module.family.endswith("FlashWriter"):
        preserve = False
        if metadata.format_version not in (10, 12) and ".vbf" not in metadata.cpus[
            0
        ].values.get("cpuimagename", ""):
            preserve = parameters.get("FlagToHoldSFormatRecords")
            if type(preserve) is not bool:
                raise ValueError(
                    "Selected native FlagToHoldSFormatRecords Boolean required"
                )
        archive = native2026_archive(metadata, preserve_srecords=preserve)
        if archive.data is None or not archive.data:
            raise ValueError(
                "Selected native DCMPRL archive has no contiguous GetData buffer"
            )
        image, flash_size = archive.data, archive.flash_size
    return DCMPRLPlan(
        DCMPRLContext(
            request_id,
            response_id,
            kind == "8",
            cpu_type == "31",
            receive_timeout,
            wait,
            flash_size,
        ),
        image,
        cpu_index,
        module,
    )


@dataclass(frozen=True)
class Phase6Node:
    target: bytes
    wake_ms: int
    diag_id: str | None = None

    def __post_init__(self):
        if not isinstance(self.target, bytes) or len(self.target) != 1:
            raise ValueError("Exact native one-byte Phase6 target required")
        if type(self.wake_ms) is not int or not 0 <= self.wake_ms <= 120000:
            raise ValueError("Native Phase6 wake time outside host bounds")
        if self.diag_id is not None and (
            type(self.diag_id) is not str or "\0" in self.diag_id
        ):
            raise ValueError("Exact current Phase6 node DiagID required")


def phase6_getter_records(
    identifiers: tuple[bytes, ...],
    nodes: tuple[Phase6Node, ...],
    node_identifier_counts: tuple[int, ...],
    previous_records: tuple[bytes, ...],
) -> tuple[bytes, ...]:
    """Reconstruct per-node getter writes and the 5a050 counted import."""
    count = len(identifiers) if type(identifiers) is tuple else -1
    if (
        type(identifiers) is not tuple
        or len(identifiers) > 34
        or any(
            type(value) is not bytes or len(value) > 33 or b"\0" in value
            for value in identifiers
        )
        or type(nodes) is not tuple
        or len(nodes) > 9
        or any(type(node) is not Phase6Node for node in nodes)
        or type(node_identifier_counts) is not tuple
        or len(node_identifier_counts) != len(nodes)
        or any(type(value) is not int or value < 0 for value in node_identifier_counts)
        or sum(node_identifier_counts) != count
        or type(previous_records) is not tuple
        or len(previous_records) > 34
        or any(
            type(record) is not bytes or len(record) != 12
            for record in previous_records
        )
    ):
        raise ValueError("Exact bounded native Phase6 getter vectors required")

    raw = list(previous_records[:count])
    raw.extend([bytes(12)] * (count - len(raw)))
    slot = 0
    for node, node_count in zip(nodes, node_identifier_counts, strict=True):
        if node_count and node.diag_id is None:
            raise ValueError("Current native node DiagID source is unavailable")
        diag_id = node.diag_id
        if node_count and diag_id is None:
            raise ValueError("Current native node DiagID source is unavailable")
        for _ in range(node_count):
            if slot >= 34:
                break
            assert diag_id is not None
            source = diag_id.encode("latin1")[:6]
            prior = raw[slot]
            string_field = bytearray(prior[4:11])
            string_field[: len(source)] = source
            string_field[len(source)] = 0
            raw[slot] = bytes(4) + string_field + prior[11:12]
            slot += 1
        if slot >= 34:
            break

    # 1005a050 copies exactly returned-ID count; stale raw tail is ignored.
    return tuple(raw)


def process_before_ig_off_on_at_retry(
    runtime: NativeRuntime2026,
    target: bytes,
) -> None:
    """Both P6 exports, prepare1fa0/flash5790: reset the selected CPU's node."""
    from scripts.programming_2026_common import Unified2026

    Unified2026(runtime).ecu_reset_phase6(target)


def get_phase6_cids(
    runtime: NativeRuntime2026,
    nodes: tuple[Phase6Node, ...],
    *,
    receive_timeout_ms: int,
    programming_started_at: float,
    initial_delay_seconds: int,
    unresolved_retry_seconds: int,
    check_dtcs: bool = False,
    engine_state: DHControllerState2026 | None = None,
) -> tuple[dict, ...]:
    """P6CIDGetter 19f0/1dbb: all nodes, timed '?' refresh and DTC fallback."""
    import math

    from scripts.programming_2026_common import CommonResponseError, Unified2026

    if (
        not isinstance(nodes, tuple)
        or len(nodes) > 9
        or any(not isinstance(n, Phase6Node) for n in nodes)
    ):
        raise ValueError("At most nine immutable native Phase6 nodes required")
    for value in (receive_timeout_ms, initial_delay_seconds, unresolved_retry_seconds):
        if type(value) is not int or not 0 <= value <= 120000:
            raise ValueError("Bounded unsigned native getter timing required")
    if (
        isinstance(programming_started_at, bool)
        or not isinstance(programming_started_at, (float, int))
        or not math.isfinite(programming_started_at)
        or programming_started_at > runtime.clock()
    ):
        raise ValueError("Finite observed programming start time required")
    if type(check_dtcs) is not bool:
        raise ValueError("Native getter DTC mode required")
    if runtime.native_cancelled is None:
        raise ValueError("Native getter cancellation observation must be bound")
    unified = Unified2026(runtime)
    results = []
    try:
        runtime.call_owned("connect", "disconnect", protocol=6)
        runtime.call("set_timeout", milliseconds=receive_timeout_ms)
        runtime.call("wait", milliseconds=max((n.wake_ms for n in nodes), default=0))
        elapsed = int(runtime.clock() - programming_started_at)
        if elapsed < initial_delay_seconds:
            runtime.call("wait", milliseconds=(initial_delay_seconds - elapsed) * 1000)
        for node in nodes:
            ids = ()
            error = None
            try:
                while True:
                    ids = ()  # Native refresh removes the preceding node's new CID rows.
                    with unified.phase6_filtered(node.target):
                        # 1760 acquires the filter, then callback12 can skip the
                        # request entirely. Outer no-ID/DTC policy still runs.
                        if runtime.native_cancellation_requested():
                            break
                        response = unified.diag.call_phase6(
                            node.target,
                            b"\x22\xf1\x88",
                            b"\x62\xf1\x88",
                            minimum=22,
                            error_code=3,
                            check_native_cancel=True,
                        )
                        try:
                            ids = decode_p6_cids(response)
                        except ValueError as exc:
                            raise CommonResponseError(3) from exc
                    if (
                        not any("?" in cid for cid in ids)
                        or int(runtime.clock() - programming_started_at)
                        >= unresolved_retry_seconds
                    ):
                        break
                    runtime.call("wait", milliseconds=500)
            except (Exception, KeyboardInterrupt) as exc:
                if not is_native_exception2026(exc):
                    raise
                try:
                    _, driver_status = native_error_fields2026(exc)
                except TypeError:
                    # 1760→1933 converts its unknown native catch to CPass9999.
                    error = CommonResponseError(9999)
                else:
                    # Outer1d2b admits only these two CJ2534 statuses to DTC
                    # fallback; other raw-driver failures are rethrown first.
                    if driver_status is not None and driver_status not in (9, 16):
                        raise
                    error = exc
            dtc = False
            if check_dtcs:
                dtc = any(
                    record[:3] in (b"\xe3\x03\x51", b"\xe3\x04\x51") and record[3] & 1
                    for record in unified.get_user_defined_dtcs(node.target)
                )
            if error is not None and not dtc:
                raise error
            if not dtc:
                ids = tuple(
                    cid
                    for cid in ids
                    if "!" in cid or not (len(cid) >= 11 and cid[10] == "#")
                )
                if not ids:
                    raise CommonResponseError(3)
            results.append(
                {
                    "target_hex": node.target.hex(),
                    "cids": ids,
                    "programming_dtc": bool(dtc),
                }
            )
        return tuple(results)
    except (Exception, KeyboardInterrupt) as error:
        _record_source_error(engine_state, error, None)
        raise
    finally:
        errors = runtime.close()
        if errors:
            active_error = sys.exception()
            if active_error is None:
                raise OSError("Native Phase6 getter cleanup failed")
            active_error.add_note("Phase6 getter cleanup failure: " + ", ".join(errors))


def native_phase6_nodes(
    container: CalibrationContainer,
    module: NativeModuleIdentity,
) -> tuple[Phase6Node, ...]:
    """Use actual2026 node metadata and verified native hexadecimal time units."""
    if (
        not isinstance(module, NativeModuleIdentity)
        or module.cuw_build != "2026"
        or module.family
        not in (
            "TCUWP6CanCIDGetter",
            "TCUWP6CanReprostdPrepareWriter",
            "TCUWP6CanReprostdFlashWriter",
        )
    ):
        raise ValueError("Exact source-identified actual2026 Phase6 module required")
    if identify_native_module(module.sha256, module.module_name) != module:
        raise ValueError("Native Phase6 identity differs from authenticated registry")
    first = native2026_metadata(container)
    try:
        count = int(first.vehicle["numberofnode"])
    except (KeyError, ValueError) as exc:
        raise ValueError("Native Phase6 node count missing or malformed") from exc
    if not 1 <= count <= 9:
        raise ValueError("Native Phase6 node count outside bounds")
    result = []
    for node in range(1, count + 1):
        metadata = native2026_metadata(container, node=node)
        text = metadata.node_values.get("diagid", "")
        if len(text) != 2 or any(c not in "0123456789abcdefABCDEF" for c in text):
            raise ValueError("Native Phase6 node diagnostic target malformed")
        result.append(Phase6Node(bytes.fromhex(text), metadata.wakeup_ms, text))
    return tuple(result)


@dataclass(frozen=True)
class Phase6PrepareContext:
    target: bytes
    wake_ms: int
    emissions_delay_ms: int
    wait_after_programming_ms: int
    pending_limit: int
    can_fd: bool
    gateway_mode: str
    service_auth_key: bytes = field(repr=False)

    def __post_init__(self):
        Phase6Node(self.target, self.wake_ms)
        if any(
            type(v) is not int or not 0 <= v <= 120000
            for v in (
                self.emissions_delay_ms,
                self.wait_after_programming_ms,
                self.pending_limit,
            )
        ):
            raise ValueError("Native Phase6 preparation timings outside host bounds")
        if (
            type(self.can_fd) is not bool
            or not isinstance(self.gateway_mode, str)
            or len(self.gateway_mode) > 2
        ):
            raise ValueError("Native Phase6 protocol/gateway metadata required")
        if (
            not isinstance(self.service_auth_key, bytes)
            or len(self.service_auth_key) != 16
        ):
            raise ValueError(
                "Imported sixteen-byte service authentication key required"
            )


def prepare_phase6(
    runtime: NativeRuntime2026,
    context: Phase6PrepareContext,
    secret_client: SecretInfoClient,
    *,
    retry: bool,
    gateway_kind: int = 0,
    state: dict | None = None,
    engine_state: DHControllerState2026 | None = None,
) -> dict:
    """Actual P6 StartPrepareWrite, with successful periodic ownership retained.

    The same runtime continues into flashing. On failure every acquired resource
    is compensated; on success only the diagnostic filter is released, matching
    native preparation's still-running tester-present lifecycle.
    """
    from scripts.programming_2026_common import (
        Unified2026,
        security_up_key,
    )

    if (
        not isinstance(context, Phase6PrepareContext)
        or type(retry) is not bool
        or not isinstance(secret_client, SecretInfoClient)
    ):
        raise ValueError("Frozen native Phase6 preparation context/retry required")
    if type(gateway_kind) is not int or not 0 <= gateway_kind <= 255:
        raise ValueError("Native cached gateway byte required")
    if (
        engine_state is not None
        and gateway_kind != engine_state.engine.repro_gateway_node
    ):
        raise ValueError("P6 gateway observation differs from actual engine state")
    unified = Unified2026(runtime)
    periodic = False
    identifier = None
    state = {} if state is None else state
    if state.get("stage"):
        raise ValueError("Native P6 preparation state cannot be reused")
    state.update(
        stage="wake", gateway_kind=gateway_kind, complete=False, periodic_owned=False
    )

    def wait(milliseconds):
        runtime.call("wait", milliseconds=milliseconds)

    def broadcast(payload, *, functional=False):
        if functional:
            unified.diag.write(b"\x18\xdb\xef\xe0" + payload, 0x100)
        unified.diag.write(b"\0\0\x07\x77" + payload)
        unified.diag.write(b"\0\0\x07\x7f\xfe" + payload, 0x80)

    def stop_periodic():
        nonlocal periodic
        if periodic:
            runtime.release("stop_sync_periodic")
            periodic = False

    def start_periodic(delay):
        nonlocal periodic
        frames = (
            (b"\x18\xdb\xef\xe0\x3e\x80", 0x100),
            (b"\0\0\x07\x77\x3e\x80", 0),
            (b"\0\0\x07\x7f\xfe\x3e\x80", 0x80),
        )
        runtime.call_owned(
            "start_sync_periodic",
            "stop_sync_periodic",
            frames=frames,
            interval_ms=2000,
            retry_ms=100,
            count=3,
            delay_ms=delay,
        )
        periodic = True

    try:
        runtime.call("set_local_time_to_previous_send_time")
        wait(context.wake_ms)
        unified.stop_ota_reprogramming()
        if context.gateway_mode == "00" and gateway_kind == 0:
            gateway_kind = unified.judge_repro_gateway_node(1)
            state["gateway_kind"] = gateway_kind
            if engine_state is not None:
                engine_state.engine.set_repro_gateway_node(gateway_kind)
        state["stage"] = "extended_broadcast"
        broadcast(b"\x10\x83", functional=True)
        wait(1000)
        start_periodic(1000)
        unified.cancel_automatic_ig_off(retry, context.target)
        if gateway_kind == 1:
            unified.collate_seed_key_phase5_gateway()
            unified.routine_phase5_gateway(0)
            wait(1500)
            unified.routine_phase5_gateway(1)
        stop_periodic()
        state["stage"] = "dtc_broadcast"
        broadcast(b"\x85\x82")
        wait(1000)
        start_periodic(1000)
        if gateway_kind == 1:
            unified.routine_phase5_gateway(2)
            wait(1500)
            unified.routine_phase5_gateway(3)
        stop_periodic()
        state["stage"] = "communication_broadcast"
        # Native functional payload83 differs from the first physical payload81.
        unified.diag.write(b"\x18\xdb\xef\xe0\x28\x83\x01", 0x100)
        broadcast(b"\x28\x81\x01")
        wait(context.emissions_delay_ms)
        broadcast(b"\x28\x83\x01")
        wait(context.emissions_delay_ms)
        start_periodic(1000)
        request, response = unified.diag.phase6_addresses(context.target)
        identifier = unified.diag.start_filter(request, response)
        try:
            state["stage"] = "programming_session"
            unified.diag.call_phase6(
                context.target,
                b"\x10\x02",
                b"\x50\x02",
                minimum=6,
                error_code=0x29,
                pending_limit=context.pending_limit,
            )
            stop_periodic()
            start_periodic(0)
            wait(context.wait_after_programming_ms)
            state["stage"] = "security_seed"
            tx_flags = 0x100 | (0x180000 if context.can_fd else 0)
            seed = unified.diag.call(
                request,
                response,
                b"\x27\x01",
                b"\x67\x01",
                minimum=18,
                error_code=0x10,
                phase5=True,
                pending_limit=context.pending_limit,
                busy_limit=0x159A,
                tx_flags=tx_flags,
            )[2:18]
            state["stage"] = "security_key"
            key = security_up_key(
                runtime, secret_client, seed, context.service_auth_key
            )
            try:
                unified.diag.call(
                    request,
                    response,
                    b"\x27\x02" + key,
                    b"\x67\x02",
                    minimum=2,
                    error_code=0x11,
                    phase5=True,
                    pending_limit=context.pending_limit,
                    busy_limit=0x159A,
                    tx_flags=tx_flags,
                )
            except CommonResponseError as error:
                if error.response == b"\x7f\x27\x35":
                    raise CommonResponseError(0x3EA, error.response) from error
                raise
        except (Exception, KeyboardInterrupt) as error:
            _record_source_error(engine_state, error, 1)
            raise
        finally:
            active_error = sys.exception()
            try:
                runtime.release("stop_filter", identifier=identifier)
            except (Exception, KeyboardInterrupt) as cleanup_error:
                if is_native_exception2026(cleanup_error):
                    state["native_suppressed_cleanup_errors"] = [
                        type(cleanup_error).__name__
                    ]
                elif active_error is not None:
                    active_error.add_note(
                        "Filter cleanup failure: " + type(cleanup_error).__name__
                    )
                else:
                    raise
        state["stage"] = "prepared"
        state["complete"] = True
        state["periodic_owned"] = True
        return state
    except (Exception, KeyboardInterrupt) as error:
        _record_source_error(engine_state, error, 1)
        releases = []
        if (
            identifier is not None
            and not state.get("native_suppressed_cleanup_errors")
            and runtime.owns_resource("stop_filter", identifier=identifier)
        ):
            releases.append(("stop_filter", {"identifier": identifier}))
        if periodic and runtime.owns_resource("stop_sync_periodic"):
            releases.append(("stop_sync_periodic", {}))
        for operation, values in releases:
            try:
                runtime.release(operation, **values)
            except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001 - retain initiating error and attempt both resources
                error.add_note(
                    "Prepare cleanup failure: " + type(cleanup_error).__name__
                )
        raise


class Phase6FlashChannel:
    """Recovered P6 flash wire helpers; this does not implement StartFlashWrite.

    Logical software selection, CPU associations and finalization remain owned by
    the complete export state machine, never delegated to a success callback.
    """

    def __init__(
        self,
        runtime: NativeRuntime2026,
        target: bytes,
        *,
        pending_limit: int,
        can_fd: bool,
    ):
        from scripts.programming_2026_common import Unified2026

        Phase6Node(target, 0)
        if (
            type(pending_limit) is not int
            or not 0 <= pending_limit <= 120000
            or type(can_fd) is not bool
        ):
            raise ValueError("Native P6 flash pending time/protocol required")
        self.runtime = runtime
        self.diag = Unified2026(runtime).diag
        self.request, self.response = self.diag.phase6_addresses(target)
        self.pending_limit = pending_limit
        self.tx_flags = 0x100 | (0x180000 if can_fd else 0)
        self.transferred = 0

    def call(
        self,
        payload: bytes,
        expected: bytes,
        minimum: int,
        error_code: int,
        pending_limit: int | None = None,
    ):
        return self.diag.call(
            self.request,
            self.response,
            payload,
            expected,
            minimum=minimum,
            error_code=error_code,
            phase5=True,
            pending_limit=self.pending_limit
            if pending_limit is None
            else pending_limit,
            busy_limit=0x159A,
            tx_flags=self.tx_flags,
        )

    @staticmethod
    def geometry(address: int, length: int) -> bytes:
        if (
            type(address) is not int
            or type(length) is not int
            or not 0 <= address <= 0xFFFFFFFF
            or not 0 < length <= 0xFFFFFFFF
            or address + length > 2**32
        ):
            raise ValueError("Native imported four-byte address/length required")
        return address.to_bytes(4, "big") + length.to_bytes(4, "big")

    def routine(
        self,
        mode: int,
        *,
        signature: bytes | None = None,
        address: int | None = None,
        length: int | None = None,
    ):
        """Flash2d20: DD00 authenticate, FF00 erase, DD01 verify, DD02 end."""
        if type(mode) is not int or mode not in range(4):
            raise ValueError("Native P6 routine mode0..3 required")
        rid = (b"\xdd\x00", b"\xff\x00", b"\xdd\x01", b"\xdd\x02")[mode]
        payload = b"\x31\x01" + rid
        expected = b"\x71\x01" + rid
        if mode in (0, 2):
            if (
                not isinstance(signature, bytes)
                or len(signature) not in (64, 384)
                or address is not None
                or length is not None
            ):
                raise ValueError("Native64/384-byte signature required")
            payload += b"\x01" + len(signature).to_bytes(2, "big") + signature
            expected += b"\x02\x02\0"
        elif mode == 1:
            if signature is not None or address is None or length is None:
                raise ValueError("Native erase geometry required")
            payload += b"\x44" + self.geometry(address, length)
        else:
            if signature is not None or address is not None or length is not None:
                raise ValueError("End routine has no metadata payload")
            expected += b"\x02\x02"
        return self.call(
            payload,
            expected,
            len(expected),
            (0x56, 0x45, 0x4D, 0x46)[mode],
            180 if mode == 3 else None,
        )

    def transfer(
        self,
        address: int,
        data: bytes,
        *,
        data_format: int = 1,
        download_length: int | None = None,
        acknowledged: Callable[[int], None] | None = None,
        stream: Phase6Transfer | None = None,
    ) -> int:
        """Flash2a20/3ff0/4370/2c50: download, bounded blocks, timeout restore, exit."""
        from scripts.programming import reprostd_block_size

        if not isinstance(data, bytes) or not 0 < len(data) <= 64 * 1024 * 1024:
            raise ValueError("Bounded imported P6 transfer data required")
        if type(data_format) is not int or data_format not in (1, 0x11, 0x21):
            raise ValueError("Native raw/compression/delta data format required")
        if stream is not None:
            if (
                not isinstance(stream, Phase6Transfer)
                or stream.source is None
                or stream.data != data
                or stream.address != address
                or stream.data_format != data_format
                or stream.download_length != download_length
            ):
                raise ValueError(
                    "Source-bound matching native P6 stream transfer required"
                )
            stream.validate_stream()
        geometry = self.geometry(
            address, len(data) if download_length is None else download_length
        )
        old = self.runtime.call("get_send_timeout")
        if type(old) is not int or not 0 <= old <= 0xFFFFFFFF:
            raise ValueError("Native send timeout required")
        response = self.call(
            bytes((0x34, data_format, 0x44)) + geometry, b"\x74", 3, 0x1A
        )
        # Independently reconciled Flash2a20 uses the same bounded numeric codec.
        try:
            block_size = reprostd_block_size(response)
        except ValueError as error:
            from scripts.programming_2026_common import CommonResponseError

            raise CommonResponseError(0x1A, response) from error
        before = self.transferred
        try:
            self.runtime.call(
                "set_send_timeout", milliseconds=((block_size + 8) // 7) * 161 + 1000
            )
            blocks = (
                (
                    (sequence & 255, data[offset : offset + block_size])
                    for sequence, offset in enumerate(
                        range(0, len(data), block_size), 1
                    )
                )
                if stream is None
                else stream.stream_blocks(block_size, self.runtime)
            )
            for counter, block in blocks:
                self.call(
                    bytes((0x36, counter)) + block, bytes((0x76, counter)), 2, 0x22
                )
                self.transferred += len(block)
                if acknowledged is not None:
                    acknowledged(len(block))
        finally:
            self.runtime.call("set_send_timeout", cleanup=True, milliseconds=old)
        self.call(b"\x37", b"\x77", 1, 0x1C)
        return self.transferred - before

    def write_programming_information(
        self, subtype: int, tester_id: bytes, system_date, device_information: bytes
    ):
        """Flash4490/initializer1000: F120..F13F and F050 native write DIDs."""
        from datetime import date

        if type(subtype) is not int or not 1 <= subtype <= 32:
            raise ValueError("Source-resolved P6 software subtype1..32 required")
        if (
            not isinstance(tester_id, bytes)
            or len(tester_id) > 17
            or not isinstance(system_date, date)
        ):
            raise ValueError(
                "Native bounded tester bytes and observed UTC date required"
            )
        if not isinstance(device_information, bytes) or len(device_information) != 16:
            raise ValueError("Imported native sixteen-byte device information required")
        # Native formats decimal text then parses it as hex, producing BCD dates.
        encoded_date = bytes.fromhex(
            f"{system_date.year:04d}{system_date.month:02d}{system_date.day:02d}"
        )
        did = (0xF11F + subtype).to_bytes(2, "big")
        self.call(
            b"\x2e" + did + b"GTS" + tester_id.ljust(17, b"\0") + encoded_date,
            b"\x6e" + did,
            3,
            0x55,
        )
        self.call(b"\x2e\xf0\x50" + device_information, b"\x6e\xf0\x50", 3, 0x47)


def native_phase6_prepare_context(
    container: CalibrationContainer,
    module: NativeModuleIdentity,
    *,
    node: int,
    metadata: Native2026Metadata | None = None,
) -> Phase6PrepareContext:
    """Bind P6 preparation fields; native pending timeout uses first logical block."""
    if (
        not isinstance(module, NativeModuleIdentity)
        or module.family != "TCUWP6CanReprostdPrepareWriter"
        or module.cuw_build != "2026"
        or identify_native_module(module.sha256, module.module_name) != module
    ):
        raise ValueError("Exact actual2026 P6 prepare module required")
    metadata = (
        native2026_metadata(container, node=node) if metadata is None else metadata
    )
    native2026_validate_runtime_metadata(metadata)
    if metadata.source_sha256 != container.digest or metadata.node != node:
        raise ValueError("P6 preparation metadata differs from its actual source")
    target = metadata.node_values.get("diagid", "")
    if len(target) != 2 or any(c not in "0123456789abcdefABCDEF" for c in target):
        raise ValueError("Native Phase6 node diagnostic target malformed")
    if not metadata.logical_blocks:
        raise ValueError("Native Phase6 preparation requires logical software metadata")
    block = metadata.logical_blocks[0]
    values = metadata.sections[f"logicalblock{node}{block.slot:02}"]
    pending = values.get("p4servermaxtime", "03")
    if len(pending) > 8 or any(c not in "0123456789abcdefABCDEF" for c in pending):
        raise ValueError("Native logical P4ServerMaxTime malformed")
    gateways = metadata.gateway_values
    if not gateways:
        raise ValueError(
            "Native P6 preparation requires its first gateway metadata row"
        )
    return Phase6PrepareContext(
        bytes.fromhex(target),
        metadata.wakeup_ms,
        metadata.emissions_delay_ms,
        metadata.wait_after_programming_ms,
        block.routine_response_pending_limit,
        metadata.protocol_at_node == "02",
        gateways[0]["gatewaymode"],
        metadata.service_auth_key_bytes,
    )


@dataclass(frozen=True)
class Phase6Transfer:
    address: int
    download_length: int
    transfer_length: int
    data: bytes = field(repr=False)
    data_format: int = 1
    source: LargeSource2026 | None = field(default=None, repr=False)
    backing: LargeMaterialization2026 | None = field(default=None, repr=False)

    def __post_init__(self):
        Phase6FlashChannel.geometry(self.address, self.download_length)
        if (
            type(self.transfer_length) is not int
            or not 0 < self.transfer_length <= 0xFFFFFFFF
        ):
            raise ValueError("Imported native P6 TransferLength required")
        if (
            not isinstance(self.data, bytes)
            or not 0 < len(self.data) <= 64 * 1024 * 1024
        ):
            raise ValueError("Materialized native P6 transfer bytes required")
        if type(self.data_format) is not int or self.data_format not in (1, 0x11, 0x21):
            raise ValueError("Native P6 transfer format required")
        if self.source is not None or self.backing is not None:
            self.validate_stream()

    def validate_stream(self):
        if not isinstance(self.source, LargeSource2026) or not isinstance(
            self.backing, LargeMaterialization2026
        ):
            raise TypeError("Authenticated native P6 stream backing required")
        validate_large_materialization_2026(self.source.container, self.backing)
        if self.data != self.backing.descriptor:
            raise ValueError(
                "Native P6 descriptor differs from source-bound materialization"
            )

    @property
    def native_length(self) -> int:
        return len(self.data) if self.backing is None else self.backing.record.length

    @property
    def payload_target_length(self) -> int:
        return (
            self.transfer_length
            if self.backing is not None and not self.backing.binary
            else self.native_length
        )

    def stream_blocks(self, block_size: int, runtime: NativeRuntime2026):
        import struct

        self.validate_stream()
        assert self.source is not None and self.backing is not None
        descriptor = self.backing.descriptor
        end = struct.unpack_from("<I", descriptor, 0x10C)[0]
        if self.backing.binary:
            start = struct.unpack_from("<I", descriptor, 0x114)[0]
            for sequence, payload in enumerate(
                phase6_binary_stream_blocks(
                    self.source,
                    start,
                    end,
                    self.native_length,
                    block_size,
                    runtime=runtime,
                ),
                1,
            ):
                yield sequence & 255, payload
        else:
            groups = tuple(
                struct.unpack_from("<II", descriptor, offset)
                for offset in (0x110, 0x11C, 0x128, 0x130)
            )
            yield from phase6_srecord_stream_blocks(
                Phase6SRecordStream(self.source, end, groups),
                self.address,
                self.transfer_length,
                block_size,
                runtime=runtime,
            )


@dataclass(frozen=True)
class Phase6LogicalWrite:
    cpu_index: int
    pending_limit: int
    subtype: int
    device_information: bytes = field(repr=False)
    routine: Phase6Transfer
    authentication: bytes = field(repr=False)
    erase: tuple[int, int] | None
    contents: tuple[Phase6Transfer, ...] = field(repr=False)
    verification: bytes = field(repr=False)
    method_type: int = 1

    def __post_init__(self):
        if type(self.method_type) is not int or self.method_type not in (1, 2, 3):
            raise ValueError("Native logical reprogramming method type1/2/3 required")
        if type(self.cpu_index) is not int or not 0 <= self.cpu_index < 4096:
            raise ValueError("Native CPU association required")
        if type(self.pending_limit) is not int or not 0 <= self.pending_limit <= 120000:
            raise ValueError("Bounded native P6 pending limit required")
        if type(self.subtype) is not int or not 1 <= self.subtype <= 32:
            raise ValueError("Native logical software subtype required")
        if (
            not isinstance(self.device_information, bytes)
            or len(self.device_information) != 16
        ):
            raise ValueError("Native logical nonce required")
        if any(
            not isinstance(s, bytes) or len(s) not in (64, 384)
            for s in (self.authentication, self.verification)
        ):
            raise ValueError("Native logical CheckData64/384 required")
        if self.erase is not None:
            Phase6FlashChannel.geometry(*self.erase)
        if (
            not isinstance(self.routine, Phase6Transfer)
            or not self.contents
            or len(self.contents) > 3
            or any(not isinstance(t, Phase6Transfer) for t in self.contents)
        ):
            raise ValueError("Native logical routine and content transfers required")


@dataclass(frozen=True)
class Phase6FlashPlan:
    target: bytes
    can_fd: bool
    wake_ms: int
    blocks: tuple[Phase6LogicalWrite, ...] = field(repr=False)
    cpu_flash_sizes: tuple[tuple[int, int], ...]
    module: NativeModuleIdentity

    def __post_init__(self):
        Phase6Node(self.target, self.wake_ms)
        if (
            type(self.can_fd) is not bool
            or not self.blocks
            or any(not isinstance(b, Phase6LogicalWrite) for b in self.blocks)
        ):
            raise ValueError("Frozen native P6 logical block plan required")
        module = self.module
        if (
            not isinstance(module, NativeModuleIdentity)
            or module.family != "TCUWP6CanReprostdFlashWriter"
            or module.cuw_build != "2026"
            or identify_native_module(module.sha256, module.module_name) != module
        ):
            raise ValueError("Exact actual2026 P6 flash module required")
        sizes = dict(self.cpu_flash_sizes)
        if (
            len(sizes) != len(self.cpu_flash_sizes)
            or set(sizes) != {b.cpu_index for b in self.blocks}
            or any(
                type(v) is not int or not 0 <= v <= 0xFFFFFFFF for v in sizes.values()
            )
        ):
            raise ValueError("Imported per-CPU native FlashSize required")
        for cpu in sizes:
            blocks = tuple(block for block in self.blocks if block.cpu_index == cpu)
            total = sum(
                block.routine.transfer_length
                + sum(
                    transfer.transfer_length
                    if block.method_type == 1
                    else transfer.native_length
                    for transfer in block.contents
                )
                for block in blocks
            )
            written = sum(
                transfer.payload_target_length
                for block in blocks
                for transfer in (block.routine, *block.contents)
            )
            if not 0 < total <= 0xFFFFFFFF or written > 0xFFFFFFFF:
                raise ValueError(
                    "Native P6 uint32 CPU progress or transfer sum overflows"
                )


def native_phase6_flash_plan(
    container: CalibrationContainer | NativeLargeContainer2026,
    module: NativeModuleIdentity,
    *,
    node: int,
    metadata: Native2026Metadata | None = None,
) -> Phase6FlashPlan:
    """1f60/3ff0: bind native logical areas and archive aliases before any I/O.

    Ordinary archives and authenticated large-file descriptors come from their
    actual CUW2026 producers; no archive flag or source span is synthesized.
    """
    from scripts.calibration_2026 import (
        native2026_logical_archive,
        native2026_logical_cpu_flash_size,
    )
    from scripts.programming_2026_common import make_send_data_records

    if (
        not isinstance(module, NativeModuleIdentity)
        or module.family != "TCUWP6CanReprostdFlashWriter"
        or module.cuw_build != "2026"
        or identify_native_module(module.sha256, module.module_name) != module
    ):
        raise ValueError("Exact actual2026 P6 flash module required")
    metadata = (
        native2026_metadata(container, node=node) if metadata is None else metadata
    )
    native2026_validate_runtime_metadata(metadata)
    if metadata.source_sha256 != container.digest or metadata.node != node:
        raise ValueError("P6 writer metadata differs from its actual source")
    target = metadata.node_values.get("diagid", "")
    if len(target) != 2 or any(c not in "0123456789abcdefABCDEF" for c in target):
        raise ValueError("Native Phase6 node diagnostic target malformed")
    writes = []
    for block in metadata.logical_blocks:
        areas = {area.kind: area for area in block.areas}

        def area(kind, areas=areas):
            if kind not in areas:
                raise ValueError("Required native P6 logical area missing: " + kind)
            return areas[kind]

        def signature(kind, area=area):
            value = area(kind).check_data
            if len(value) not in (64, 384):
                raise ValueError("Native P6 CheckData64/384 missing or malformed")
            return value

        def transfer(kind, archive_kind, data_format, area=area, block=block):
            geometry = area(kind)
            archive = native2026_logical_archive(metadata, block, archive_kind)
            transfer_length = geometry.transfer_length
            if transfer_length <= 0:
                raise ValueError("Native P6 positive TransferLength required")
            if archive.kind_records:
                data = make_send_data_records(
                    archive.kind_records, geometry.address, transfer_length
                )
            else:
                data = archive.data
            if data is None:
                raise ValueError("Native P6 archive has no supported materialized data")
            return Phase6Transfer(
                geometry.address,
                geometry.length,
                transfer_length,
                data,
                data_format,
                LargeSource2026(metadata.source_container)
                if archive.streamed
                else None,
                archive.backing if archive.streamed else None,
            )

        routine = transfer(
            "EraseAndReproRoutine",
            "ReproData" if block.repro_method == "00" else "EraseAndReproRoutine",
            1,
        )
        if block.repro_method_type == 1:
            contents = []
            for kind in ("ReproData", "ReproDataSegment02", "ReproDataSegment03"):
                if kind not in areas:
                    break
                contents.append(transfer(kind, "ReproData", 1))
            verification_kind = "ReproData"
        else:
            contents = [
                transfer(
                    "DeltaOrCompressionReproData",
                    "DeltaOrCompressionReproData",
                    0x21
                    if block.repro_method == "03"
                    else 0x11
                    if block.repro_method == "02"
                    else 1,
                )
            ]
            verification_kind = "DeltaOrCompressionReproData"
        erase = (
            None
            if block.repro_method_type == 2
            else (area("EraseMemory").address, area("EraseMemory").length)
        )
        writes.append(
            Phase6LogicalWrite(
                block.cpu_index,
                block.routine_response_pending_limit,
                block.did_subtype,
                block.device_info,
                routine,
                signature("EraseAndReproRoutine"),
                erase,
                tuple(contents),
                signature(verification_kind),
                block.repro_method_type,
            )
        )
    sizes = tuple(
        (cpu, native2026_logical_cpu_flash_size(metadata, cpu))
        for cpu in sorted({b.cpu_index for b in writes})
    )
    return Phase6FlashPlan(
        bytes.fromhex(target),
        metadata.protocol_at_node == "02",
        metadata.wakeup_ms,
        tuple(writes),
        sizes,
        module,
    )


def flash_phase6(
    runtime: NativeRuntime2026,
    plan: Phase6FlashPlan,
    *,
    tester_id: bytes,
    system_date,
    state: dict | None = None,
    notification: NotificationBool | None = None,
    engine_state: DHControllerState2026 | None = None,
) -> dict:
    """5840→1f60 archive/stream state machine over an existing prepared runtime."""
    from scripts.programming_2026_common import Unified2026

    if not isinstance(plan, Phase6FlashPlan):
        raise TypeError("Frozen source-identified native P6 flash plan required")
    if notification is not None and type(notification) is not NotificationBool:
        raise TypeError("Concrete source-bound native notification required")
    if engine_state is not None and type(engine_state) is not DHControllerState2026:
        raise TypeError("Engine-issued native programming state required")
    boundary_worker = None
    if len(plan.cpu_flash_sizes) != 1:
        if engine_state is None:
            raise ValueError("Multi-CPU P6 requires the actual active engine worker")
        engine = engine_state.engine
        engine._require_owned_phase()
        boundary_worker = engine.worker
        if boundary_worker.runtime is not runtime or tuple(
            block.cpu_index for block in engine_state.metadata.logical_blocks
        ) != tuple(block.cpu_index for block in plan.blocks):
            raise ValueError("P6 CPU boundaries differ from the active native source")
    for block in plan.blocks:
        for transfer in (block.routine, *block.contents):
            if transfer.source is not None:
                transfer.validate_stream()
    # Validate caller observations before acquiring a filter or issuing a frame.
    from datetime import date

    if (
        not isinstance(tester_id, bytes)
        or len(tester_id) > 17
        or not isinstance(system_date, date)
    ):
        raise ValueError("Native tester bytes and observed UTC date required")
    state = {} if state is None else state
    if state.get("stage"):
        raise ValueError("Native P6 flash state cannot be reused")
    native_cpu_indices = {
        cpu: cpu
        if engine_state is not None
        and engine_state.metadata.runtime_projection is not None
        else boundary_worker.native_index_for_source_cpu(cpu)
        if boundary_worker is not None
        else engine_state.native_cpu_index
        if engine_state is not None
        else cpu
        for cpu, _ in plan.cpu_flash_sizes
    }
    state.update(
        stage="filter",
        complete=False,
        notification=False if notification is None else bool(notification),
        retry_required=False
        if engine_state is None
        else engine_state.native_context_964,
        transferred=0,
        counts={
            cpu: 0
            if engine_state is None
            else engine_state.transferred_bytes[native_cpu_indices[cpu]]
            for cpu, _ in plan.cpu_flash_sizes
        },
        percentages={
            cpu: 0
            if engine_state is None
            else engine_state.progress[native_cpu_indices[cpu]]
            for cpu, _ in plan.cpu_flash_sizes
        },
    )
    totals = {
        cpu: sum(
            b.routine.transfer_length
            + sum(
                t.transfer_length if b.method_type == 1 else t.native_length
                for t in b.contents
            )
            for b in plan.blocks
            if b.cpu_index == cpu
        )
        for cpu, _ in plan.cpu_flash_sizes
    }
    written = dict.fromkeys(totals, 0)
    sizes = dict(plan.cpu_flash_sizes)
    baseline = plan.blocks[0].routine.transfer_length
    unified = Unified2026(runtime)
    request, response = unified.diag.phase6_addresses(plan.target)
    identifier = None

    def notify(field):
        runtime.call("notify", field=field, value=state[field])

    def stop_periodic():
        if runtime.owns_resource("stop_sync_periodic"):
            runtime.release("stop_sync_periodic")
        else:
            runtime.call("stop_sync_periodic")

    try:
        identifier = unified.diag.start_filter(request, response)
        for ordinal, block in enumerate(plan.blocks):
            state["logical_block"] = ordinal
            if engine_state is not None:
                engine_state.engine.set_logical_block_index(ordinal)
            state["cpu_index"] = block.cpu_index
            state["stage"] = "programming_information"
            channel = Phase6FlashChannel(
                runtime,
                plan.target,
                pending_limit=block.pending_limit,
                can_fd=plan.can_fd,
            )
            channel.write_programming_information(
                block.subtype, tester_id, system_date, block.device_information
            )

            def acknowledged(size, block=block, ordinal=ordinal):
                written[block.cpu_index] += size
                state["transferred"] += size
                if ordinal != 0 or written[block.cpu_index] > baseline:
                    total = totals[block.cpu_index]
                    state["counts"][block.cpu_index] = int(
                        written[block.cpu_index] / total * sizes[block.cpu_index]
                    )
                    if engine_state is not None:
                        engine_state.set_native_count(
                            native_cpu_indices[block.cpu_index],
                            state["counts"][block.cpu_index],
                        )
                    notify("counts")
                    denominator = total if ordinal else total - baseline
                    if denominator <= 0:
                        raise ValueError(
                            "Native P6 progress denominator is not positive"
                        )
                    state["percentages"][block.cpu_index] = int(
                        (written[block.cpu_index] - (baseline if ordinal == 0 else 0))
                        / denominator
                        * 100
                    )
                    if engine_state is not None:
                        engine_state.set_native_percentage(
                            native_cpu_indices[block.cpu_index],
                            state["percentages"][block.cpu_index],
                        )
                    notify("percentages")

            def send(transfer: Phase6Transfer) -> None:
                channel.transfer(  # noqa: B023 - called synchronously within this block
                    transfer.address,
                    transfer.data,
                    data_format=transfer.data_format,
                    download_length=transfer.download_length,
                    acknowledged=acknowledged,
                    stream=transfer if transfer.source is not None else None,
                )

            state["stage"] = "routine_download"
            send(block.routine)
            state["stage"] = "authenticate"
            channel.routine(0, signature=block.authentication)
            state["notification"] = True
            if notification is None:
                notify("notification")
            else:
                notification.assign(True)
            if block.erase is not None:
                state["stage"] = "erase"
                channel.routine(1, address=block.erase[0], length=block.erase[1])
            state["stage"] = "content_download"
            for transfer in block.contents:
                send(transfer)
            state["stage"] = "verify"
            channel.routine(2, signature=block.verification)
            if ordinal + 1 < len(plan.blocks):
                next_cpu = plan.blocks[ordinal + 1].cpu_index
                if block.cpu_index != next_cpu:
                    assert boundary_worker is not None
                    state["stage"] = "cpu_boundary"
                    # 272a callback1 blocks until the host updates the same export.
                    assert engine_state is not None
                    engine_state.engine.notify_logical_cpu_boundary(next_cpu)
        state["stage"] = "end"
        channel.routine(3)
        state["stage"] = "reset"
        channel.call(b"\x11\x01", b"\x51\x01", 2, 0x18, 180)
        runtime.call("wait", milliseconds=plan.wake_ms)
        stop_periodic()
        state["stage"] = "default_broadcast"
        unified.diag.write(b"\x18\xdb\xef\xe0\x10\x81", 0x100)
        unified.diag.write(b"\0\0\x07\x77\x10\x81")
        unified.diag.write(b"\0\0\x07\x7f\xfe\x10\x81", 0x80)
        state["notification"] = False
        if notification is None:
            notify("notification")
        else:
            notification.assign(False)
        state["stage"] = "filter_cleanup"
        try:
            runtime.release("stop_filter", identifier=identifier)
        except (Exception, KeyboardInterrupt) as cleanup_error:
            if not is_native_exception2026(cleanup_error):
                raise
            state["native_suppressed_cleanup_errors"] = [type(cleanup_error).__name__]
        state["stage"] = "complete"
        state["complete"] = True
        return state
    except (Exception, KeyboardInterrupt) as error:
        state["complete"] = False
        cleanup_errors = []
        _record_source_error(engine_state, error, None)
        if identifier is not None and runtime.owns_resource(
            "stop_filter", identifier=identifier
        ):
            try:
                runtime.release("stop_filter", identifier=identifier)
            except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001 - preserve the initiating native/host failure
                cleanup_errors.append(type(cleanup_error).__name__)
                error.add_note(
                    "Filter cleanup failure: " + type(cleanup_error).__name__
                )
        try:
            native_error_fields2026(error)
        except TypeError:
            typed_transfer_error = False
        else:
            typed_transfer_error = True
        if typed_transfer_error:
            # Native2931 clears every CPU row in this node before the two callbacks.
            for cpu in state["counts"]:
                state["counts"][cpu] = 0
                state["percentages"][cpu] = 0
                if engine_state is not None:
                    engine_state.set_native_count(native_cpu_indices[cpu], 0)
                    engine_state.set_native_percentage(native_cpu_indices[cpu], 0)
            if not state["notification"]:
                state["retry_required"] = True
            state["error_result"] = 2 if state["notification"] else 1
            try:
                notify("counts")
                notify("percentages")
            except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001 - preserve initiating error
                cleanup_errors.append(type(cleanup_error).__name__)
                error.add_note(
                    "Progress cleanup failure: " + type(cleanup_error).__name__
                )
        try:
            if runtime.owns_resource("stop_sync_periodic"):
                runtime.release("stop_sync_periodic")
            else:
                runtime.call("stop_sync_periodic", cleanup=True)
        except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001 - preserve initiating error
            cleanup_errors.append(type(cleanup_error).__name__)
            error.add_note("Periodic cleanup failure: " + type(cleanup_error).__name__)
        if typed_transfer_error and engine_state is not None:
            engine_state.record_native_error(
                state["error_result"], engine_state.primary_error
            )
            if state["error_result"] == 1:
                engine_state.mark_native_retry()
        state["cleanup_errors"] = cleanup_errors
        raise


@dataclass(frozen=True)
class Phase6SRecordWindow:
    status: int
    consumed: int = 0
    address: int | None = None
    payload: bytes = field(default=b"", repr=False)


def parse_phase6_srecord_window(data: bytes) -> Phase6SRecordWindow:
    """Flash1980 mode1: one streaming record, native0/1/2 window statuses.

    Status1 requires the caller to refill/look ahead even when a complete record
    ends exactly at this window. No address is assigned on that native branch.
    """

    if not isinstance(data, bytes) or len(data) > 0x500001:
        raise ValueError("Bounded native P6 S-record window required")
    if len(data) < 2:
        return Phase6SRecordWindow(2)
    kind = data[1] - ord("0")
    widths = {0: 2, 1: 2, 2: 3, 3: 4, 5: 2, 7: 4, 8: 3, 9: 2}
    if data[0] != ord("S") or kind not in widths:
        raise CommonResponseError(0x3F6)
    if len(data) < 4:
        return Phase6SRecordWindow(2)

    def decode(raw):
        if any(c not in b"0123456789abcdefABCDEF" for c in raw):
            raise CommonResponseError(0x3F7)
        return bytes.fromhex(raw.decode("ascii"))

    count = decode(data[2:4])[0]
    width = widths[kind]
    if count < width + 1:
        raise CommonResponseError(0x3F6)
    end = 4 + 2 * count
    if len(data) < end:
        return Phase6SRecordWindow(2)
    raw = decode(data[2:end])
    if sum(raw) & 255 != 255:
        raise CommonResponseError(0x3F6)
    if kind in (7, 8, 9) and count != width + 1:
        raise CommonResponseError(0x3F6)
    if kind == 5:
        if data[3] not in b"345":
            raise CommonResponseError(0x3F6)
        width = data[3] - ord("0") - 1
    payload = raw[1 + width : -1] if kind in (1, 2, 3) else b""
    consumed = end
    if len(data) == consumed:
        return Phase6SRecordWindow(1, consumed, payload=payload)
    if data[consumed] in b"\r\n":
        consumed += 1
        if len(data) == consumed:
            return Phase6SRecordWindow(1, consumed, payload=payload)
        if data[consumed] in b"\r\n":
            consumed += 1
    address = int.from_bytes(raw[1 : 1 + width], "big")
    return Phase6SRecordWindow(0, consumed, address, payload)


def phase6_binary_stream_blocks(
    source: bytes | LargeSource2026,
    start: int,
    end: int,
    transfer_length: int,
    block_size: int,
    *,
    runtime: NativeRuntime2026 | None = None,
):
    """Flash3280 byte-source equivalent of5-MiB reads and native zero padding.

    The source-bound large-file descriptor producer must supply the inclusive
    offsets. This helper does not manufacture such a descriptor from a filename.
    """

    if (
        not isinstance(source, (bytes, LargeSource2026))
        or not 0 < len(source) <= 0xFFFFFFFF
    ):
        raise ValueError("Bounded authorized native source bytes required")
    if (
        any(type(v) is not int for v in (start, end, transfer_length, block_size))
        or not 0 <= start <= end < len(source)
        or not 0 < transfer_length <= 0xFFFFFFFF
        or not 1 <= block_size <= 4093
    ):
        raise ValueError(
            "Native bounded inclusive span and negotiated block length required"
        )
    cursor, written = start, 0
    while cursor <= end and written < transfer_length:
        if runtime is not None:
            runtime.check()
        count = min(0x500000, end - cursor + 1)
        window = source[cursor : cursor + count]
        full = count // block_size
        if full:
            for offset in range(0, full * block_size, block_size):
                block = window[offset : offset + block_size]
                yield block
                written += len(block)
            cursor += full * block_size
        else:
            size = count
            if written + count < transfer_length:
                size = min(transfer_length - written, block_size)
            yield window[:size].ljust(size, b"\0")
            written += size
            cursor += count
    while written < transfer_length:
        size = min(block_size, transfer_length - written)
        yield bytes(size)
        written += size
    if written != transfer_length:
        raise CommonResponseError(9999)


@dataclass(frozen=True)
class Phase6SRecordStream:
    source: bytes | LargeSource2026 = field(repr=False)
    end: int
    groups: tuple[tuple[int, int], ...]

    def __post_init__(self):
        if (
            not isinstance(self.source, (bytes, LargeSource2026))
            or not 0 < len(self.source) <= 0xFFFFFFFF
        ):
            raise ValueError("Authorized bounded native stream source bytes required")
        if type(self.end) is not int or not 0 <= self.end < len(self.source):
            raise ValueError("Native inclusive S-record source end required")
        if not isinstance(self.groups, tuple) or not 1 <= len(self.groups) <= 4:
            raise ValueError(
                "Native descriptor one to four address/offset groups required"
            )
        for address, offset in self.groups:
            if (
                type(address) is not int
                or not 0 <= address <= 0xFFFFFFFF
                or type(offset) is not int
                or not 0 <= offset <= self.end
            ):
                raise ValueError("Native bounded stream address/offset group required")


def phase6_srecord_stream_blocks(
    stream: Phase6SRecordStream,
    address: int,
    transfer_length: int,
    block_size: int,
    *,
    runtime: NativeRuntime2026 | None = None,
):
    """Flash3870: source groups,5-MiB lookahead, record-boundary blocks and zero tail.

    Yields(counter,payload), retaining the native counter restart when source
    exhaustion switches to the separate zero-fill loop. Descriptor production is
    a separate source-backed CUW engine responsibility.
    """

    if not isinstance(stream, Phase6SRecordStream):
        raise TypeError("Frozen native S-record stream descriptor required")
    if (
        type(address) is not int
        or not 0 <= address <= 0xFFFFFFFF
        or type(transfer_length) is not int
        or not 0 < transfer_length <= 0xFFFFFFFF
        or type(block_size) is not int
        or not 1 <= block_size <= 4093
    ):
        raise ValueError("Native bounded stream address/transfer/block length required")
    matches = [offset for start, offset in stream.groups if start == address]
    if not matches:
        raise CommonResponseError(9999)
    start = cursor = matches[0]
    written, sequence = 0, 1
    pending = bytearray()
    window, window_start = b"", cursor
    retry = False
    while start != 0 and cursor <= stream.end and written < transfer_length:
        if runtime is not None:
            runtime.check()
        local = cursor - window_start
        if local >= len(window):
            window_start = cursor
            window = stream.source[cursor : min(cursor + 0x500000, stream.end + 1)]
            local = 0
        record = parse_phase6_srecord_window(window[local:])
        if record.status != 0 and not retry:
            # Native seekg rewinds unconsumed bytes and retries at this record.
            retry = True
            window, window_start = b"", cursor
            continue
        if record.status == 2:
            raise CommonResponseError(9999)
        retry = False
        if cursor == start and (record.address or 0) < address:
            raise CommonResponseError(9999)
        if record.consumed <= 0:
            raise CommonResponseError(9999)
        cursor += record.consumed
        payload = record.payload[: transfer_length - written - len(pending)]
        if len(pending) + len(payload) > block_size:
            raise CommonResponseError(9999)
        pending.extend(payload)
        if pending and (
            len(pending) >= block_size
            or cursor > stream.end
            or written + len(pending) >= transfer_length
        ):
            if cursor > stream.end and written + len(pending) < transfer_length:
                pending.extend(
                    bytes(min(block_size, transfer_length - written) - len(pending))
                )
            yield sequence & 255, bytes(pending)
            written += len(pending)
            sequence += 1
            pending.clear()
    if pending:
        raise CommonResponseError(9999)
    if written < transfer_length:
        sequence = 1
        while written < transfer_length:
            size = min(block_size, transfer_length - written)
            yield sequence & 255, bytes(size)
            written += size
            sequence += 1
    if written != transfer_length:
        raise CommonResponseError(9999)


MODULE_OPERATIONS = {
    "TCUWCanDCMPRLVersionGetter.dll": "get_cid",
    "TCUWCanDCMPRLPrepareWriter.dll": "prepare",
    "TCUWCanDCMPRLFlashWriter.dll": "write",
    "TCUWP6CanCIDGetter.dll": "get_cid",
    "TCUWP6CanReprostdPrepareWriter.dll": "prepare",
    "TCUWP6CanReprostdFlashWriter.dll": "write",
}
_BIND_TOKEN = object()
_BOUND_CONTEXTS: weakref.WeakValueDictionary[int, P6ExecutionContext] = (
    weakref.WeakValueDictionary()
)


class _P6GetterImportReceipt2026:
    """One issued raw getter return awaiting the source outer callback."""

    __slots__ = (
        "_consumed",
        "active_record",
        "context",
        "control_context",
        "identifiers",
        "job",
        "lease",
        "outer_session",
        "records",
        "sequence",
        "session",
    )

    def __init__(self, context, identifiers, records):
        if (
            type(context) is not P6ExecutionContext
            or _BOUND_CONTEXTS.get(id(context)) is not context
            or context.export != "StartGetCID"
            or context.identity.module_name != "TCUWP6CanCIDGetter.dll"
            or context.engine_state is None
        ):
            raise ValueError("Exact issued P6 getter Execute result required")
        self.context = context
        self.identifiers = identifiers
        self.records = records
        self.session = self.outer_session = self.control_context = self.job = None
        self.lease = self.active_record = None
        self.sequence = None
        self._consumed = False

    def bind_outer_return(self, session, outer_session, control_context, job) -> None:
        from scripts.cuw_engine_threads import EngineThreadJob2026
        from scripts.programming_2026_common import NativeControlContext2026
        from scripts.programming_replay import ProgrammingReplay

        state = self.context.engine_state
        if state is None:
            raise ValueError("Exact P6 getter engine state required")
        engine = state.engine
        lease = getattr(job, "_lease", None)
        active_record = getattr(job, "_active_record", None)
        sequence = getattr(job, "_sequence", None)
        target = getattr(session, "_control_target2026", None)
        if (
            self._consumed
            or self.session is not None
            or type(session) is not ProgrammingReplay
            or type(outer_session) is not ProgrammingReplay
            or type(control_context) is not NativeControlContext2026
            or type(job) is not EngineThreadJob2026
            or getattr(session, "_engine2026", None) is not engine
            or getattr(session, "_controller2026", None)
            is not engine._controller_execution
            or getattr(session, "_control_export2026", None) != "StartGetCID"
            or getattr(session, "_executed_selection2026", None)
            != self.context.selection
            or target is None
            or getattr(target, "_context", None) is not control_context
            or getattr(job, "_session", None) is not outer_session
            or getattr(session, "_phase6_outer_session2026", None) is not outer_session
            or engine._thread_job is not job
            or lease is None
            or getattr(lease, "phase", None) != 0
            or active_record is None
            or type(sequence) is not int
            or sequence <= 0
        ):
            raise ValueError("P6 getter result lacks its issued outer return join")
        self.session = session
        self.outer_session = outer_session
        self.control_context = control_context
        self.job = job
        self.lease = lease
        self.active_record = active_record
        self.sequence = sequence

    def validate_consume(self, engine) -> None:
        from threading import get_ident

        from scripts.programming_2026_common import (
            NativeControlContext2026,
            _control_getter_return_values2026,
        )

        state = self.context.engine_state
        outer_session = self.outer_session
        control_context = self.control_context
        if state is None:
            raise ValueError("Current source-issued P6 getter callback required")
        if (
            self._consumed
            or state.engine is not engine
            or engine.dh_state is not state
            or not engine._active
            or engine._phase_thread != get_ident()
            or self.context.export != "StartGetCID"
            or _BOUND_CONTEXTS.get(id(self.context)) is not self.context
            or self.session is None
            or self.job is None
            or outer_session is None
            or control_context is None
            or engine._thread_job is not self.job
            or self.job._session is not self.outer_session
            or self.session._phase6_outer_session2026 is not self.outer_session
            or outer_session._phase6_getter_import2026 is not self
            or self.job._sequence != self.sequence
            or self.job._lease is not self.lease
            or self.job._active_record is not self.active_record
            or self.session._engine2026 is not engine
            or self.session._executed_selection2026 != self.context.selection
            or self.session._control_target2026._context is not control_context
            or engine._controller_execution is not self.session._controller2026
            or self.session._controller2026.native_control_context2026(engine)
            is not control_context
        ):
            raise ValueError("Current source-issued P6 getter callback required")
        if (
            type(control_context) is not NativeControlContext2026
            or _control_getter_return_values2026(control_context) != self.identifiers
        ):
            raise ValueError("P6 import IDs differ from the final getter vector")
        engine._validate_phase6_getter_result(self.identifiers, self.records)

    def consume(self, engine) -> None:
        self.validate_consume(engine)
        engine._import_phase6_getter_result(self.identifiers, self.records)
        self._consumed = True


@dataclass(frozen=True)
class P6ExecutionContext:
    identity: NativeModuleIdentity
    export: str
    selection: object = field(repr=False)
    native: (
        DCMPRLPlan | Phase6PrepareContext | Phase6FlashPlan | tuple[Phase6Node, ...]
    ) = field(repr=False)
    observations: Mapping = field(repr=False)
    secret_info: SecretInfoClient | None = field(default=None, repr=False)
    security_composer: NativeSecurityComposer2026 | None = field(
        default=None, repr=False
    )
    engine_state: DHControllerState2026 | None = field(default=None, repr=False)
    getter_state: DCMGetterState2026 | None = field(default=None, repr=False)
    _proof: object = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        from scripts.programming_2026_common import NativeParameterBinding2026

        if (
            self._proof is not _BIND_TOKEN
            or not isinstance(self.selection, NativeParameterBinding2026)
            or not isinstance(self.identity, NativeModuleIdentity)
            or self.identity.module_name not in MODULE_OPERATIONS
            or self.identity
            != identify_native_module(self.identity.sha256, self.identity.module_name)
            or self.identity.cuw_build != "2026"
            or self.selection.module_name != self.identity.module_name
            or self.export not in self.identity.callable_exports
            or (
                self.export != "ProcessBeforeIGOffOnAtRetry"
                and (
                    type(self.engine_state) is not DHControllerState2026
                    or self.engine_state.metadata != self.selection.metadata
                )
            )
            or (
                self.security_composer is not None
                and (
                    type(self.security_composer) is not NativeSecurityComposer2026
                    or self.security_composer.client is not self.secret_info
                )
            )
        ):
            raise ValueError(
                "P6/DCMPRL execution context requires actual native binding"
            )


def bind_native_context(
    container,
    node: int,
    observed_cids: tuple[str, ...],
    selection,
    identity: NativeModuleIdentity,
    attachments: Mapping[str, bytes],
    observations: Mapping,
) -> P6ExecutionContext:
    """Actual31 selection → exact module bytes → actual47 metadata/48 addresses."""
    from datetime import date
    from types import MappingProxyType

    from scripts.calibration_2026 import (
        native2026_location_id,
    )
    from scripts.calibration_catalog import SelectionContext
    from scripts.j2534_2026 import communication_addresses_from_parameter
    from scripts.programming_2026_common import NativeParameterBinding2026

    if (
        not isinstance(selection, NativeParameterBinding2026)
        or not isinstance(identity, NativeModuleIdentity)
        or identity.module_name not in MODULE_OPERATIONS
        or not isinstance(attachments, Mapping)
        or not isinstance(observations, Mapping)
    ):
        raise TypeError(
            "Actual2026 selection, module bytes and native host observations required"
        )
    SelectionContext(observed_cids)
    if set(attachments) - {
        "selected_module",
        "secret_info_module",
        "cuw_module",
        "tester_id",
    } or set(observations) - {
        "cpu_index",
        "stage",
        "module_version",
        "export",
        "retry",
        "gateway_kind",
        "programming_started_at",
        "initial_delay_seconds",
        "unresolved_retry_seconds",
        "check_dtcs",
        "tester_id",
        "system_date",
        "previous_addresses",
        "response_canids",
        "dh_state",
        "dcm_getter_state",
    }:
        raise ValueError(
            "P6/DCMPRL binding rejects manual geometry and undeclared overrides"
        )
    if (
        "selected_module" not in attachments
        or any(not isinstance(value, bytes) for value in attachments.values())
        or sum(map(len, attachments.values())) > 96 * 1024 * 1024
    ):
        raise ValueError("Exact immutable selected native module bytes required")
    operation = MODULE_OPERATIONS[identity.module_name]
    cpu = observations.get("cpu_index", 0)
    selection = selection.validate_against(
        container, operation=operation, node=node, cpu_index=cpu
    )
    if observations.get("stage", operation) != operation:
        raise ValueError("Native requested stage differs from selected P6/DCMPRL row")
    version = observations.get("module_version")
    dispatch = selection.dispatch(
        {identity.module_name: attachments["selected_module"]},
        module_versions=None if version is None else {identity.module_name: version},
    )
    if dispatch["identity"] != identity:
        raise ValueError("Selected P6/DCMPRL bytes differ from authenticated identity")
    export = observations.get("export", dispatch["operation"])
    if export != dispatch["operation"] and not (
        export == "ProcessBeforeIGOffOnAtRetry"
        and identity.family
        in ("TCUWP6CanReprostdPrepareWriter", "TCUWP6CanReprostdFlashWriter")
    ):
        raise ValueError("Native export differs from selected P6/DCMPRL operation")
    options = {}
    secret = None
    security = None
    parameter = selection.parameter
    metadata = selection.metadata
    engine_state = observations.get("dh_state")
    getter_state = observations.get("dcm_getter_state")
    if export != "ProcessBeforeIGOffOnAtRetry":
        if (
            type(engine_state) is not DHControllerState2026
            or engine_state.metadata != metadata
        ):
            raise ValueError("Actual loaded-engine P6/DCMPRL state required")
        if operation == "write":
            _ = engine_state.notification  # Require actual persistence before I/O.
    if identity.module_name == "TCUWCanDCMPRLVersionGetter.dll" and (
        type(getter_state) is not DCMGetterState2026
        or getter_state.metadata != metadata
    ):
        raise ValueError("Actual active-engine DCM getter record state required")
    if identity.module_name == "TCUWCanDCMPRLVersionGetter.dll":
        assert getter_state is not None
        getter_state.validate_current()
    if identity.module_name.startswith("TCUWCanDCMPRL"):
        if set(attachments) != {"selected_module"}:
            raise ValueError("DCMPRL export has no external software data attachment")
        resolver = communication_addresses_from_parameter(
            None if operation == "get_cid" else container,
            parameter,
            response_canids=observations.get("response_canids"),
            history=list(observations.get("previous_addresses", ())),
        )
        resolved, addresses = resolver.resolve(
            selection.selector_functions,
            cids=observed_cids,
            location_id=native2026_location_id(metadata, cpu)
            if metadata.cpus
            else None,
        )
        index = 0  # Resolver returns the selected CPU's inner address group.
        if not resolved or not 0 <= index < len(addresses):
            raise ValueError("Actual DCMPRL selected communication address unavailable")
        record = addresses[index].record()
        values = {
            "ReceiveTimeoutBeforeGetCID": parameter.long("ReceiveTimeoutBeforeGetCID")
            or 0,
            "WaitTimeAfterEndOfFlashing": parameter.long("WaitTimeAfterEndOfFlashing")
            or 0,
        }
        hold = parameter.boolean("FlagToHoldSFormatRecords")
        if hold is not None:
            values["FlagToHoldSFormatRecords"] = hold
        native = native_dcmprl_plan(
            container,
            cpu,
            identity,
            request_id=record[:3],
            response_id=record[3:6],
            parameters=values,
            node=node,
        )
        if operation == "prepare":
            assert engine_state is not None
            retry = engine_state.native_context_964
            if "retry" in observations and observations["retry"] is not retry:
                raise ValueError("Retry observation differs from actual native state")
            options["retry"] = retry
    elif export == "ProcessBeforeIGOffOnAtRetry":
        if set(attachments) != {"selected_module"}:
            raise ValueError(
                "Native P6 retry reset has no secret or payload attachment"
            )
        nodes = native_phase6_nodes_for_selected_metadata(metadata)
        native = nodes
    elif operation == "get_cid":
        if set(attachments) != {"selected_module"}:
            raise ValueError("Native P6 getter has no secret or payload attachment")
        native = native_phase6_nodes(container, identity)
        required = {
            "programming_started_at",
            "initial_delay_seconds",
            "unresolved_retry_seconds",
            "check_dtcs",
        }
        if not required <= observations.keys():
            raise ValueError(
                "Native P6 getter controller timing/DTC observations required"
            )
        options = {key: observations[key] for key in required}
        options["receive_timeout_ms"] = (
            parameter.long("ReceiveTimeoutBeforeGetCID") or 0
        )
    elif operation == "prepare":
        if set(attachments) != {"selected_module", "secret_info_module", "cuw_module"}:
            raise ValueError("Exact native CUW and SecretInfo dependencies required")
        assert engine_state is not None
        retry = engine_state.native_context_964
        if "retry" in observations and observations["retry"] is not retry:
            raise ValueError("Retry observation differs from actual native state")
        security = NativeSecurityComposer2026.from_native_modules(
            attachments["secret_info_module"], attachments["cuw_module"]
        )
        secret = security.client
        native = native_phase6_prepare_context(
            container, identity, node=node, metadata=metadata
        )
        options = {
            "retry": retry,
            "gateway_kind": engine_state.engine.repro_gateway_node,
        }
        if (
            "gateway_kind" in observations
            and observations["gateway_kind"] != options["gateway_kind"]
        ):
            raise ValueError("P6 gateway observation differs from actual engine state")
    else:
        if set(attachments) - {"selected_module", "tester_id"}:
            raise ValueError("Native P6 writer does not accept external image geometry")
        native = native_phase6_flash_plan(
            container, identity, node=node, metadata=metadata
        )
        tester = attachments.get("tester_id", observations.get("tester_id"))
        if isinstance(tester, str):
            tester = tester.encode("latin1")
        observed_date = observations.get("system_date")
        if isinstance(observed_date, str) and len(observed_date) == 10:
            observed_date = date.fromisoformat(observed_date)
        if (
            not isinstance(tester, bytes)
            or len(tester) > 17
            or not isinstance(observed_date, date)
        ):
            raise ValueError(
                "Observed native tester bytes and UTC system date required"
            )
        options = {"tester_id": tester, "system_date": observed_date}
    context = P6ExecutionContext(
        identity,
        export,
        selection,
        native,
        MappingProxyType(options),
        secret,
        security,
        engine_state=engine_state,
        getter_state=getter_state,
        _proof=_BIND_TOKEN,
    )
    _BOUND_CONTEXTS[id(context)] = context
    return context


def native_phase6_nodes_for_selected_metadata(metadata) -> tuple[Phase6Node, ...]:
    target = metadata.node_values.get("diagid", "")
    if len(target) != 2 or any(char not in "0123456789abcdefABCDEF" for char in target):
        raise ValueError("Native selected Phase6 diagnostic target malformed")
    return (Phase6Node(bytes.fromhex(target), metadata.wakeup_ms, target),)


def execute_context(context: P6ExecutionContext, runtime: NativeRuntime2026) -> dict:
    """Run one exact selected export while retaining the caller's runtime lifetime."""
    if not isinstance(context, P6ExecutionContext) or not isinstance(
        runtime, NativeRuntime2026
    ):
        raise TypeError(
            "Canonical P6/DCMPRL context and concrete native runtime required"
        )
    if _BOUND_CONTEXTS.get(id(context)) is not context:
        raise ValueError(
            "P6/DCMPRL context was not issued by the native binding factory"
        )
    context.__post_init__()
    # Retry exports are void and let native exceptions escape. Getters return
    # a vector pointer plus a separate success BOOL through their last argument.
    # Prepare/flash return the BOOL directly.
    if context.export == "ProcessBeforeIGOffOnAtRetry":
        return {**_execute_context(context, runtime), "native_return": None}
    state = {}
    success = (
        {"native_return": None, "native_success": True}
        if context.export == "StartGetCID"
        else {"native_return": True}
    )
    try:
        result = _execute_context(context, runtime, state)
        if (
            context.export == "StartPrepareWrite"
            and isinstance(context.native, DCMPRLPlan)
            and context.engine_state is not None
            and context.engine_state.error_kind == 1
        ):
            context.engine_state.mark_native_retry()
            result["retry_required"] = True
        return {**result, **success}
    except (Exception, KeyboardInterrupt) as error:
        if not is_native_exception2026(error) or state.get("native_cleanup_escape"):
            raise
        result = {
            **state,
            "state": "failed",
            "complete": False,
            **(
                {"native_return": None, "native_success": False}
                if context.export == "StartGetCID"
                else {"native_return": False}
            ),
            "error": type(error).__name__,
        }
        try:
            primary, secondary = native_error_fields2026(error)
        except TypeError:
            # DCM catch-all blocks explicitly write9999. P6 catch-all blocks
            # preserve prior error fields, so no default enum is manufactured.
            if context.identity.module_name.startswith("TCUWCanDCMPRL"):
                result["native_primary_error"] = 9999
                if context.export != "StartGetCID":
                    result["native_error_kind"] = (
                        1 if context.export == "StartPrepareWrite" else 2
                    )
        else:
            result["native_primary_error"] = primary
            if secondary is not None:
                result["native_passthru_error"] = secondary
            if context.export == "StartPrepareWrite":
                result["native_error_kind"] = 1
            elif context.export == "StartFlashWrite":
                result["native_error_kind"] = state.get("error_result", 2)
        if "native_primary_error" in result:
            assert context.engine_state is not None
            context.engine_state.record_native_error(
                result.get("native_error_kind"),
                result["native_primary_error"],
                result.get("native_passthru_error"),
            )
            result.update(
                native_error_kind=context.engine_state.error_kind,
                native_primary_error=context.engine_state.primary_error,
                native_passthru_error=context.engine_state.passthru_error,
            )
            if (
                context.export == "StartPrepareWrite"
                and isinstance(context.native, DCMPRLPlan)
                and context.engine_state.error_kind == 1
            ) or (
                context.export == "StartFlashWrite"
                and isinstance(context.native, Phase6FlashPlan)
                and state.get("error_result") == 1
            ):
                context.engine_state.mark_native_retry()
        if context.engine_state is not None:
            result.update(
                native_error_kind=context.engine_state.error_kind,
                native_primary_error=context.engine_state.primary_error,
                native_passthru_error=context.engine_state.passthru_error,
            )
        return result


def _execute_context(
    context: P6ExecutionContext, runtime: NativeRuntime2026, state: dict | None = None
) -> dict:
    state = {} if state is None else state
    native = context.native
    if isinstance(native, DCMPRLPlan):
        client = DCMPRL2026(
            native.context,
            runtime=runtime,
            getter_state=context.getter_state,
            notification=context.engine_state.notification
            if context.export == "StartFlashWrite" and context.engine_state is not None
            else None,
            engine_state=context.engine_state,
        )
        state.update(client.state)
        client.state = state
        if context.export == "StartGetCID":
            identifier = client.get_version()
            return {
                **client.state,
                "state": "read_completed",
                "identifiers": ()
                if client.state.get("native_cancelled")
                else (identifier.encode("latin1"),),
            }
        if context.export == "StartPrepareWrite":
            return {
                **client.prepare(retry=context.observations["retry"]),
                "state": "prepare_completed",
            }
        return {**client.flash(native.image), "state": "writer_completed"}
    if context.export == "ProcessBeforeIGOffOnAtRetry":
        assert isinstance(native, tuple) and len(native) == 1
        process_before_ig_off_on_at_retry(runtime, native[0].target)
        return {"state": "retry_reset_completed", "complete": True}
    if isinstance(native, tuple):
        rows = get_phase6_cids(
            runtime, native, engine_state=context.engine_state, **context.observations
        )
        identifiers = tuple(cid.encode("latin1") for row in rows for cid in row["cids"])
        assert context.engine_state is not None
        engine = context.engine_state.engine
        records = phase6_getter_records(
            identifiers,
            native,
            tuple(len(row["cids"]) for row in rows),
            engine.identifier_records,
        )
        receipt = _P6GetterImportReceipt2026(context, identifiers, records)
        return {
            "_phase6_getter_import2026": receipt,
            "state": "read_completed",
            "complete": True,
            "identifiers": identifiers,
            "identifier_records": records,
            "nodes": rows,
        }
    if isinstance(native, Phase6PrepareContext):
        assert context.secret_info is not None
        if context.security_composer is None:
            raise ValueError(
                "Canonical P6 preparation requires actual native AES composer"
            )
        runtime.bind_security_composer(context.security_composer)
        return {
            **prepare_phase6(
                runtime,
                native,
                context.secret_info,
                state=state,
                engine_state=context.engine_state,
                **context.observations,
            ),
            "state": "prepare_completed",
        }
    return {
        **flash_phase6(
            runtime,
            native,
            state=state,
            notification=context.engine_state.notification
            if context.engine_state is not None
            else None,
            engine_state=context.engine_state,
            **context.observations,
        ),
        "state": "writer_completed",
    }
