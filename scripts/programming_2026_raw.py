"""Source-identified CUW2026 generic CAN programming operations.

No DLL is executed and no transport is opened by importing this module.
"""

import hashlib
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field

from scripts.j2534_2026 import (
    NativeCommunicationAddress,
    communication_addresses_from_parameter,
)
from scripts.native_modules import NativeModuleIdentity, identify_native_module
from scripts.programming import NativeTransportError
from scripts.programming_2026_common import (
    CanDiag2026,
    CommonResponseError,
    NativeException2026,
    NativeGeneralParameters2026,
    NativeJ2534Exception2026,
    NativeParameter2026,
    NativeParameterBinding2026,
    NativePassThruException2026,
    NativeRuntime2026,
    SecretInfoClient,
    is_native_exception2026,
)
from scripts.programming_vendor import NativeTransportError as VendorTransportError

SOFTWARE_INFO = "TCUWCanSoftwareInfoIDGetter.dll"
REPRO_PREPARE = "TCUWCanReproStdPrepareWriter.dll"
REPRO_WRITE = "TCUWCanReproStdFlashWriter.dll"
POWERTRAIN = "TCUWCanPowerTrainFlashWriter.dll"
SOLAR = "TCUWCanPowerTrainFlashWriterForSolar.dll"

IMPLEMENTED_EXPORTS = {
    SOFTWARE_INFO: ("StartGetCID",),
    REPRO_PREPARE: ("StartPrepareWrite",),
    REPRO_WRITE: ("StartFlashWrite",),
    POWERTRAIN: ("PrepareRetry", "StartFlashWrite"),
    SOLAR: ("StartFlashWrite",),
}


@contextmanager
def _preserve_active_host_error():
    """Cleanup cannot replace an already propagating host failure."""
    original = sys.exception()
    try:
        yield
    except BaseException as cleanup_error:
        if (
            original is None
            or is_native_exception2026(original)
            or isinstance(original, VendorTransportError)
        ):
            raise
        original.add_note("Cleanup also failed: " + type(cleanup_error).__name__)


def _native_error(error):
    if isinstance(error, NativePassThruException2026):
        return error.error
    if isinstance(error, (NativeTransportError, VendorTransportError)):
        return getattr(error, "native_error_code", 1)
    return error.code


def _driver_error(error):
    if isinstance(error, NativeJ2534Exception2026):
        return error.j2534_error
    if isinstance(error, (NativeTransportError, VendorTransportError)):
        return getattr(error, "passthru_status", error.code)
    return None


@dataclass(frozen=True)
class SoftwareInfoContext2026:
    identity: NativeModuleIdentity
    addresses: tuple[NativeCommunicationAddress, ...]
    receive_timeout_ms: int = 0
    id_byte_num: int = 0
    apgs_parking_assist_monitor: bool = False

    def __post_init__(self):
        if (
            not isinstance(self.identity, NativeModuleIdentity)
            or self.identity
            != identify_native_module(self.identity.sha256, SOFTWARE_INFO)
            or self.identity.cuw_build != "2026"
            or type(self.addresses) is not tuple
            or len(self.addresses) > 256
            or any(
                not isinstance(v, NativeCommunicationAddress) for v in self.addresses
            )
            or type(self.receive_timeout_ms) is not int
            or not 0 <= self.receive_timeout_ms <= 0xFFFFFFFF
            or type(self.id_byte_num) is not int
            or not 0 <= self.id_byte_num <= 16
            or type(self.apgs_parking_assist_monitor) is not bool
        ):
            raise ValueError(
                "Exact2026 software-info source and bounded native context required"
            )


def bind_native_context(
    container, node, observed_cids, selection, identity, attachments, observations
):
    if identity.module_name in (REPRO_WRITE, REPRO_PREPARE):
        return bind_repro_context(
            container,
            node,
            observed_cids,
            selection,
            identity,
            attachments,
            observations,
        )
    if identity.module_name == SOLAR:
        return bind_solar_context(
            container,
            node,
            observed_cids,
            selection,
            identity,
            attachments,
            observations,
        )
    if identity.module_name == POWERTRAIN:
        if observations.get("stage") == "retry":
            retry_observations = {
                key: value for key, value in observations.items() if key != "stage"
            }
            return bind_powertrain_retry_context(
                container,
                node,
                observed_cids,
                selection,
                identity,
                attachments,
                retry_observations,
            )
        return bind_powertrain_context(
            container,
            node,
            observed_cids,
            selection,
            identity,
            attachments,
            observations,
        )
    if (
        not isinstance(selection, NativeParameterBinding2026)
        or selection.operation != "get_cid"
        or selection.module_name != SOFTWARE_INFO
        or attachments
        or observations
    ):
        raise ValueError("Native software-info getter binding required")
    selection.validate_against(container, operation="get_cid", node=node, cpu_index=0)
    success, addresses = communication_addresses_from_parameter(
        container, selection.parameter
    ).resolve(
        selection.selector_functions,
        cids=observed_cids,
        location_id=selection.metadata.cpu.values.get("locationid") or None,
    )
    if not success:
        raise ValueError("Native software-info CAN address selection failed")
    return SoftwareInfoContext2026(
        identity,
        addresses,
        selection.parameter.long("ReceiveTimeoutBeforeGetCID") or 0,
        selection.parameter.long("SoftwareInfoIDByteNum") or 0,
        selection.metadata.vehicle.get("kindofecu") == "38",
    )


def decode_software_info2026(data: bytes, id_byte_num: int = 0) -> str:
    """SoftwareInfo1af0: fixed J2534 offsets, 16 bytes, NUL then trailing space."""
    if type(id_byte_num) is not int or not 0 <= id_byte_num <= 16:
        raise ValueError("Native SoftwareInfoIDByteNum must be zero through sixteen")
    if type(data) is not bytes or not 23 <= len(data) <= 4128:
        raise CommonResponseError(3)
    offset = 8 if data[5:7] == b"\x5a\x88" else 7
    if len(data) < offset + 16:
        raise CommonResponseError(3)
    value = bytearray(data[offset : offset + 16]) + b"\0"
    if value[0] and id_byte_num:
        value[id_byte_num] = 0
    # Native loop deliberately stops at byte zero; it never trims its first space.
    for index in range(15, 0, -1):
        if value[index] != 0x20:
            break
        value[index] = 0
    result = bytes(value).split(b"\0", 1)[0]
    if not result:
        raise CommonResponseError(3)
    return result.decode("latin-1")


def run_software_info(
    context: SoftwareInfoContext2026, runtime: NativeRuntime2026
) -> dict:
    """StartGetCID1180 and full1240/157d/1790/1af0 address iteration."""
    if not isinstance(context, SoftwareInfoContext2026) or not isinstance(
        runtime, NativeRuntime2026
    ):
        raise TypeError("Bound software-info context and runtime required")
    if runtime.owns_resource("disconnect"):
        raise ValueError("Native getter requires its own connection scope")
    diag = CanDiag2026(runtime)
    cids, query_ids, history = [], [], []
    failure = None
    cleanup_errors = []
    if runtime.native_cancelled is None:
        raise ValueError("Native getter cancellation callback required")

    def exchange(address, payload, minimum, expected):
        request, response = address.headers()
        identifier = diag.start_filter(request, response)
        try:
            if runtime.native_cancellation_requested():
                return None
            return diag.call(
                request,
                response,
                payload,
                expected,
                minimum=minimum,
                error_code=3,
                check_native_cancel=True,
            )
        finally:
            with _preserve_active_host_error():
                runtime.release("stop_filter", identifier=identifier)

    try:
        runtime.call_owned("connect", "disconnect", protocol=6)
        runtime.call("set_timeout", milliseconds=context.receive_timeout_ms)
        for address in context.addresses:
            block_override = address.extended or context.apgs_parking_assist_monitor
            try:
                if block_override:
                    diag.set_block_size(1)
                raw_listing = exchange(address, b"\x1a\x88\0", 4, b"\x5a\x88\0")
                listing = None if raw_listing is None else raw_listing[3:]
                if listing is None or b"\0" in listing:
                    if runtime.native_cancellation_requested():
                        continue
                    raise CommonResponseError(3)
                history.append(address)
                request, response = address.headers()
                filter_id = diag.start_filter(request, response)
                try:
                    if runtime.native_cancellation_requested():
                        continue
                    for identifier in listing:
                        prefix = b"\x5a\x88" + bytes((identifier,))
                        payload = diag.call(
                            request,
                            response,
                            b"\x1a\x88" + bytes((identifier,)),
                            prefix,
                            minimum=3,
                            error_code=3,
                            check_native_cancel=True,
                        )
                        cids.append(
                            decode_software_info2026(
                                response + payload, context.id_byte_num
                            )
                        )
                        if len(cids) <= 34:
                            query_ids.append(address.request)
                        if len(cids) > 65536:
                            raise ValueError(
                                "Host software-info result capacity exceeded"
                            )
                finally:
                    with _preserve_active_host_error():
                        runtime.release("stop_filter", identifier=filter_id)
            finally:
                with _preserve_active_host_error():
                    if block_override:
                        try:
                            runtime.call(
                                "control_io",
                                cleanup=True,
                                ioctl=2,
                                parameters=((0x1E, 0),),
                            )
                        except (
                            CommonResponseError,
                            NativeTransportError,
                            VendorTransportError,
                            NativeException2026,
                        ) as exc:
                            cleanup_errors.append(
                                (
                                    None
                                    if type(exc) is NativeException2026
                                    else _native_error(exc),
                                    _driver_error(exc),
                                )
                            )

    except (
        CommonResponseError,
        NativeTransportError,
        VendorTransportError,
        NativeException2026,
    ) as exc:
        failure = exc
    finally:
        with _preserve_active_host_error():
            if runtime.owns_resource("disconnect"):
                runtime.release("disconnect")
    driver = isinstance(failure, (NativeTransportError, VendorTransportError))
    return {
        "native_return": None,
        "native_success": failure is None,
        "state": "cid_read_completed" if failure is None else "get_cid_failed",
        "cids": tuple(cids),
        "query_ids": tuple(query_ids),
        "history": tuple(history),
        "cleanup_failed": bool(cleanup_errors),
        "cleanup_errors": tuple(cleanup_errors),
        "native_error_code": None
        if type(failure) is NativeException2026
        else (
            getattr(failure, "native_error_code", 1)
            if driver
            else _native_error(failure)
            if failure
            else None
        ),
        "driver_error_code": _driver_error(failure),
        "programming_completed": False,
    }


@dataclass(frozen=True)
class SolarContext2026:
    identity: NativeModuleIdentity
    selection: NativeParameterBinding2026
    address: NativeCommunicationAddress
    finish_address: NativeCommunicationAddress
    cpu_index: int
    cpu_count: int
    image: bytes = field(repr=False)
    flash_size: int
    header: bytes
    location_id: bytes
    target_password: int = field(repr=False)
    new_password: int = field(repr=False)
    retry_password: bool = False
    retrying: bool = False
    next_cpu_type: str = ""
    secondary_cpu_type: str = ""
    initial_counts: tuple[int, ...] = ()
    initial_percentages: tuple[int, ...] = ()

    def __post_init__(self):
        for progress in (self.initial_counts, self.initial_percentages):
            if (
                type(progress) is not tuple
                or progress
                and len(progress) != self.cpu_count
                or any(type(v) is not int or not 0 <= v <= 0xFFFFFFFF for v in progress)
            ):
                raise ValueError(
                    "Native CPU-sized unsigned progress snapshots required"
                )
        if (
            not isinstance(self.identity, NativeModuleIdentity)
            or self.identity
            != identify_native_module(self.identity.sha256, self.identity.module_name)
            or self.identity.cuw_build != "2026"
            or self.identity.module_name not in (SOLAR, POWERTRAIN)
            or not isinstance(self.selection, NativeParameterBinding2026)
            or self.selection.operation != "write"
            or self.selection.module_name != self.identity.module_name
            or any(
                not isinstance(v, NativeCommunicationAddress)
                for v in (self.address, self.finish_address)
            )
            or self.address.extended
            or type(self.location_id) is not bytes
            or len(self.location_id) != 8
            or type(self.image) is not bytes
            or not 0 < len(self.image) <= 64 * 1024 * 1024
            or type(self.header) is not bytes
            or type(self.secondary_cpu_type) is not str
            or len(self.secondary_cpu_type) > 259
            or not self.secondary_cpu_type.isascii()
            or any(c in self.secondary_cpu_type for c in ("/", "\\", "\0"))
            or type(self.cpu_index) is not int
            or type(self.cpu_count) is not int
            or not 0 <= self.cpu_index < self.cpu_count <= 256
            or type(self.flash_size) is not int
            or not 0 <= self.flash_size <= 0xFFFFFFFF
            or any(
                type(v) is not int or not 0 <= v <= 0xFFFFFFFF
                for v in (self.target_password, self.new_password)
            )
            or any(type(v) is not bool for v in (self.retry_password, self.retrying))
        ):
            raise ValueError("Exact2026 Solar native metadata/image context required")


def _bind_classic_write_context(
    container, node, observed_cids, selection, identity, attachments, observations
):
    from scripts.calibration_2026 import (
        native2026_archive,
        native2026_archive_password,
        native2026_cpu_count,
        native2026_cpu_targets,
        native2026_cpu_values,
        native2026_new_password,
    )

    if (
        not isinstance(selection, NativeParameterBinding2026)
        or selection.operation != "write"
        or selection.module_name not in (SOLAR, POWERTRAIN)
        or attachments
        or set(observations)
        - {
            "cpu_index",
            "target_index",
            "retry_password",
            "retrying",
            "native_engine_cpu_type",
            "counts",
            "percentages",
        }
    ):
        raise ValueError(
            "Imported2026 Solar selection and native retry observations required"
        )
    index = observations.get("cpu_index", 0)
    selection.validate_against(container, operation="write", node=node, cpu_index=index)
    metadata = selection.metadata
    producer = communication_addresses_from_parameter(container, selection.parameter)
    success, addresses = producer.resolve(
        selection.selector_functions,
        cids=observed_cids,
        location_id=metadata.cpu.values.get("locationid") or None,
    )
    if not success or len(addresses) < 2:
        raise ValueError(
            "Native Solar FlashWrite selector must produce programming/finish pair"
        )
    targets = native2026_cpu_targets(metadata)
    target = observations.get("target_index", 0)
    if type(target) is not int or not 0 <= target < len(targets):
        raise ValueError("Native target password selection absent")
    archive = native2026_archive(metadata)
    if archive.data is None:
        raise ValueError("Solar requires materialized native archive")
    parameters = {key: selection.value(key) for key in selection.values}
    retry_password = observations.get("retry_password", False)
    external = selection.parameter.boolean("ExternalMemoryFlag") or False
    if selection.module_name == SOLAR:
        password = (
            native2026_new_password(metadata, parameters)
            if retry_password and not external
            else targets[target].password
        )
    else:
        password = (
            native2026_archive_password(archive, parameters)
            if retry_password
            and (
                selection.cpu_type == "22"
                or selection.parameter.boolean("IGOffRetriableFlag")
            )
            else targets[target].password
        )

    count = native2026_cpu_count(metadata)
    next_type = (
        native2026_cpu_values(metadata, index + 1).get("cputype", "")
        if index + 1 < count
        else ""
    )
    return SolarContext2026(
        identity,
        selection,
        addresses[0],
        addresses[1],
        index,
        count,
        archive.data,
        archive.flash_size,
        archive.header,
        bytes.fromhex(metadata.cpu.values.get("locationid", "")),
        targets[target].password,
        password,
        retry_password,
        observations.get("retrying", False),
        next_type,
        observations.get("native_engine_cpu_type", ""),
        tuple(observations.get("counts", ())),
        tuple(observations.get("percentages", ())),
    )


def bind_solar_context(
    container, node, observed_cids, selection, identity, attachments, observations
):
    if identity.module_name != SOLAR:
        raise ValueError("Exact Solar writer identity required")
    return _bind_classic_write_context(
        container, node, observed_cids, selection, identity, attachments, observations
    )


def bind_powertrain_context(
    container, node, observed_cids, selection, identity, attachments, observations
):
    if identity.module_name != POWERTRAIN:
        raise ValueError("Exact PowerTrain writer identity required")
    return _bind_classic_write_context(
        container, node, observed_cids, selection, identity, attachments, observations
    )


def _solar_secondary_parameter(selection, cpu_type):
    kind = selection.metadata.vehicle.get("kindofecu", "")
    contact = selection.metadata.vehicle.get("contacttype", "")
    name = kind + contact + cpu_type + ".ini"
    if name not in selection.catalog_sources:
        raise CommonResponseError(9999)
    data = selection.catalog_sources[name]
    parameter = (
        NativeParameter2026.from_encoded(data)
        if selection.encoded
        else NativeParameter2026.from_csv(data)
    )
    if not parameter.set_keys(kind, cpu_type, contact):
        raise CommonResponseError(9999)
    return parameter


def _next_cpu_ig_flag(selection, next_cpu_type):
    general = NativeGeneralParameters2026.from_binding(selection)
    return general.boolean_with_keys(
        selection.metadata.vehicle.get("kindofecu", ""),
        next_cpu_type,
        selection.metadata.vehicle.get("contacttype", ""),
        "FlagToDoIGOFFONAtCPUTypeChange",
    )


def run_solar(
    context: SolarContext2026, runtime: NativeRuntime2026, *, notify=lambda *_: None
) -> dict:
    """Solar1170/182a/1c30/1c89; observers report native state, never success."""
    from scripts.programming_2026_common import (
        block_ranges_from_image,
        block_ranges_from_sizes,
        calc_block_sizes,
        check_block_ranges,
        check_cpu_type_from_firmware,
        native_block_info,
        select_retry_password,
    )
    from scripts.programming_2026_legacy import CommonFlash2026, writing_error_dispose

    if (
        not isinstance(context, SolarContext2026)
        or context.identity.module_name != SOLAR
        or not isinstance(runtime, NativeRuntime2026)
        or not callable(notify)
    ):
        raise TypeError("Bound Solar context/runtime and observer required")
    selection, parameter = context.selection, context.selection.parameter
    values = {key: selection.value(key) for key in selection.values}
    counts, percentages = (
        list(context.initial_counts or (0,) * context.cpu_count),
        list(context.initial_percentages or (0,) * context.cpu_count),
    )
    writer = CommonFlash2026(runtime)
    request, response = context.address.headers()
    finish, _ = context.finish_address.headers()
    external = parameter.boolean("ExternalMemoryFlag") or False
    sizes = calc_block_sizes(native_block_info(values))
    if parameter.boolean("ReadBlockRangeFromS0HeaderFlag"):
        ranges = block_ranges_from_image(context.header)
        check_block_ranges(context.flash_size, sizes, ranges)
    else:
        ranges = block_ranges_from_sizes(sizes)
    if not ranges:
        raise ValueError("Native Solar block geometry absent")
    saved_timeout, filter_id = None, None
    failure, error = None, 9999
    cleanup_errors = []
    completed = False
    flashing_ended = False
    non_retriable = False

    def observe(*event):
        runtime.check()
        notify(*event)
        runtime.check()

    def error_observer(value):
        # CUW59070 slot6 queues existing error fields; its argument is ignored.
        observe("error", value)

    def wait(name):
        runtime.call("wait", milliseconds=parameter.long(name) or 0)

    try:
        observe("flashing_ended", False)
        wait("WaitTimeAfterReprogrammingMode")
        saved_timeout = runtime.call("get_timeout")
        runtime.call(
            "set_timeout",
            milliseconds=parameter.long("ReceiveTimeoutBeforeFlashWrite") or 0,
        )
        filter_id = writer.diag.start_filter(request, response)
        writer.check_id_with_wait_of_sfs(
            request,
            response,
            context.location_id,
            context.new_password,
            parameter.long("WaitTimeBetweenSF") or 0,
            parameter.long("ReceiveTimeoutBeforeInitialCommand") or 0,
            _solar_secondary_parameter(selection, context.secondary_cpu_type).boolean(
                "BigEndianFlag"
            )
            or False,
        )
        wait("WaitTimeBetweenSF")
        memory, wide = writer.get_memory_info(request, response, external)
        if not check_cpu_type_from_firmware(memory.firmware_version, values, wide):
            raise CommonResponseError(10)
        no_verify = parameter.boolean("FlagToNonVerifyProcess") or False
        for position, (first, last) in enumerate(ranges):
            if position + 1 == len(ranges):
                non_retriable = True
                observe("non_retriable", True)
            writer.erase_block(request, response, first, last, parameter, wide)
            writer.write_block(
                request,
                response,
                context.cpu_index,
                first,
                last,
                sizes,
                memory,
                context.image,
                context.flash_size // 2 if no_verify else context.flash_size,
                parameter,
                counts,
                percentages,
                observe,
                error_observer,
                parameter.long("WaitTimeBetweenSF") or 0,
                external,
            )
            writer.in_verify_block(request, response, parameter, first, last, wide)
            if not no_verify:
                writer.verify_block(
                    request,
                    response,
                    context.cpu_index,
                    first,
                    last,
                    sizes,
                    context.image,
                    context.flash_size,
                    parameter,
                    counts,
                    percentages,
                    observe,
                    error_observer,
                    wide,
                )
        flashing_ended = True
        observe("flashing_ended", True)
        writer.finish_reprogramming(finish, response)
        wait("WaitTimeAfterEndOfFlashing")
        if context.cpu_index + 1 < context.cpu_count:
            change_ig = _next_cpu_ig_flag(selection, context.next_cpu_type)
            if not change_ig:
                observe("cpu_change_without_ig")
        non_retriable = False
        observe("non_retriable", False)
        observe("retry_password", False)
        observe("retrying", False)
        observe("write_complete_callback")
        completed = True
    except (
        CommonResponseError,
        NativeTransportError,
        VendorTransportError,
        NativePassThruException2026,
    ) as exc:
        failure = exc
        error = _native_error(exc)
        writing_error_dispose(
            context.cpu_index,
            counts,
            percentages,
            lambda field: observe(field, counts[:], percentages[:]),
        )
        observe("error_kind", 2)
    finally:
        with _preserve_active_host_error():
            try:
                if filter_id is not None:
                    try:
                        runtime.release("stop_filter", identifier=filter_id)
                    except (
                        CommonResponseError,
                        NativeTransportError,
                        VendorTransportError,
                        NativeException2026,
                    ) as exc:
                        cleanup_errors.append(
                            (
                                None
                                if type(exc) is NativeException2026
                                else _native_error(exc),
                                _driver_error(exc),
                            )
                        )
            finally:
                with _preserve_active_host_error():
                    if saved_timeout is not None:
                        runtime.call(
                            "set_timeout", cleanup=True, milliseconds=saved_timeout
                        )
    retry_password = (
        False
        if completed
        else select_retry_password(non_retriable, error, context.retry_password)
    )
    return {
        "native_return": completed,
        "native_success": None,
        "state": "write_completed" if completed else "write_failed",
        "programming_completed": completed,
        "flashing_ended": flashing_ended,
        "counts": tuple(counts),
        "percentages": tuple(percentages),
        "native_error_code": None if completed else error,
        "driver_error_code": _driver_error(failure),
        "retry_password": retry_password,
        "cleanup_failed": bool(cleanup_errors),
        "cleanup_errors": tuple(cleanup_errors),
    }


@dataclass(frozen=True)
class PowerTrainRetryContext2026:
    identity: NativeModuleIdentity
    address: NativeCommunicationAddress
    b32rv85_512k: bool
    previous_error: int
    wait_after_dummy_ms: int = 0

    def __post_init__(self):
        if (
            not isinstance(self.identity, NativeModuleIdentity)
            or self.identity != identify_native_module(self.identity.sha256, POWERTRAIN)
            or self.identity.cuw_build != "2026"
            or not isinstance(self.address, NativeCommunicationAddress)
            or self.address.extended
            or type(self.b32rv85_512k) is not bool
            or any(
                type(v) is not int or not 0 <= v <= 0xFFFFFFFF
                for v in (self.previous_error, self.wait_after_dummy_ms)
            )
        ):
            raise ValueError("Bound2026 PowerTrain retry context required")


def prepare_powertrain_retry(
    context: PowerTrainRetryContext2026, runtime: NativeRuntime2026
) -> dict:
    """PowerTrain2810: dummy drain by prior error13/15, repeat05/ACK until ready."""
    from scripts.programming_2026_legacy import CommonFlash2026

    if not isinstance(context, PowerTrainRetryContext2026) or not isinstance(
        runtime, NativeRuntime2026
    ):
        raise TypeError("Bound PowerTrain retry context and runtime required")
    writer = CommonFlash2026(runtime)
    request, response = context.address.headers()
    filter_id = writer.diag.start_filter(request, response)
    failure = None
    cleanup_errors = []
    attempts = 0
    try:
        if context.b32rv85_512k:
            runtime.call("wait", milliseconds=5000)
        else:
            while True:
                attempts += 1
                writer.diag.write(request + b"\x05")
                if writer.receive_ack(response):
                    break
                if context.previous_error not in (13, 15):
                    raise CommonResponseError(20)
                writer.diag.write(
                    request + bytes(1024 if context.previous_error == 13 else 256)
                )
                while True:
                    message = runtime.call(
                        "read_specified_can_message", address=response, frame=0, count=1
                    )
                    if (
                        type(message) is not bytes
                        or not message.startswith(response)
                        or not len(response) <= len(message) <= 4128
                    ):
                        raise ValueError(
                            "Bounded addressed native retry response required"
                        )
                    if len(message) == 5 and message[4] in (0x3C, 0xFF):
                        break
                runtime.call("wait", milliseconds=context.wait_after_dummy_ms)
    except (
        CommonResponseError,
        NativeTransportError,
        VendorTransportError,
        NativePassThruException2026,
    ) as exc:
        failure = exc
    finally:
        with _preserve_active_host_error():
            try:
                runtime.release("stop_filter", identifier=filter_id)
            except (
                CommonResponseError,
                NativeTransportError,
                VendorTransportError,
                NativeException2026,
            ) as exc:
                cleanup_errors.append(
                    (
                        None
                        if type(exc) is NativeException2026
                        else _native_error(exc),
                        _driver_error(exc),
                    )
                )
    return {
        "native_return": failure is None,
        "native_success": None,
        "state": "retry_prepared" if failure is None else "retry_prepare_failed",
        "programming_completed": False,
        "attempts": attempts,
        "cleanup_failed": bool(cleanup_errors),
        "cleanup_errors": tuple(cleanup_errors),
        "native_error_code": getattr(failure, "native_error_code", 1)
        if isinstance(failure, (NativeTransportError, VendorTransportError))
        else _native_error(failure)
        if failure
        else None,
        "driver_error_code": _driver_error(failure),
    }


def bind_powertrain_retry_context(
    container, node, observed_cids, selection, identity, attachments, observations
):
    if (
        not isinstance(selection, NativeParameterBinding2026)
        or selection.operation != "write"
        or selection.module_name != POWERTRAIN
        or attachments
        or set(observations) - {"cpu_index", "previous_error"}
    ):
        raise ValueError("Imported2026 PowerTrain retry selection required")
    selection.validate_against(
        container,
        operation="write",
        node=node,
        cpu_index=observations.get("cpu_index", 0),
    )
    metadata = selection.metadata
    success, addresses = communication_addresses_from_parameter(
        container, selection.parameter
    ).resolve(
        selection.selector_functions,
        cids=observed_cids,
        location_id=metadata.cpu.values.get("locationid") or None,
    )
    if not success or not addresses:
        raise ValueError("Native PowerTrain retry programming address absent")
    return PowerTrainRetryContext2026(
        identity,
        addresses[0],
        selection.cpu_type == "22",
        observations.get("previous_error", 9999),
        selection.parameter.long("WaitTimeAfterSendDummyData") or 0,
    )


def run_powertrain(
    context: SolarContext2026, runtime: NativeRuntime2026, *, notify=lambda *_: None
) -> dict:
    """PowerTrain1290: imported perCPU geometry, exact shared CommonFlash calls."""
    from scripts.programming_2026_common import (
        block_ranges_from_info,
        calc_block_sizes,
        check_cpu_type_from_firmware,
        complete_block_info,
        native_block_info,
        select_retry_password,
    )
    from scripts.programming_2026_legacy import CommonFlash2026, writing_error_dispose

    if (
        not isinstance(context, SolarContext2026)
        or context.identity.module_name != POWERTRAIN
        or not isinstance(runtime, NativeRuntime2026)
        or not callable(notify)
    ):
        raise TypeError("Bound PowerTrain context/runtime and observer required")
    selection, parameter = context.selection, context.selection.parameter
    runtime_metadata = selection.metadata
    cpu_type_updates = {}
    request, response = context.address.headers()
    finish, _ = context.finish_address.headers()
    counts, percentages = (
        list(context.initial_counts or (0,) * context.cpu_count),
        list(context.initial_percentages or (0,) * context.cpu_count),
    )
    writer = CommonFlash2026(runtime)
    failure = None
    cleanup_errors = []
    error = 9999
    non_retriable, completed, flashing_ended = False, False, False
    initial_timeout = runtime.call("get_timeout")
    filter_id = None

    def observe(*event):
        runtime.check()
        notify(*event)
        runtime.check()

    def error_observer(value):
        # CUW59070 slot6 queues existing error fields; its argument is ignored.
        observe("error", value)

    def runtime_cpu_type():
        from scripts.calibration_2026 import (
            native2026_cpu_type,
            native2026_global_cpu_index,
        )

        return native2026_cpu_type(
            runtime_metadata, native2026_global_cpu_index(runtime_metadata)
        )

    def values():
        return {key: selection.value(key) for key in selection.values}

    try:
        if selection.cpu_type == "22":
            runtime.call("wait", milliseconds=2000)
        filter_id = writer.diag.start_filter(request, response)
        if not context.retrying and selection.cpu_type == "22":
            writer.change_next_cpu(request, response)
        if (
            not context.retrying
            or parameter.boolean("IGOffRetriableFlag")
            or selection.cpu_type == "22"
        ):
            runtime.call(
                "wait",
                milliseconds=parameter.long("WaitTimeAfterReprogrammingMode") or 0,
            )
            writer.check_id_with_wait_of_sfs(
                request,
                response,
                context.location_id,
                context.new_password,
                parameter.long("WaitTimeBetweenSF") or 0,
                parameter.long("ReceiveTimeoutBeforeInitialCommand") or 0,
                parameter.boolean("BigEndianFlag") or False,
            )
            if parameter.boolean("FlagToResetProcessAfterCheckProgramID"):
                writer.diag.write(request + b"\x05")
                if not writer.receive_ack(response):
                    raise CommonResponseError(40)
        shrink = parameter.boolean("ShrinkFlag") or False
        memory = None
        if parameter.boolean("32BHFlag"):
            memory, actual_shrink = writer.get_memory_info(request, response)
            if actual_shrink != shrink:
                from scripts.calibration_2026 import (
                    native2026_global_cpu_index,
                    native2026_with_cpu_type,
                )

                changed_cpu = native2026_global_cpu_index(runtime_metadata)
                alternate = parameter.string("AlternateCPUType") or ""
                runtime_metadata = native2026_with_cpu_type(
                    runtime_metadata, changed_cpu, alternate
                )
                cpu_type_updates[str(changed_cpu)] = alternate
                try:
                    selection = selection.reselect_alternate_cpu()
                except (ValueError, LookupError) as exc:
                    raise CommonResponseError(10) from exc
                parameter = selection.parameter
            shrink = actual_shrink
        runtime.call(
            "set_timeout",
            milliseconds=parameter.long("ReceiveTimeoutBeforeFlashWrite") or 0,
        )
        if memory is None or not any(
            (
                memory.start_address,
                memory.end_address,
                memory.block_size_kib,
                memory.firmware_version,
            )
        ):
            memory, shrink = writer.get_memory_info(request, response)
        if not check_cpu_type_from_firmware(memory.firmware_version, values(), shrink):
            try:
                selection = selection.reselect_alternate_cpu()
            except (ValueError, LookupError) as exc:
                raise CommonResponseError(10) from exc
            parameter = selection.parameter
            if not check_cpu_type_from_firmware(
                memory.firmware_version, values(), shrink
            ):
                raise CommonResponseError(10)
        observe("programming_started", True)
        blocks = complete_block_info(native_block_info(values()), memory)
        sizes = calc_block_sizes(blocks)
        ranges = block_ranges_from_info(blocks)
        if not ranges:
            raise ValueError("Native PowerTrain programming geometry absent")
        # Native erase inserts zero slots before a non-one first block index.
        if ranges[0][0] != 1:
            sizes = (0,) * (ranges[0][0] - 1) + sizes
        for position, (first, last) in enumerate(ranges):
            if runtime_cpu_type() == "22" or not writer.check_block(
                request, response, parameter, first, last, shrink
            ):
                writer.erase_block(request, response, first, last, parameter, shrink)
            if shrink and position + 1 == len(ranges):
                non_retriable = True
                observe("non_retriable", True)
            writer.write_block(
                request,
                response,
                context.cpu_index,
                first,
                last,
                sizes,
                memory,
                context.image,
                context.flash_size,
                parameter,
                counts,
                percentages,
                observe,
                error_observer,
            )
            if not parameter.boolean("FlagToNonInVerifyProcess"):
                writer.in_verify_block(
                    request, response, parameter, first, last, shrink
                )
            writer.verify_block(
                request,
                response,
                context.cpu_index,
                first,
                last,
                sizes,
                context.image,
                context.flash_size,
                parameter,
                counts,
                percentages,
                observe,
                error_observer,
                shrink,
            )
        observe("retry_password", False)
        change_ig = (
            _next_cpu_ig_flag(selection, context.next_cpu_type)
            if context.cpu_index + 1 < context.cpu_count
            else True
        )

        if context.cpu_index + 1 < context.cpu_count and not change_ig:
            try:
                writer.change_next_cpu(request, response)
            finally:
                with _preserve_active_host_error():
                    observe("cpu_change_without_ig")
                    observe("programming_started", False)
                    non_retriable = False
                    observe("non_retriable", False)
        if change_ig or context.cpu_index + 1 == context.cpu_count:
            flashing_ended = True
            observe("flashing_ended", True)
            from scripts.calibration_2026 import (
                native2026_cpu_count,
                native2026_cpu_type,
            )

            general = NativeGeneralParameters2026.from_binding(selection)
            receive = any(
                general.boolean_with_keys(
                    runtime_metadata.vehicle.get("kindofecu", ""),
                    native2026_cpu_type(runtime_metadata, index),
                    runtime_metadata.vehicle.get("contacttype", ""),
                    "FlagToReceiveRespForFinish",
                )
                for index in range(native2026_cpu_count(runtime_metadata))
            )
            writer.finish_reprogramming(finish, response if receive else None)
        observe("programming_started", False)
        completed = True
    except (
        CommonResponseError,
        NativeTransportError,
        VendorTransportError,
        NativePassThruException2026,
    ) as exc:
        failure = exc
        error = _native_error(exc)
        writing_error_dispose(
            context.cpu_index,
            counts,
            percentages,
            lambda field: observe(field, counts[:], percentages[:]),
        )
        observe("error_kind", 2)
    finally:
        with _preserve_active_host_error():
            try:
                if filter_id is not None:
                    try:
                        runtime.release("stop_filter", identifier=filter_id)
                    except (
                        CommonResponseError,
                        NativeTransportError,
                        VendorTransportError,
                        NativeException2026,
                    ) as exc:
                        cleanup_errors.append(
                            (
                                None
                                if type(exc) is NativeException2026
                                else _native_error(exc),
                                _driver_error(exc),
                            )
                        )
            finally:
                with _preserve_active_host_error():
                    runtime.call(
                        "set_timeout", cleanup=True, milliseconds=initial_timeout
                    )
    return {
        "native_return": completed,
        "native_success": None,
        "state": "write_completed" if completed else "write_failed",
        "programming_completed": completed,
        "flashing_ended": flashing_ended,
        "counts": tuple(counts),
        "percentages": tuple(percentages),
        "native_error_code": None if completed else error,
        "driver_error_code": _driver_error(failure),
        "retry_password": False
        if completed
        else select_retry_password(non_retriable, error, context.retry_password),
        "cleanup_failed": bool(cleanup_errors),
        "cleanup_errors": tuple(cleanup_errors),
        "selected_parameter_cpu_type": selection.cpu_type,
        "cpu_type_updates": cpu_type_updates,
    }


def reprostd_download_request2026(
    address: int | bytes, size: int | bytes, selector: int = 1
) -> bytes:
    """Actual2810 copies original CBytes into zeroed, fixed-width wire slots."""
    if type(selector) is not int or selector not in (1, 0x21, 0x11):
        raise ValueError("Native ReproStd selector required")
    encoded = []
    for value, maximum in ((address, 0xFFFFFFFF), (size, 64 * 1024 * 1024)):
        if type(value) is int and 0 <= value <= maximum:
            encoded.append(value.to_bytes(4, "big"))
        elif type(value) is bytes and len(value) <= 512:
            encoded.append(value)
        else:
            raise ValueError("Native bounded CBytes or uint32 geometry required")
    if type(address) is int and type(size) is int and address + size > 0x100000000:
        raise ValueError("Host ReproStd geometry exceeds uint32 address space")
    request = bytearray(b"\x34" + bytes((selector, 0x44)) + bytes(8))
    request[3 : 3 + len(encoded[0])] = encoded[0]
    request[7 : 7 + len(encoded[1])] = encoded[1]
    return bytes(request[:11])


def reprostd_block_size2026(response: bytes) -> int:
    """Native2810 reads the declared width from its zeroed response buffer."""
    if type(response) is not bytes or len(response) < 3 or response[0] != 0x74:
        raise ValueError("Native positive RequestDownload response required")
    width = response[1] >> 4
    maximum = min(
        int.from_bytes(response[2 : 2 + width].ljust(width, b"\0"), "big"), 0xFFF
    )
    if maximum < 3:
        raise ValueError("Native download maximum cannot contain data")
    return maximum - 2


def reprostd_routine_request2026(
    operation: str,
    address: int | bytes,
    size: int | bytes,
    *,
    checksum: bytes | None = None,
    signature: bytes | None = None,
    signature_width: int = 16,
) -> tuple[bytes, bytes]:
    """Actual2b60 native zeroed buffer, ordered CBytes copies and fixed DataSize."""
    identifiers = {
        "routine_check": b"\x10\xf5",
        "erase": b"\xff\x00",
        "verify": b"\x10\xf6",
    }
    if (
        operation not in identifiers
        or type(signature_width) is not int
        or signature_width not in (16, 256)
    ):
        raise ValueError("Native routine operation and selected spec width required")
    # Validate both raw CBytes without normalizing their original widths.
    reprostd_download_request2026(address, size)
    encoded_address = (
        address if isinstance(address, bytes) else address.to_bytes(4, "big")
    )
    encoded_size = size if isinstance(size, bytes) else size.to_bytes(4, "big")
    request = bytearray(4123)
    request[:5] = b"\x31\x01" + identifiers[operation] + b"\x44"
    request[5 : 5 + len(encoded_address)] = encoded_address
    request[9 : 9 + len(encoded_size)] = encoded_size
    length = 13
    if operation != "erase":
        if checksum is not None and (
            type(checksum) is not bytes or len(checksum) > 512
        ):
            raise ValueError("Native bounded CRC CBytes required")
        if type(signature) is not bytes or len(signature) > 512:
            raise ValueError("Native bounded signature CBytes required")
        request[13] = 4 if checksum else 0
        if checksum:
            request[14 : 14 + len(checksum)] = checksum
        else:
            request[14:18] = bytes.fromhex("ffffffff")
        request[18:20] = signature_width.to_bytes(2, "big")
        request[20 : 20 + len(signature)] = signature
        length = 20 + signature_width
    elif checksum is not None or signature is not None:
        raise ValueError("Native erase has no checksum/signature inputs")
    return bytes(request[:length]), b"\x71\x01" + identifiers[operation]


class ReproStd2026:
    """ReproStdFlashWriter2810/2a80/2b60/3180/3420/3560, literal phase5 CAN."""

    def __init__(
        self,
        runtime: NativeRuntime2026,
        address: NativeCommunicationAddress,
        pending_limit: int = 180,
    ):
        if (
            not isinstance(runtime, NativeRuntime2026)
            or not isinstance(address, NativeCommunicationAddress)
            or type(pending_limit) is not int
            or not 0 <= pending_limit <= 0xFFFFFFFF
        ):
            raise ValueError("Bound native ReproStd communication context required")
        self.runtime = runtime
        self.diag = CanDiag2026(runtime)
        self.request, self.response = address.headers()
        self.pending_limit = pending_limit

    def send(self, payload, expected, error, minimum=0):
        return self.diag.call(
            self.request,
            self.response,
            payload,
            expected,
            error_code=error,
            minimum=minimum or len(expected),
            phase5=True,
            pending_limit=self.pending_limit,
            busy_limit=0x159A,
        )

    def fingerprint(
        self, slot: int, nonce: bytes, tester_info: bytes, system_time: tuple
    ):
        from scripts.programming import reprostd_fingerprint_requests

        # Exact2026 3560 agrees with the older pure builder; wire calls stay2026.
        for (request, response), error in zip(
            reprostd_fingerprint_requests(slot, nonce, tester_info, system_time),
            (71, 84, 85),
            strict=True,
        ):
            self.send(request, response, error)

    def transfer(
        self,
        address: int,
        declared_size: int,
        data: bytes,
        method: int,
        *,
        progress=lambda _count: None,
        source_address: bytes | None = None,
        source_length: bytes | None = None,
    ):
        if (
            type(data) is not bytes
            or not 0 <= len(data) <= 64 * 1024 * 1024
            or method not in (0, 1, 2, 3)
            or not callable(progress)
        ):
            raise ValueError("Native materialized ReproStd image and method required")
        selector = {0: 1, 1: 1, 2: 0x21, 3: 0x11}[method]
        request = reprostd_download_request2026(
            address if source_address is None else source_address,
            declared_size if source_length is None else source_length,
            selector,
        )
        prior = self.runtime.call("get_send_timeout")
        if type(prior) is not int or not 0 <= prior <= 0xFFFFFFFF:
            raise ValueError("Native send timeout must be unsigned milliseconds")
        reply = self.send(request, b"\x74", 26, 3)
        try:
            chunk = reprostd_block_size2026(reply)
        except ValueError as exc:
            raise CommonResponseError(26, reply) from exc
        frames = (chunk + 2 + (7 if len(self.request) == 4 else 6) - 1) // (
            7 if len(self.request) == 4 else 6
        )
        try:
            self.runtime.call("set_send_timeout", milliseconds=frames * 161 + 1000)
            cursor, sequence = 0, 1
            while cursor < len(data):
                part = data[cursor : cursor + chunk]
                counter = bytes((sequence & 255,))
                self.send(b"\x36" + counter + part, b"\x76" + counter, 34)
                cursor += len(part)
                self.runtime.check()
                progress(len(part))
                self.runtime.check()
                sequence += 1
        finally:
            with _preserve_active_host_error():
                self.runtime.call("set_send_timeout", cleanup=True, milliseconds=prior)
        self.send(b"\x37", b"\x77", 28)
        return len(data)

    def routine(self, operation: int, area, required_spec: str):
        from scripts.calibration_2026 import NativeLogicalArea2026

        if operation not in (0, 1, 2) or not isinstance(area, NativeLogicalArea2026):
            raise ValueError("Imported native ReproStd routine metadata required")
        name, error = {0: ("routine_check", 86), 1: ("erase", 69), 2: ("verify", 77)}[
            operation
        ]
        signature = (
            None
            if operation == 1
            else area.cmac
            if required_spec == "03"
            else area.digital_signature
        )
        request, expected = reprostd_routine_request2026(
            name,
            area.address_bytes,
            bytes.fromhex(area.values.get("length", "")),
            checksum=None if operation == 1 else area.crc,
            signature=signature,
            signature_width=16 if required_spec == "03" else 256,
        )
        self.send(request, expected, error)


def execute_context(context, runtime: NativeRuntime2026) -> dict:
    if isinstance(context, SoftwareInfoContext2026):
        return run_software_info(context, runtime)
    if isinstance(context, PowerTrainRetryContext2026):
        return prepare_powertrain_retry(context, runtime)
    if isinstance(context, ReproStdContext2026):
        from scripts.programming_2026_dh import DHGateway2026
        from scripts.programming_2026_suzuki_fhi import SuzukiUtils2026

        dh_gateway = None
        if context.dh_identity is not None:
            if context.secret_info is None:
                raise ValueError(
                    "Native DH gateway requires original private security binding"
                )
            dh_gateway = DHGateway2026(
                runtime, context.selection, context.dh_identity, context.secret_info
            )
        suzuki = (
            SuzukiUtils2026(
                context.suzuki_identity,
                runtime,
                container=context.selection.metadata.source_container,
                parameters=context.selection.parameter,
            )
            if context.suzuki_identity is not None
            else None
        )
        if context.identity.module_name == REPRO_WRITE:
            return run_repro_write(context, runtime, dh_gateway=dh_gateway)
        return run_repro_prepare(
            context,
            runtime,
            secret_info=context.secret_info,
            gateway_node=context.repro_gateway_node,
            dh_gateway=dh_gateway,
            suzuki=suzuki,
        )
    if isinstance(context, SolarContext2026):
        return (
            run_solar(context, runtime)
            if context.identity.module_name == SOLAR
            else run_powertrain(context, runtime)
        )
    raise TypeError("Bound source-identified generic2026 context required")


@dataclass(frozen=True)
class ReproStdContext2026:
    identity: NativeModuleIdentity
    selection: NativeParameterBinding2026
    addresses: tuple[NativeCommunicationAddress, ...]
    tester_info: bytes = b""
    gateway_type: int = 0
    secret_info: SecretInfoClient | None = field(default=None, repr=False)
    dh_identity: NativeModuleIdentity | None = None
    suzuki_identity: NativeModuleIdentity | None = None
    repro_gateway_node: int = 0
    native_retry_flag_964: bool = False

    def __post_init__(self):
        for dependency, name in (
            (self.dh_identity, "TCUWDHUtils.dll"),
            (self.suzuki_identity, "TCUWCanSuzukiUDSUtils.dll"),
        ):
            if dependency is not None and (
                not isinstance(dependency, NativeModuleIdentity)
                or dependency != identify_native_module(dependency.sha256, name)
                or dependency.cuw_build != "2026"
            ):
                raise ValueError("Exact2026 gateway utility identity required")
        if (
            not isinstance(self.identity, NativeModuleIdentity)
            or self.identity.module_name not in (REPRO_PREPARE, REPRO_WRITE)
            or self.identity
            != identify_native_module(self.identity.sha256, self.identity.module_name)
            or self.identity.cuw_build != "2026"
            or not isinstance(self.selection, NativeParameterBinding2026)
            or self.selection.module_name != self.identity.module_name
            or self.selection.operation
            != ("prepare" if self.identity.module_name == REPRO_PREPARE else "write")
            or type(self.addresses) is not tuple
            or not self.addresses
            or any(
                not isinstance(v, NativeCommunicationAddress) for v in self.addresses
            )
            or self.secret_info is not None
            and not isinstance(self.secret_info, SecretInfoClient)
            or type(self.tester_info) is not bytes
            or len(self.tester_info) not in (0, 32)
            or type(self.gateway_type) is not int
            or self.gateway_type not in (0, 1, 2)
            or type(self.repro_gateway_node) is not int
            or self.repro_gateway_node not in (0, 1, 2)
            or type(self.native_retry_flag_964) is not bool
        ):
            raise ValueError("Bound actual2026 ReproStd metadata/context required")


def bind_repro_context(
    container, node, observed_cids, selection, identity, attachments, observations
):
    if (
        not isinstance(selection, NativeParameterBinding2026)
        or identity.module_name not in (REPRO_WRITE, REPRO_PREPARE)
        or set(attachments)
        - {"tester_info", "secret_info", "cuw_engine", "dh_utils", "suzuki_utils"}
        or set(observations)
        - {"gateway_type", "repro_gateway_node", "native_retry_flag_964"}
    ):
        raise ValueError(
            "Exact imported ReproStd metadata and tester observation required"
        )
    selection.validate_against(
        container, operation=selection.operation, node=node, cpu_index=0
    )
    success, addresses = communication_addresses_from_parameter(
        container, selection.parameter
    ).resolve(selection.selector_functions, cids=observed_cids, location_id=None)
    if not success or not addresses:
        raise ValueError("Native ReproStd address selector failed")
    tester_info = attachments.get("tester_info", b"")
    if identity.module_name == REPRO_WRITE and len(tester_info) != 32:
        raise ValueError(
            "Original engine tester-info bytes required for fingerprint records"
        )
    secret_info = None
    if "secret_info" in attachments or "cuw_engine" in attachments:
        if "secret_info" not in attachments or "cuw_engine" not in attachments:
            raise ValueError(
                "Both original SecretInfo and CUW engine caller bytes required"
            )
        secret_info = SecretInfoClient.from_native_modules(
            attachments["secret_info"], attachments["cuw_engine"]
        )
    auxiliary = []
    for key, name in (
        ("dh_utils", "TCUWDHUtils.dll"),
        ("suzuki_utils", "TCUWCanSuzukiUDSUtils.dll"),
    ):
        data = attachments.get(key)
        if data is None:
            auxiliary.append(None)
            continue
        if type(data) is not bytes or not 0 < len(data) <= 64 * 1024 * 1024:
            raise ValueError("Bound immutable native gateway utility module required")
        dependency = identify_native_module(hashlib.sha256(data).hexdigest(), name)
        if dependency.cuw_build != "2026":
            raise ValueError("Gateway dependency belongs to another native build")
        auxiliary.append(dependency)
    return ReproStdContext2026(
        identity,
        selection,
        addresses,
        tester_info,
        observations.get("gateway_type", 0),
        secret_info,
        *auxiliary,
        repro_gateway_node=observations.get("repro_gateway_node", 0),
        native_retry_flag_964=observations.get("native_retry_flag_964", False),
    )


def run_repro_write(
    context: ReproStdContext2026,
    runtime: NativeRuntime2026,
    *,
    notify=lambda *_: None,
    dh_gateway=None,
) -> dict:
    """Actual ReproStd1b40 virtual dispatch and native logical archive order."""
    from scripts.calibration_2026 import (
        native2026_logical_archive,
        native2026_logical_cpu_flash_size,
    )
    from scripts.programming_2026_common import Unified2026, make_send_data_records
    from scripts.programming_2026_dh import (
        DHGateway2026,
        central_gateway_request_can_id,
    )

    if (
        not isinstance(context, ReproStdContext2026)
        or context.identity.module_name != REPRO_WRITE
        or not isinstance(runtime, NativeRuntime2026)
        or not callable(notify)
    ):
        raise TypeError("Bound ReproStd writer/runtime and observer required")
    metadata = context.selection.metadata
    blocks = tuple(
        block for block in metadata.logical_blocks if block.node == metadata.node
    )
    if not blocks or len(blocks) > 32 or len(context.tester_info) != 32:
        raise ValueError("Native logical blocks/tester identity required")
    if len(context.addresses) < metadata.node:
        raise ValueError("Native ReproStd node address vector is incomplete")
    address = context.addresses[metadata.node - 1]
    channel = ReproStd2026(runtime, address)
    unified = Unified2026(runtime)
    gateways = metadata.gateway_values
    dh = bool(
        gateways
        and gateways[0]["gatewaydiagid"]
        and bytes.fromhex(gateways[0]["gatewaydiagid"])
        == central_gateway_request_can_id()
    )

    if dh and (
        not isinstance(dh_gateway, DHGateway2026) or dh_gateway.runtime is not runtime
    ):
        raise ValueError("Concrete source-bound DH gateway context required")
    totals, sent, counts, percentages = {}, {}, {}, {}
    failure = None
    non_retriable = False
    for block in blocks:
        for area in block.areas:
            if (
                area.record is not None
                and native2026_logical_archive(metadata, block, area.kind).streamed
            ):
                raise ValueError(
                    "Native ReproStd3180 has no source-backed stream reader for descriptor archives"
                )
    native_exit = False
    cleanup_errors = []
    first = blocks[0]

    def area_for(block, kind, required=True):
        area = next((item for item in block.areas if item.kind == kind), None)
        if area is None and required:
            raise ValueError("Native ReproStd logical area absent: " + kind)
        return area

    def routine_kind(block):
        return {
            1: "EraseAndReproRoutine",
            2: "DeltaEraseAndReproRoutine",
            3: "CompressionEraseAndReproRoutine",
        }.get(block.repro_method_type, "")

    def image_kind(block):
        if block.repro_method in ("02", "03"):
            return "DeltaOrCompressionReproData"
        return {1: "ReproData", 2: "DeltaReproData", 3: "CompressionReproData"}.get(
            block.repro_method_type, "ReproData"
        )

    def archive_data(block, area):
        if area.length == 0:
            return b""
        archive = native2026_logical_archive(metadata, block, area.kind)
        if archive.streamed:
            raise ValueError(
                "Native streamed ReproStd archive requires its stream reader"
            )
        if archive.data is not None:
            return archive.data
        return make_send_data_records(archive.kind_records, area.address, area.length)

    first_routine = area_for(first, routine_kind(first), False)
    first_stub = first_routine.length if first_routine else 0
    for block in blocks:
        routine = area_for(block, routine_kind(block), False)
        image = area_for(block, image_kind(block), False)
        total = routine.length if routine else 0
        total += (
            image.length
            if image and block.repro_method_type == 1
            else len(archive_data(block, image))
            if image
            else 0
        )
        totals[block.cpu_index] = (totals.get(block.cpu_index, 0) + total) & 0xFFFFFFFF
        sent[block.cpu_index] = counts[block.cpu_index] = percentages[
            block.cpu_index
        ] = 0
    from scripts.programming import reprostd_fingerprint_requests

    # Validate imported fixed-width metadata before the first programming I/O.
    for block in blocks:
        reprostd_fingerprint_requests(
            block.did_subtype,
            block.nonce,
            context.tester_info,
            (2026, 10, 2, 20, 0, 0, 0, 0),
        )
        selected_areas = []
        if block.repro_method in ("01", "07", "09"):
            routine = area_for(block, routine_kind(block))
            selected_areas.append((routine, (0,)))
        image = area_for(block, image_kind(block), block.repro_method_type != 2)
        if image is not None and (block.repro_method_type != 2 or image.length):
            selected_areas.append(
                (image, (2,) if block.repro_method_type == 2 else (1, 2))
            )
        for area, operations in selected_areas:
            if area is None:
                raise ValueError("Native logical area is absent")
            reprostd_download_request2026(
                area.address_bytes, bytes.fromhex(area.values.get("length", ""))
            )
            if area.length and not archive_data(block, area):
                raise ValueError(
                    "Native nonzero logical archive contains no transmission bytes"
                )
            for operation in operations:
                signature = (
                    None
                    if operation == 1
                    else area.cmac
                    if block.required_spec == "03"
                    else area.digital_signature
                )
                reprostd_routine_request2026(
                    {0: "routine_check", 1: "erase", 2: "verify"}[operation],
                    area.address_bytes,
                    bytes.fromhex(area.values.get("length", "")),
                    checksum=None if operation == 1 else area.crc,
                    signature=signature,
                    signature_width=16 if block.required_spec == "03" else 256,
                )
    filter_id = channel.diag.start_filter(channel.request, channel.response)

    def observe(*event):
        runtime.check()
        notify(*event)
        runtime.check()

    try:
        for index, block in enumerate(blocks):
            observe("logical_block", index)
            channel.pending_limit = block.routine_response_pending_limit
            now = runtime.call("get_system_time")
            if type(now) is not tuple:
                raise ValueError("Native SYSTEMTIME tuple required")
            channel.fingerprint(
                block.did_subtype, block.nonce, context.tester_info, now
            )

            def progress(size, block=block, index=index):
                cpu = block.cpu_index
                sent[cpu] = (sent[cpu] + size) & 0xFFFFFFFF
                total = totals[cpu]
                if total == 0:
                    raise ValueError("Native ReproStd progress denominator is zero")
                if index or sent[cpu] > first_stub:
                    counts[cpu] = int(
                        sent[cpu]
                        / total
                        * native2026_logical_cpu_flash_size(metadata, cpu)
                    )
                    denominator = total if index else total - first_stub
                    if denominator == 0:
                        raise ValueError(
                            "Native ReproStd post-stub progress denominator is zero"
                        )
                    percentages[cpu] = int(
                        (sent[cpu] if index else sent[cpu] - first_stub)
                        / denominator
                        * 100
                    )
                    observe("count", cpu, counts[cpu])
                    observe("percent", cpu, percentages[cpu])

            if block.repro_method in ("01", "07", "09"):
                routine = area_for(block, routine_kind(block))
                assert routine is not None
                channel.transfer(
                    routine.address,
                    routine.length,
                    archive_data(block, routine),
                    0,
                    source_address=routine.address_bytes,
                    source_length=bytes.fromhex(routine.values.get("length", "")),
                    progress=progress,
                )
                channel.routine(0, routine, block.required_spec)
            non_retriable = True
            observe("non_retriable", True)
            image = area_for(block, image_kind(block), block.repro_method_type != 2)
            if block.repro_method_type == 2:
                if image is not None and image.length:
                    channel.transfer(
                        image.address,
                        image.length,
                        archive_data(block, image),
                        2,
                        source_address=image.address_bytes,
                        source_length=bytes.fromhex(image.values.get("length", "")),
                        progress=progress,
                    )
                    channel.routine(2, image, block.required_spec)
            else:
                assert image is not None
                channel.routine(1, image, block.required_spec)
                channel.transfer(
                    image.address,
                    image.length,
                    archive_data(block, image),
                    3 if block.repro_method_type == 3 else 1,
                    source_address=image.address_bytes,
                    source_length=bytes.fromhex(image.values.get("length", "")),
                    progress=progress,
                )
                channel.routine(2, image, block.required_spec)
            if (
                index + 1 < len(blocks)
                and block.cpu_index != blocks[index + 1].cpu_index
            ):
                observe("cpu_change_without_ig")
        channel.pending_limit = 180
        channel.send(b"\x11\x01", b"\x51\x01", 24)
        flow = metadata.node_values.get("chargelocalbusecureprogrammingflow", "")
        if flow == "01":
            request = bytes.fromhex(
                metadata.node_values.get(
                    "chargelocalbuspoweroncontrollingecudiagid", ""
                )
            )
            if len(request) != 2:
                raise ValueError("Native charge-bus diagnostic ID must have two bytes")
            response = request[:1] + bytes(((request[1] + 8) & 255,))
            unified.routine_charge_local_bus(
                b"\0\0" + request,
                b"\0\0" + response,
                1,
                start_filter=channel.request != b"\0\0" + request,
            )
        elif flow == "02":
            unified.routine_charge_local_bus_phase6(1)
        if runtime.owns_resource("stop_sync_periodic"):
            runtime.release("stop_sync_periodic")
        else:
            runtime.call("stop_sync_periodic")
        channel.diag.write(bytes.fromhex("000007771081"))
        channel.diag.write(bytes.fromhex("0000077ffe1081"), 0x80)
        channel.diag.write(bytes.fromhex("18dbefe01081"), 0x100)
        if gateways and gateways[0]["gatewaydiagid"] == "0751":
            smc_request, smc_response = (
                bytes.fromhex("00000751"),
                bytes.fromhex("00000761"),
            )
            smc_filter = channel.diag.start_filter(smc_request, smc_response)
            try:
                channel.diag.call(
                    smc_request,
                    smc_response,
                    b"\x10\x01",
                    b"\x50\x01",
                    minimum=6,
                    error_code=1017,
                    phase5=True,
                    pending_limit=180,
                    busy_limit=0x159A,
                )
            finally:
                with _preserve_active_host_error():
                    runtime.release("stop_filter", identifier=smc_filter)
        # Native EH259d/261f suppress only this end-of-gateway scope.
        try:
            if dh:
                assert isinstance(dh_gateway, DHGateway2026)
                dh_gateway.end_reprogramming_mode_for_multi_types(context.gateway_type)
            elif gateways and gateways[0]["gatewaydiagid"] == "0751":
                if unified.read_programming_mode_control_state() != 0:
                    unified.routine_smc_gateway(4)
        except (
            CommonResponseError,
            NativeTransportError,
            VendorTransportError,
            NativeException2026,
        ):
            pass
        non_retriable = False
        observe("non_retriable", False)
        native_exit = True
    except (
        CommonResponseError,
        NativeTransportError,
        VendorTransportError,
        NativePassThruException2026,
    ) as exc:
        failure = exc
        native_exit = True
    finally:
        with _preserve_active_host_error():
            try:
                runtime.release("stop_filter", identifier=filter_id)
            except (
                CommonResponseError,
                NativeTransportError,
                VendorTransportError,
                NativePassThruException2026,
            ) as exc:
                # Native EH26e2 preserves the stored BOOL; runtime retains ownership.
                cleanup_errors.append(
                    (
                        None
                        if type(exc) is NativeException2026
                        else _native_error(exc),
                        _driver_error(exc),
                    )
                )
    if native_exit:
        if failure is not None:
            runtime.call("set_history_enabled", cleanup=True, enabled=False)
        try:
            if context.repro_gateway_node == 2:
                unified.central_gateway_session()
        finally:
            with _preserve_active_host_error():
                runtime.call("set_history_enabled", cleanup=True, enabled=True)
        if failure is not None:
            for cpu in counts:
                counts[cpu] = percentages[cpu] = 0
            observe("count", tuple(sorted(counts.items())))
            observe("percent", tuple(sorted(percentages.items())))
            if runtime.owns_resource("stop_sync_periodic"):
                runtime.release("stop_sync_periodic")
            else:
                runtime.call("stop_sync_periodic", cleanup=True)
    return {
        "native_return": failure is None,
        "native_success": None,
        "state": "write_completed" if failure is None else "write_failed",
        "programming_completed": failure is None,
        "counts": tuple(sorted(counts.items())),
        "percentages": tuple(sorted(percentages.items())),
        "non_retriable": non_retriable,
        "cleanup_failed": bool(cleanup_errors),
        "cleanup_errors": tuple(cleanup_errors),
        "error_kind": (2 if non_retriable else 1) if failure is not None else None,
        "recovery_needed": failure is not None and not non_retriable,
        "native_error_code": _native_error(failure) if failure else None,
        "driver_error_code": _driver_error(failure),
    }


class ReproPrepare2026:
    """ReproStdPrepare vtable slots0..5 and tester-present broadcast families."""

    def __init__(
        self,
        context: ReproStdContext2026,
        runtime: NativeRuntime2026,
        *,
        gateway_node: int = 0,
        dh_gateway=None,
        suzuki=None,
    ):
        from scripts.programming_2026_common import Unified2026

        self.context, self.runtime = context, runtime
        self.metadata = context.selection.metadata
        self.diag = CanDiag2026(runtime)
        self.unified = Unified2026(runtime)
        self.gateway_node = gateway_node
        self.dh_gateway, self.suzuki = dh_gateway, suzuki
        self.dh_gateway_type = context.gateway_type
        self.gateways = self.metadata.gateway_values
        self.first_gateway = (
            self.gateways[0]["gatewaydiagid"].upper() if self.gateways else ""
        )
        self.emissions = self.metadata.emissions_delay_ms

    def wait(self, milliseconds):
        self.runtime.call("wait", milliseconds=milliseconds)

    def write(self, data, flags=0, *, locked=False):
        if locked:
            self.runtime.call("lock")
        try:
            self.diag.write(data, flags)
        finally:
            with _preserve_active_host_error():
                if locked:
                    self.runtime.call("unlock", cleanup=True)

    def frames(self, repro_gw=False):
        frames = [
            (bytes.fromhex("000007773e80"), 0),
            (bytes.fromhex("0000077ffe3e80"), 0x80),
        ]
        if self.first_gateway == "0751":
            frames.append((bytes.fromhex("000007003e80"), 0))
        if repro_gw:
            frames.append((bytes.fromhex("000007505f3e02"), 0x80))
        frames.append((bytes.fromhex("18dbefe03e80"), 0x100))
        if self.dh_gateway_type == 2:
            # DHUtils source3f70: exact SU-regulation tester-present message.
            from scripts.programming_2026_dh import su_tester_present

            frames.append((su_tester_present(), 0))
        return tuple(frames)

    def tester_present(self, repro_gw=False):
        for data, flags in self.frames(repro_gw):
            self.write(data, flags)
        self.runtime.call("set_local_time_to_previous_send_time")

    def periodic(self, repro_gw, delay):
        frames = self.frames(repro_gw)
        self.runtime.call_owned(
            "start_sync_periodic",
            "stop_sync_periodic",
            frames=frames,
            interval_ms=2000,
            retry_ms=100,
            delay_ms=delay,
            count=len(frames),
        )

    def stop_periodic(self):
        if self.runtime.owns_resource("stop_sync_periodic"):
            self.runtime.release("stop_sync_periodic")
        else:
            self.runtime.call("stop_sync_periodic")

    def start_communication(self):
        if self.first_gateway == "0751":
            if self.suzuki is None:
                raise ValueError("Source-bound Suzuki utility required for gateway0751")
            request, response = bytes.fromhex("00000751"), bytes.fromhex("00000761")
            identifier = self.diag.start_filter(request, response)
            try:
                self.suzuki.send(
                    request,
                    response,
                    b"\x10\x03",
                    b"\x50\x03",
                    minimum=6,
                    error_code=88,
                )
            finally:
                with _preserve_active_host_error():
                    self.runtime.release("stop_filter", identifier=identifier)
        self.write(bytes.fromhex("000007771083"), locked=True)
        self.wait(1000)
        self.write(bytes.fromhex("0000077ffe1083"), 0x80, locked=True)
        self.write(bytes.fromhex("18dbefe01083"), 0x100, locked=True)
        self.wait(1000)

    def stop_dtc(self):
        self.write(bytes.fromhex("000007778582"))
        self.wait(1000)
        self.tester_present(self.gateway_node == 2)
        self.wait(1000)
        self.write(bytes.fromhex("0000077ffe8582"), 0x80)
        self.wait(1000)

    def diagnostic_mask(self):
        self.write(bytes.fromhex("00000777288101"))
        if self.emissions == 0:
            self.wait(1000)
            self.tester_present(self.gateway_node == 2)
            self.wait(1000)
        self.write(bytes.fromhex("0000077ffe288101"), 0x80)
        remaining = self.emissions
        if not remaining:
            self.wait(1000)
        else:
            while remaining > 2000:
                self.wait(2000)
                self.tester_present(self.gateway_node == 2)
                remaining -= 2000
            self.wait(remaining)
        if self.emissions == 0:
            self.tester_present(self.gateway_node == 2)
            self.wait(1000)
        self.write(bytes.fromhex("00000777288301"))
        if self.emissions == 0:
            self.wait(1000)
            self.tester_present(self.gateway_node == 2)
            self.wait(1000)
        self.write(bytes.fromhex("0000077ffe288301"), 0x80)
        self.write(bytes.fromhex("18dbefe0288301"), 0x100)
        if self.emissions:
            first = 2000 - remaining
            delay = self.emissions
            while first < delay:
                self.wait(first)
                delay -= first
                first = 2000
                self.tester_present(self.gateway_node == 2)
            self.wait(delay)
        else:
            self.wait(1000)

    def session(self, request, response):
        pending = (
            self.metadata.logical_blocks[0].routine_response_pending_limit
            if self.metadata.logical_blocks
            else 180
        )
        self.diag.call(
            request,
            response,
            b"\x10\x02",
            b"\x50\x02",
            minimum=6,
            error_code=41,
            phase5=True,
            pending_limit=pending,
            busy_limit=0x159A,
            send_tester_present=True,
        )

    def _security(self, request, response, secret_info):
        from scripts.programming_2026_common import SecretInfoClient

        if not isinstance(secret_info, SecretInfoClient):
            raise TypeError("Native SecretInfo client binding required")
        pending = (
            self.metadata.logical_blocks[0].routine_response_pending_limit
            if self.metadata.logical_blocks
            else 180
        )
        seed = self.diag.call(
            request,
            response,
            b"\x27\x01",
            b"\x67\x01",
            minimum=18,
            error_code=16,
            phase5=True,
            pending_limit=pending,
            busy_limit=0x159A,
        )
        key = self.unified.calc_seed_key(
            secret_info, self.metadata.service_auth_key_bytes, seed[2:18]
        )
        self.diag.call(
            request,
            response,
            b"\x27\x02" + key,
            b"\x67\x02",
            minimum=2,
            error_code=17,
            phase5=True,
            pending_limit=pending,
            busy_limit=0x159A,
        )

    def security(self, request, response, secret_info):
        try:
            self._security(request, response, secret_info)
        except CommonResponseError as exc:
            if exc.response == b"\x7f\x27\x35":
                raise CommonResponseError(1002, exc.response) from exc
            raise


def run_repro_prepare(
    context: ReproStdContext2026,
    runtime: NativeRuntime2026,
    *,
    secret_info=None,
    gateway_node=0,
    dh_gateway=None,
    suzuki=None,
) -> dict:
    """ReproStdPrepare2110 native chronology, including gateway/charge-bus paths."""
    from scripts.programming_2026_common import SecretInfoClient
    from scripts.programming_2026_dh import (
        DHGateway2026,
        central_gateway_request_can_id,
    )
    from scripts.programming_2026_suzuki_fhi import SuzukiUtils2026

    if (
        not isinstance(context, ReproStdContext2026)
        or context.identity.module_name != REPRO_PREPARE
        or not isinstance(runtime, NativeRuntime2026)
        or not isinstance(secret_info, SecretInfoClient)
        or type(gateway_node) is not int
        or gateway_node not in (0, 1, 2)
    ):
        raise ValueError(
            "Bound ReproStd preparation/runtime/private native security required"
        )
    controller = ReproPrepare2026(
        context,
        runtime,
        gateway_node=gateway_node,
        dh_gateway=dh_gateway,
        suzuki=suzuki,
    )
    metadata, unified = controller.metadata, controller.unified
    if len(context.addresses) < metadata.node:
        raise ValueError("Native preparation address vector does not cover node")
    address = context.addresses[metadata.node - 1]
    request, response = address.headers()
    dh_id = central_gateway_request_can_id().hex().upper()
    if any(item["gatewaydiagid"].upper() == dh_id for item in controller.gateways) and (
        not isinstance(dh_gateway, DHGateway2026) or dh_gateway.runtime is not runtime
    ):
        raise ValueError("Concrete source-bound DH gateway utility required")
    if any(
        item["gatewaydiagid"].upper() == "0751" for item in controller.gateways
    ) and not isinstance(suzuki, SuzukiUtils2026):
        raise ValueError("Concrete source-bound Suzuki gateway utility required")
    failure = None
    cleanup_errors = []
    filter_id = None
    prepared = False
    block_attempted = False
    block_override = bool(context.addresses[0].extended)
    try:
        runtime.call("set_local_time_to_previous_send_time")
        controller.wait(metadata.wakeup_ms)
        if controller.gateways and controller.gateways[0]["gatewaymode"] in (
            "01",
            "02",
        ):
            first_id = controller.first_gateway
            if first_id == "07505F" and not controller.gateway_node:
                try:
                    controller.gateway_node = unified.judge_repro_gateway_node(0)
                except (
                    NativeTransportError,
                    VendorTransportError,
                    NativeJ2534Exception2026,
                ) as exc:
                    if _driver_error(exc) in (9, 16):
                        raise CommonResponseError(1003) from exc
                    raise
            elif first_id == dh_id:
                assert isinstance(dh_gateway, DHGateway2026)
                controller.dh_gateway_type = (
                    dh_gateway.start_reprogramming_mode_for_multi_types()
                )
        controller.start_communication()
        controller.stop_periodic()
        controller.periodic(False, 1000)
        flow = metadata.node_values.get("chargelocalbusecureprogrammingflow", "")
        if flow == "01":
            bus_request = bytes.fromhex(
                metadata.node_values.get(
                    "chargelocalbuspoweroncontrollingecudiagid", ""
                )
            )
            if len(bus_request) != 2:
                raise ValueError("Native charge-bus diagnostic ID must have two bytes")
            bus_response = bus_request[:1] + bytes(((bus_request[1] + 8) & 255,))
            unified.routine_charge_local_bus(
                b"\0\0" + bus_request, b"\0\0" + bus_response, 0
            )
            controller.wait(metadata.charge_local_bus_start_ms)
        elif flow == "02":
            unified.routine_charge_local_bus_phase6(0)
            controller.wait(metadata.charge_local_bus_start_ms)
        if controller.first_gateway != "0751":
            unified.cancel_automatic_ig_off(False)
        has_repro_gateway = False
        suppressed_gateway = False
        for gateway in controller.gateways:
            identifier = gateway["gatewaydiagid"].upper()
            if identifier == "07505F":
                has_repro_gateway = True
                try:
                    if controller.gateway_node == 1:
                        unified.collate_seed_key_phase5_gateway()
                        unified.routine_phase5_gateway(0)
                        controller.wait(1500)
                        unified.routine_phase5_gateway(1)
                    elif controller.gateway_node == 2:
                        unified.collate_seed_key_central_gateway()
                except (CommonResponseError, NativePassThruException2026) as exc:
                    if (
                        request == bytes.fromhex("000007505f")
                        and context.native_retry_flag_964
                        and _native_error(exc) == 23
                    ):
                        suppressed_gateway = True
                    else:
                        raise
            elif identifier == "0751":
                assert isinstance(suzuki, SuzukiUtils2026)
                if suzuki.supports_wired_repro(with_filter=True):
                    suzuki.gateway_authorize(None, with_filter=True)
                else:
                    unified.collate_seed_key_smc_gateway()
        controller.stop_periodic()
        controller.stop_dtc()
        if controller.emissions == 0:
            controller.tester_present(controller.gateway_node == 2)
            controller.wait(1000)
            controller.diagnostic_mask()
        controller.periodic(False, 1000)
        for gateway in controller.gateways:
            identifier = gateway["gatewaydiagid"].upper()
            if identifier == "07505F" and has_repro_gateway and not suppressed_gateway:
                if controller.gateway_node == 1:
                    unified.routine_phase5_gateway(2)
                    controller.wait(1500)
                    unified.routine_phase5_gateway(3)
                elif controller.gateway_node == 2:
                    unified.change_mode(
                        0, bytes.fromhex("000007505f"), bytes.fromhex("000007585f")
                    )
                    controller.wait(1500)
            elif identifier == "0751":
                unified.routine_smc_gateway(2)
                controller.wait(1500)
        controller.stop_periodic()
        if controller.emissions:
            controller.diagnostic_mask()
        controller.periodic(
            controller.gateway_node == 2, 0 if controller.emissions else 1000
        )
        filter_id = controller.diag.start_filter(request, response)
        if block_override:
            block_attempted = True
            controller.diag.set_block_size(1)
        try:
            controller.session(request, response)
        except (
            NativeTransportError,
            VendorTransportError,
            NativeJ2534Exception2026,
        ) as exc:
            if not controller.gateways and _driver_error(exc) in (9, 16):
                raise CommonResponseError(1004) from exc
            raise
        if controller.emissions == 0:
            controller.stop_periodic()
            controller.periodic(controller.gateway_node == 2, 0)
        controller.wait(metadata.wakeup_ms)
        controller.security(request, response, secret_info)
        prepared = True
    except (
        CommonResponseError,
        NativeTransportError,
        VendorTransportError,
        NativePassThruException2026,
    ) as exc:
        failure = exc
    finally:
        with _preserve_active_host_error():
            try:
                if block_attempted:
                    try:
                        runtime.call(
                            "control_io", cleanup=True, ioctl=2, parameters=((0x1E, 0),)
                        )
                    except (
                        CommonResponseError,
                        NativeTransportError,
                        VendorTransportError,
                        NativeException2026,
                    ) as exc:
                        cleanup_errors.append(
                            (
                                None
                                if type(exc) is NativeException2026
                                else _native_error(exc),
                                _driver_error(exc),
                            )
                        )
            finally:
                with _preserve_active_host_error():
                    try:
                        if filter_id is not None:
                            try:
                                runtime.release("stop_filter", identifier=filter_id)
                            except (
                                CommonResponseError,
                                NativeTransportError,
                                VendorTransportError,
                                NativeException2026,
                            ) as exc:
                                cleanup_errors.append(
                                    (
                                        None
                                        if type(exc) is NativeException2026
                                        else _native_error(exc),
                                        _driver_error(exc),
                                    )
                                )
                    finally:
                        with _preserve_active_host_error():
                            if not prepared and runtime.owns_resource(
                                "stop_sync_periodic"
                            ):
                                runtime.release("stop_sync_periodic")
    return {
        "native_return": failure is None,
        "native_success": None,
        "state": "prepared" if failure is None else "prepare_failed",
        "programming_completed": False,
        "prepared": failure is None,
        "cleanup_failed": bool(cleanup_errors),
        "cleanup_errors": tuple(cleanup_errors),
        "error_kind": 1 if failure is not None else None,
        "native_error_code": _native_error(failure) if failure else None,
        "driver_error_code": _driver_error(failure),
        "gateway_node": controller.gateway_node,
        "dh_gateway_type": controller.dh_gateway_type,
    }
