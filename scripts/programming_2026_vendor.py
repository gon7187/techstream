"""Actual CUW2026 retained HINO/SBR operations over injected CAN primitives.

Exact module identity and imported 2026 parameter/CPU context are mandatory.
No PE execution, transport discovery, secret acquisition or device access occurs.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from scripts.calibration import CalibrationContainer
from scripts.calibration_2026 import (
    native2026_archive,
    native2026_cpu_count,
    native2026_global_cpu_index,
    native2026_location_id,
    native2026_metadata_for_cpu,
)
from scripts.j2534_2026 import (
    NativeCommunicationAddress,
    communication_addresses_from_parameter,
)
from scripts.native_modules import NativeModuleIdentity, identify_native_module
from scripts.programming import NativeTransportError
from scripts.programming_2026_common import (
    CanDiag2026,
    CommonResponseError,
    NativeParameterBinding2026,
    NativePassThruException2026,
    NativeRuntime2026,
    bind_parameter2026,
    native_error_fields2026,
)
from scripts.programming_vendor import SBRFile, VendorSegment, sbr_identifiers

_MODULES = {}
for _suffix, _family in (("", "HINO"), ("ForDSS", "HINO-DSS"), ("ForVCS", "HINO-VCS")):
    for _kind, _stage in (
        ("CIDGetter", "get_cid"),
        ("PrepareWriter", "prepare"),
        ("FlashWriter", "write"),
    ):
        _MODULES[f"TCUWCanHINO{_kind}{_suffix}.dll"] = (_family, _stage)
for _kind, _stage in (
    ("SoftwareIDGetter", "get_cid"),
    ("PrepareWriter", "prepare"),
    ("FlashWriter", "write"),
):
    _MODULES[f"TCUWCanSBR{_kind}.dll"] = ("SBR", _stage)


def _uint(value, bits, name):
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError(f"Native {name} must be uint{bits}")
    return value


def _flag(binding, name):
    text = binding.value(name)
    if text not in ("", "0", "1"):
        raise ValueError(f"Native Boolean {name} is malformed")
    return text == "1"


def _decimal(binding, name):
    text = binding.value(name)
    if text and (not text.isascii() or not text.isdecimal()):
        raise ValueError(f"Native decimal {name} is malformed")
    return _uint(int(text or "0"), 32, name)


@dataclass(frozen=True)
class Vendor2026Context:
    identity: NativeModuleIdentity
    selection: NativeParameterBinding2026 = field(repr=False)
    addresses: tuple[NativeCommunicationAddress, ...]
    family: str
    stage: str
    loader: VendorSegment | None = field(default=None, repr=False)
    image: VendorSegment | None = field(default=None, repr=False)
    loader_size: int = 0
    image_size: int = 0
    files: tuple[SBRFile, ...] = field(default=(), repr=False)
    native_error_kind: int = 0
    native_retry: bool = False
    native_writing: bool = False
    native_pending_timeout_ms: int | None = None
    native_counts: tuple[int, ...] = ()
    native_percentages: tuple[int, ...] = ()
    observed_cids: tuple[str, ...] = field(default=(), repr=False)
    observations: Mapping = field(default_factory=dict, repr=False)
    address_groups: tuple[tuple[NativeCommunicationAddress, ...], ...] = ()

    def __post_init__(self):
        if (
            not isinstance(self.identity, NativeModuleIdentity)
            or self.identity
            != identify_native_module(self.identity.sha256, self.identity.module_name)
            or self.identity.cuw_build != "2026"
            or _MODULES.get(self.identity.module_name) != (self.family, self.stage)
            or not isinstance(self.selection, NativeParameterBinding2026)
            or self.selection.module_name != self.identity.module_name
            or self.selection.operation != self.stage
            or type(self.addresses) is not tuple
            or not 1 <= len(self.addresses) <= 256
            or any(
                not isinstance(a, NativeCommunicationAddress) for a in self.addresses
            )
            or type(self.native_writing) is not bool
            or type(self.native_retry) is not bool
        ):
            raise ValueError(
                "Exact CUW2026 retained vendor identity and selected context required"
            )
        for values in (self.native_counts, self.native_percentages):
            if (
                type(values) is not tuple
                or len(values) != native2026_cpu_count(self.selection.metadata)
                or any(type(v) is not int or not 0 <= v <= 0xFFFFFFFF for v in values)
            ):
                raise ValueError("Native per-CPU unsigned progress arrays required")
        _uint(self.native_error_kind, 32, "error kind")
        for size in (self.loader_size, self.image_size):
            _uint(size, 32, "download size")
        if self.native_pending_timeout_ms is not None:
            _uint(self.native_pending_timeout_ms, 32, "shared pending timeout")
        if self.stage == "write":
            if len(self.address_groups) != native2026_cpu_count(
                self.selection.metadata
            ) or any(
                type(group) is not tuple
                or not group
                or any(not isinstance(a, NativeCommunicationAddress) for a in group)
                for group in self.address_groups
            ):
                raise ValueError(
                    "Native writer vector of per-CPU address vectors required"
                )
            if self.family == "HINO" and self.native_pending_timeout_ms is None:
                raise ValueError(
                    "HINO writer requires actual prepared context+98c timing"
                )
            if self.family == "SBR":
                if not self.files or any(
                    not isinstance(f, SBRFile) for f in self.files
                ):
                    raise ValueError("Imported native SBR files required")
            elif not isinstance(self.loader, VendorSegment) or not isinstance(
                self.image, VendorSegment
            ):
                raise ValueError("Imported native HINO loader/image required")


def bind_native_context(
    container: CalibrationContainer,
    node: int,
    observed_cids: tuple[str, ...],
    selection: NativeParameterBinding2026,
    identity: NativeModuleIdentity,
    attachments: Mapping[str, bytes],
    observations: Mapping,
) -> Vendor2026Context:
    """Bind actual31 parameter selection, actual47 archives and actual48 addresses."""
    if (
        not isinstance(selection, NativeParameterBinding2026)
        or not isinstance(identity, NativeModuleIdentity)
        or identity.module_name not in _MODULES
        or not isinstance(attachments, Mapping)
        or attachments
        or not isinstance(observations, Mapping)
        or set(observations)
        - {
            "cpu_index",
            "native_error_kind",
            "native_retry",
            "native_writing",
            "native_pending_timeout_ms",
            "native_counts",
            "native_percentages",
            "previous_addresses",
            "response_canids",
        }
        or type(observed_cids) is not tuple
    ):
        raise ValueError(
            "Selected actual2026 binding and native observations required; archive overrides forbidden"
        )
    selection.validate_against(
        container,
        operation=selection.operation,
        node=node,
        cpu_index=observations.get("cpu_index", 0),
    )
    metadata = selection.metadata
    family, stage = _MODULES[identity.module_name]
    groups = ()
    if stage == "write":
        groups = native2026_write_address_groups(
            container,
            selection,
            history=list(observations.get("previous_addresses", ())),
        )
        addresses = groups[native2026_global_cpu_index(metadata)]
    else:
        resolver = communication_addresses_from_parameter(
            container,
            selection.parameter,
            response_canids=observations.get("response_canids"),
            history=list(observations.get("previous_addresses", ())),
        )
        resolved, addresses = resolver.resolve(
            selection.selector_functions,
            cids=observed_cids,
            location_id=metadata.cpu.values.get("locationid", ""),
        )
        if not resolved:
            raise ValueError("Native2026 address selector failed")
    values = {}
    if stage == "write" and family.startswith("HINO"):
        for key, name, loader in (
            ("loader", "SBLStartAddressSize", True),
            ("image", "DATAStartAddressSize", False),
        ):
            fields = selection.lines(name)
            if len(fields) != 2 or any(
                not t or len(t) > 8 or any(c not in "0123456789abcdefABCDEF" for c in t)
                for t in fields
            ):
                raise ValueError(
                    f"Native {name} requires two hexadecimal uint32 fields"
                )
            archive = native2026_archive(metadata, flash_code=loader)
            if type(archive.data) is not bytes:
                raise ValueError("Native archive materialization is unavailable")
            values[key] = VendorSegment(int(fields[0], 16), archive.data)
            values[key + "_size"] = int(fields[1], 16)
    if stage == "write" and family == "SBR":
        values["files"] = _sbr_files(metadata.cpu, selection)
    return Vendor2026Context(
        identity,
        selection,
        tuple(addresses),
        family,
        stage,
        native_error_kind=observations.get("native_error_kind", 0),
        native_retry=observations.get("native_retry", False),
        native_writing=observations.get("native_writing", False),
        native_pending_timeout_ms=observations.get("native_pending_timeout_ms"),
        native_counts=observations.get(
            "native_counts", (0,) * native2026_cpu_count(metadata)
        ),
        native_percentages=observations.get(
            "native_percentages", (0,) * native2026_cpu_count(metadata)
        ),
        observed_cids=observed_cids,
        observations=MappingProxyType(dict(observations)),
        address_groups=groups,
        **values,
    )


def native2026_write_address_groups(
    container,
    selection: NativeParameterBinding2026,
    *,
    history: list[NativeCommunicationAddress] | None = None,
) -> tuple[tuple[NativeCommunicationAddress, ...], ...]:
    """Generic Control4c10: each CPU's own row/LocationID, NULL CID/callbacks.

    History is shared, read-only here. Only native Address30f0 appends records.
    A different CPU row is an input to its address producer, not a writer reload.
    """
    if (
        not isinstance(selection, NativeParameterBinding2026)
        or selection.operation != "write"
    ):
        raise TypeError("Actual native2026 writer parameter binding required")
    metadata = selection.metadata
    selection.validate_against(
        container, operation="write", node=metadata.node, cpu_index=metadata.cpu_index
    )
    shared_history = [] if history is None else history
    groups = []
    for index in range(native2026_cpu_count(metadata)):
        state = native2026_metadata_for_cpu(metadata, index)
        binding = bind_parameter2026(
            container,
            selection.catalog_sources,
            "write",
            node=state.node,
            cpu_index=state.cpu_index,
            encoded=selection.encoded,
            metadata_state=state,
        )
        resolver = communication_addresses_from_parameter(
            container, binding.parameter, history=shared_history
        )
        success, group = resolver.resolve(
            binding.selector_functions,
            cids=(),
            location_id=native2026_location_id(binding.metadata, index),
        )
        if not success or not group:
            raise ValueError("Native writer CPU address vector is unavailable")
        groups.append(tuple(group))
    return tuple(groups)


def _sbr_files(cpu, selection):
    files = []
    for item in cpu.files:

        def hexadecimal(name, item=item):
            text = item.values.get(name, "")
            if (
                not text
                or len(text) > 8
                or any(c not in "0123456789abcdefABCDEF" for c in text)
            ):
                raise ValueError("Malformed native SBR file geometry")
            return int(text, 16)

        if item.record is None or item.values.get("eraseblock") not in ("0", "1"):
            raise ValueError("Imported native SBR record and erase flag required")
        files.append(
            SBRFile(
                VendorSegment(hexadecimal("downloadaddress"), item.record.data),
                alfid=hexadecimal("alfid"),
                erase=item.values["eraseblock"] == "1",
                logical_size=hexadecimal("downloadmemsize"),
                padded=_flag(selection, "FlagToDataBlockPadding"),
            )
        )
    return tuple(files)


def _vendor_headers(address: NativeCommunicationAddress) -> tuple[bytes, bytes]:
    # Retained exporters copy two bytes from each seven-byte address record.
    return b"\0\0" + address.request[:2], b"\0\0" + address.response[:2]


class VendorCAN2026:
    """One exact selected CAN address and common2026 communication engine."""

    def __init__(
        self,
        runtime: NativeRuntime2026,
        address: NativeCommunicationAddress,
        *,
        phase5=False,
        pending_seconds=180,
        minimum_timeout_ms=5000,
        old_timeout_ms=5000,
    ):
        if not isinstance(runtime, NativeRuntime2026) or not isinstance(
            address, NativeCommunicationAddress
        ):
            raise TypeError("Typed runtime and native address required")
        self.runtime, self.address = runtime, address
        self.diag = CanDiag2026(runtime)
        self.phase5, self.pending_seconds = phase5, pending_seconds
        self.minimum_timeout_ms, self.old_timeout_ms = (
            minimum_timeout_ms,
            old_timeout_ms,
        )
        self.history: list[dict] = []
        self.attempted = False

    def call(self, payload, expected, minimum=0, error_code=3, *, delay_ms=0):
        request, response = _vendor_headers(self.address)
        self.runtime.check()
        self.attempted = True
        answer = self.diag.call(
            request,
            response,
            payload,
            expected,
            minimum=minimum,
            error_code=error_code,
            phase5=self.phase5,
            pending_limit=self.pending_seconds if self.phase5 else 149,
            busy_limit=self.minimum_timeout_ms if self.phase5 else 255,
            send_tester_present=not self.phase5,
            pending_timeout_ms=self.old_timeout_ms,
            delay_ms=delay_ms,
        )
        self.history.append(
            {
                "request_prefix_hex": payload[:2].hex(),
                "request_length": len(payload),
                "response_length": len(answer),
            }
        )
        return answer

    def raw(self, can_id, payload):
        self.runtime.check()
        self.attempted = True
        self.diag.write(
            _uint(can_id, 16, "functional CAN ID").to_bytes(4, "big") + payload
        )

    def wait(self, milliseconds):
        self.runtime.call("wait", milliseconds=_uint(milliseconds, 32, "wait"))


def _fixed_identifier(data, width):
    if len(data) < width:
        raise CommonResponseError(3, data)
    return data[:width].split(b"\0", 1)[0]


def _native_cancel_requested(runtime: NativeRuntime2026) -> bool:
    runtime.check()
    if runtime.native_cancelled is None:
        raise ValueError("Native getter callback12 observation is not bound")
    requested = runtime.native_cancelled()
    runtime.check()
    if type(requested) is not bool:
        raise TypeError("Native getter callback12 must return Boolean")
    return requested


def get_identifiers(context: Vendor2026Context, runtime: NativeRuntime2026) -> dict:
    """2026 native getter chronology including DSS/VCS pre-query tester requests."""
    if not isinstance(context, Vendor2026Context) or context.stage != "get_cid":
        raise ValueError("Exact CUW2026 getter context required")
    selection, family = context.selection, context.family
    if runtime.native_cancelled is None:
        raise ValueError("Native getter callback12 observation is not bound")
    diag = CanDiag2026(runtime)
    filters = []
    failure = None
    identifiers = []
    try:
        runtime.call_owned("connect", "disconnect", protocol=6)
        runtime.call(
            "set_timeout",
            milliseconds=_decimal(selection, "ReceiveTimeoutBeforeGetCID"),
        )
        if family == "SBR":
            runtime.call("wait", milliseconds=10000)
        selected = context.addresses if family == "SBR" else context.addresses[:1]
        for address in selected:
            filters.append(diag.start_filter(*_vendor_headers(address)))
            p5 = (
                family == "HINO"
                and selection.metadata.vehicle.get("contacttype") == "P5-CAN"
            ) or (family == "SBR" and not _flag(selection, "FlagToSupportGetCID"))
            channel = VendorCAN2026(
                runtime,
                address,
                phase5=p5,
                pending_seconds=30 if family == "SBR" else 180,
                minimum_timeout_ms=5530 if family == "HINO" else 5000,
                old_timeout_ms=6000 if family == "HINO-VCS" else 5000,
            )

            def guarded_call(payload, expected, minimum=0, channel=channel, p5=p5):
                if _native_cancel_requested(runtime):
                    return None
                return channel.call(
                    payload,
                    expected,
                    minimum,
                    delay_ms=5000 if family == "HINO" and not p5 else 0,
                )

            if family in ("HINO-DSS", "HINO-VCS"):
                guarded_call(b"\x3e", b"\x7e", 1)
                if family == "HINO-VCS":
                    guarded_call(b"\x3e\x01", b"\x7e", 1)
                prefix, request, width = (
                    (b"\x5a\x88\x01", b"\x1a\x88\x01", 16)
                    if family == "HINO-DSS"
                    else (b"\x5a\x03", b"\x1a", 13)
                )
                answer = guarded_call(request, prefix, len(prefix) + width)
                identifiers.append(
                    b""
                    if answer is None
                    else _fixed_identifier(answer[len(prefix) :], width)
                )
            elif family == "HINO":
                guarded_call(
                    b"\x3e\0" if p5 else b"\x3e\x01",
                    b"\x7e\0" if p5 else b"\x7e",
                    2 if p5 else 1,
                )
                prefix = b"\x62\xf1\x88" if p5 else b"\x5a\x03"
                width = 12 if p5 else 13
                answer = guarded_call(
                    b"\x22\xf1\x88" if p5 else b"\x1a\x81", prefix, len(prefix) + width
                )
                identifier = (
                    b""
                    if answer is None
                    else _fixed_identifier(answer[len(prefix) :], width)
                )
                identifiers.append(identifier if p5 else identifier.replace(b" ", b""))
            else:
                support = _flag(selection, "FlagToSupportGetCID")
                width = (
                    16 if support else _decimal(selection, "SoftwareInfoROMIDByteNum")
                )
                if not 0 <= width <= 4092:
                    raise ValueError("Native ROM response minimum exceeds CAN buffer")
                prefix = b"\x49\x04\x01" if support else b"\x62\xf1\x82"
                answer = guarded_call(
                    b"\x09\x04" if support else b"\x22\xf1\x82",
                    prefix,
                    len(prefix) + width,
                )
                if answer is not None:
                    identifiers.extend(
                        sbr_identifiers(
                            answer[3:],
                            ascii_records=support,
                            rom_width=16 if support else 5,
                        )
                    )
            runtime.release("stop_filter", identifier=filters.pop())
    except BaseException as error:
        failure = error
        raise
    finally:
        errors = []
        for identifier in reversed(filters):
            try:
                runtime.release("stop_filter", identifier=identifier)
            except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - attempt all owned releases
                errors.append(error)
        if runtime.owns_resource("disconnect"):
            try:
                runtime.release("disconnect")
            except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - attempt all owned releases
                errors.append(error)
        if errors:
            if failure:
                failure.add_note(
                    "Getter cleanup failures: "
                    + ",".join(type(error).__name__ for error in errors)
                )
            else:
                raise errors[0]
    return {
        "state": "read_completed",
        "identifiers": tuple(identifiers),
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "native_build": "2026",
        "source_sha256": context.identity.sha256,
    }


def hino_key(seed: bytes, *, dcu: bool = False) -> bytes:
    """HINO2026 prepare1000: complement12 or native DCU four-byte arithmetic."""
    if (
        type(dcu) is not bool
        or type(seed) is not bytes
        or len(seed) != (4 if dcu else 12)
    ):
        raise ValueError("Native four/twelve-byte HINO seed required")
    if not dcu:
        return bytes(255 - byte for byte in seed)
    low = min(0xFFFF, (0xFFDD - int.from_bytes(seed[2:], "big")) & 0xFFFFFFFF)
    high = 0xFFFF - ((int.from_bytes(seed[:2], "big") - 0x23) & 0xFFFF)
    return low.to_bytes(2, "big") + high.to_bytes(2, "big")


def _hino_retry(channel, request, expected, minimum, error_code):
    """VCS actual EH: three attempts for driver9/16 or a returned negative SID."""
    for attempt in range(3):
        try:
            return channel.call(request, expected, minimum, error_code)
        except (NativeTransportError, NativePassThruException2026) as error:
            channel.runtime.check()
            if native_error_fields2026(error)[1] not in (9, 16) or attempt == 2:
                raise
        except CommonResponseError as error:
            channel.runtime.check()
            if getattr(error, "response", b"")[:1] != b"\x7f" or attempt == 2:
                raise
        channel.wait(1000)
    raise AssertionError("Unreachable native retry loop")


def prepare_hino(
    context: Vendor2026Context, runtime: NativeRuntime2026, *, key_provider=None
) -> dict:
    """2026 HINO preparation; ordinary/VCS arithmetic is implemented locally."""
    if not isinstance(context, Vendor2026Context) or not context.family.startswith(
        "HINO"
    ):
        raise ValueError("Bound HINO2026 context required")
    family = context.family
    if context.stage != "prepare" and not (
        family == "HINO-DSS" and context.stage == "write"
    ):
        raise ValueError("Native preparation/PrepareRetry context required")
    if family == "HINO-DSS":
        from scripts.programming_2026_legacy import HINOUtils2026

        result = HINOUtils2026(runtime).prepare_write_dss(
            *_vendor_headers(context.addresses[0]),
            notification=lambda: context.native_writing,
        )
        return {
            "state": "prepare_completed" if result.prepared else "failed",
            "native_success": result.prepared,
            "native_error_code": result.native_error_code,
            "driver_error_code": result.driver_error_code,
            "native_result_code": result.result_code,
            "physical_status": "PHYSICAL_UNCONFIRMED",
        }
    channel = VendorCAN2026(
        runtime,
        context.addresses[0],
        phase5=family == "HINO",
        old_timeout_ms=6000 if family == "HINO-VCS" else 5000,
    )
    identifier = channel.diag.start_filter(*_vendor_headers(channel.address))
    failure = None
    try:
        commands = (
            (b"\xa0\x85\x02", b"\x85\x82", b"\xa0\x28\x02", b"\x28\x81\x01")
            if family != "HINO-VCS"
            else (b"\xa0\x85\x02", b"\xa0\x28\x02")
        )
        for command in commands:
            channel.raw(0x720, command)
        channel.wait(1000)
        session = b"\x10\x85" if family == "HINO-DSS" else b"\x10\x02"
        expected = (
            b"\x50\x85"
            if family == "HINO-DSS"
            else b"\x50\x02"
            if family == "HINO"
            else b"\x50"
        )
        answer = (
            _hino_retry(channel, session, expected, 1, 41)
            if family == "HINO-VCS"
            else channel.call(session, expected, 6 if family == "HINO" else 2, 41)
        )
        if family == "HINO":
            runtime.call("set_timeout", milliseconds=int.from_bytes(answer[2:4], "big"))
            channel.minimum_timeout_ms = int.from_bytes(answer[4:6], "big") * 10
        level = 3 if family == "HINO-DSS" else 1
        dcu = (
            family == "HINO"
            and context.selection.metadata.vehicle.get("kindofecu") == "106"
        )
        width = 4 if family == "HINO-DSS" or dcu else 12
        seed = channel.call(bytes((0x27, level)), bytes((0x67, level)), width + 2, 16)[
            2 : 2 + width
        ]
        if family == "HINO":
            channel.diag.set_block_size(1)
        if family == "HINO-DSS":
            runtime.check()
            assert callable(key_provider)
            key = key_provider(seed)
            runtime.check()
        else:
            key = hino_key(seed, dcu=dcu)
        if type(key) is not bytes or len(key) != width:
            raise ValueError("Native DSS key must contain four authorized bytes")
        channel.call(
            bytes((0x27, level + 1)) + key,
            bytes((0x67, level + 1)) + (b"\x34" if family == "HINO-DSS" else b""),
            3 if family == "HINO-DSS" else 2,
            17,
        )
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            runtime.release("stop_filter", identifier=identifier)
        except (Exception, KeyboardInterrupt) as error:
            if failure:
                failure.add_note(
                    "HINO preparation filter release failed: " + type(error).__name__
                )
            else:
                raise
    return {
        "state": "prepare_completed",
        "native_pending_timeout_ms": channel.minimum_timeout_ms
        if family == "HINO"
        else None,
        "native_build": "2026",
        "source_sha256": context.identity.sha256,
        "physical_status": "PHYSICAL_UNCONFIRMED",
    }


def write_hino(
    context: Vendor2026Context,
    runtime: NativeRuntime2026,
    *,
    notify: Callable[[str, int], None] = lambda _kind, _value: None,
) -> dict:
    """2026 loader/download/routines/image/reset and native progress chronology."""
    if (
        not isinstance(context, Vendor2026Context)
        or context.stage != "write"
        or not context.family.startswith("HINO")
        or not callable(notify)
    ):
        raise ValueError("Bound HINO2026 writer and notification callback required")
    index = native2026_global_cpu_index(context.selection.metadata)
    if index >= len(context.address_groups):
        raise ValueError("Native CPU-indexed HINO address vector absent")
    family = context.family
    pending_timeout_ms = 5000
    if family == "HINO":
        assert context.native_pending_timeout_ms is not None
        pending_timeout_ms = context.native_pending_timeout_ms
    channel = VendorCAN2026(
        runtime,
        context.address_groups[index][0],
        phase5=family == "HINO",
        minimum_timeout_ms=pending_timeout_ms,
        old_timeout_ms=6000 if family == "HINO-VCS" else 5000,
    )
    identifier = channel.diag.start_filter(*_vendor_headers(channel.address))
    failure = None
    transferred = 0
    writing = False
    assert context.loader is not None and context.image is not None

    def routine(value, *, erase=False):
        request = (b"\x31\x01" if family == "HINO" else b"\x31") + value
        expected = (
            (b"\x71\x01" if family == "HINO" else b"\x71")
            + value
            + (b"" if family == "HINO-VCS" else b"\0")
        )
        try:
            channel.call(request, expected, len(expected), 90 if erase else 89)
        except (CommonResponseError, NativePassThruException2026) as error:
            if (
                family == "HINO"
                and erase
                and getattr(error, "response", b"")[:3] == b"\x7f\x31\x31"
            ):
                return
            raise

    def transfer(segment, size, *, image=False):
        nonlocal transferred
        if family == "HINO":
            request = (
                b"\x34\0\x44"
                + segment.address.to_bytes(4, "big")
                + size.to_bytes(4, "big")
            )
        elif family == "HINO-DSS":
            name = "DATAStartAddressSize" if image else "SBLStartAddressSize"
            fields = context.selection.lines(name)
            address_bytes, size_bytes = (
                bytes.fromhex(text).ljust(4, b"\0") for text in fields
            )
            request = (
                b"\x34"
                + address_bytes[:3]
                + (size_bytes[:2] if image else address_bytes[3:4] + size_bytes[:1])
                + b"\0"
            )
        else:
            request = (
                bytes((0x34, 2 if image else 1))
                + segment.address.to_bytes(4, "big")
                + size.to_bytes(4, "big")
            )
        try:
            expected = (
                bytes((0x74, 2 if image else 1)) if family == "HINO-VCS" else b"\x74"
            )
            answer = channel.call(
                request, expected, 3 if family == "HINO" else len(expected), 26
            )
        except (CommonResponseError, NativePassThruException2026) as error:
            if not image and getattr(error, "response", b"")[:3] == (
                b"\x7f\x34\x31" if family == "HINO" else b"\x7f\x34\x11"
            ):
                return False
            raise
        width = 1024
        if family == "HINO":
            count = answer[1] >> 4
            if count == 0 or len(answer) < count + 2:
                raise CommonResponseError(26, answer)
            width = min(int.from_bytes(answer[2 : count + 2], "big"), 4095) - 2
            if width <= 0:
                raise CommonResponseError(26, answer)
        for sequence, offset in enumerate(range(0, len(segment.data), width), 1):
            counter = bytes((sequence & 255,)) if family == "HINO" else b""
            chunk = segment.data[offset : offset + width]
            channel.call(
                b"\x36" + counter + chunk, b"\x76" + counter, len(counter) + 1, 34
            )
            if image:
                transferred += len(chunk)
                runtime.check()
                notify("count", transferred)
                runtime.check()
                notify("percent", transferred * 100 // len(segment.data))
                runtime.check()
        channel.call(b"\x37", b"\x77", 1, 28)
        return True

    try:
        loaded = transfer(context.loader, context.loader_size)
        if loaded:
            routine(
                b"\x10\xff"
                if family == "HINO"
                else b"\xa2"
                if family == "HINO-DSS"
                else b"\x05"
            )
            if family == "HINO-VCS":
                channel.wait(1000)
        routine(
            b"\x10\xfd"
            if family == "HINO"
            else b"\xa0"
            if family == "HINO-DSS"
            else b"\x01",
            erase=True,
        )
        runtime.check()
        notify("writing", 1)
        writing = True
        runtime.check()
        transfer(context.image, context.image_size, image=True)
        routine(
            b"\x10\xfe"
            if family == "HINO"
            else b"\xa3"
            if family == "HINO-DSS"
            else b"\x02"
        )
        if family == "HINO":
            routine(b"\x10\xfc", erase=True)
        elif family == "HINO-VCS":
            routine(b"\x03")
        if family == "HINO-VCS":
            _hino_retry(channel, b"\x11\x01", b"\x51", 1, 24)
        else:
            channel.call(
                b"\x11\x01" if family == "HINO" else b"\x11",
                b"\x51\x01" if family == "HINO" else b"\x51",
                2 if family == "HINO" else 1,
                24,
            )
        for command in (
            (b"\xa0\x28\x01", b"\xa0\x85\x01")
            if family == "HINO-VCS"
            else (b"\xa0\x28\x01", b"\x28\x80\x01", b"\xa0\x85\x01", b"\x85\x81")
        ):
            channel.raw(0x720, command)
        channel.wait(1000)
        runtime.check()
        notify("writing", 0)
        writing = False
        runtime.check()
    except (
        CommonResponseError,
        NativePassThruException2026,
        NativeTransportError,
    ) as error:
        failure = error
        error.__dict__["native_writing"] = writing
        runtime.check()
        notify("count", 0)
        runtime.check()
        notify("percent", 0)
        runtime.check()
        raise
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            runtime.release("stop_filter", identifier=identifier)
        except (Exception, KeyboardInterrupt) as error:
            if failure:
                failure.add_note(
                    "HINO writer filter release failed: " + type(error).__name__
                )
            else:
                raise
    return {
        "state": "writer_completed",
        "transferred": transferred,
        "native_build": "2026",
        "source_sha256": context.identity.sha256,
        "physical_status": "PHYSICAL_UNCONFIRMED",
    }


_SBR_SUBSTITUTION = bytearray(32)


_SECRET_TYPES = {
    0x282E0: 4,
    0x283A2: 5,
    0x28401: 6,
    0x2850B: 7,
    0x28602: 8,
    0x28710: 9,
    0x28810: 9,
    0x289E2: 12,
    0x290DD: 13,
    0x29141: 14,
    0x2924E: 15,
    0x29316: 17,
    0x29416: 16,
    0x29572: 18,
    0x296CC: 10,
    0x297CC: 11,
}


def sbr_secret_type(cpu_type: str, ssm: int) -> int:
    """SBRUtils2210 exact CPU hexadecimal*256+observed SSM-byte lookup."""
    if (
        type(cpu_type) is not str
        or not cpu_type
        or len(cpu_type) > 6
        or any(c not in "0123456789abcdefABCDEF" for c in cpu_type)
    ):
        raise ValueError("Native hexadecimal SBR CPU type required")
    key = int(cpu_type, 16) * 256 + _uint(ssm, 8, "SSM byte")
    try:
        return _SECRET_TYPES[key]
    except KeyError as error:
        raise CommonResponseError(17) from error


def sbr_cipher_function(value: int, key: int, substitution: bytes) -> int:
    """SBRUtils1330 four indexed substitutions and native16-bit rotate."""
    value = _uint(value, 16, "cipher input") ^ _uint(key, 16, "round key")
    if type(substitution) is not bytes or len(substitution) != 32:
        raise ValueError("Explicit authorized32-byte substitution required")
    low = substitution[value & 31]
    word = (
        (
            (
                substitution[((value & 1) << 4) | (value >> 12)] << 4
                | substitution[(value >> 8) & 31]
            )
            << 4
            | substitution[(value >> 4) & 31]
        )
        << 4
        | low
    ) & 65535
    return (word >> 3 | low << 13) & 65535


def sbr_des_key(seed: bytes, key: bytes, substitution: bytes) -> bytes:
    """SBRUtils1440 recovered sixteen reverse rounds; material stays caller-owned."""
    if (
        type(seed) is not bytes
        or len(seed) != 4
        or type(key) is not bytes
        or len(key) != 32
    ):
        raise ValueError("Native four-byte seed and authorized32-byte key required")
    left, right = int.from_bytes(seed[:2], "big"), int.from_bytes(seed[2:], "big")
    for index in range(15, -1, -1):
        left, right = (
            right,
            left
            ^ sbr_cipher_function(
                right,
                int.from_bytes(key[index * 2 : index * 2 + 2], "big"),
                substitution,
            ),
        )
    return right.to_bytes(2, "big") + left.to_bytes(2, "big")


class SBRUtils2026:
    """Source-owned SBRUtils methods; crypto callbacks return bytes, never success."""

    def __init__(
        self, channel: VendorCAN2026, *, wait_after_function=False, cpu_type=""
    ):

        if (
            not isinstance(channel, VendorCAN2026)
            or type(wait_after_function) is not bool
        ):
            raise TypeError("Typed CAN channel and native wait flag required")
        self.channel = channel
        self.runtime = channel.runtime
        self.wait_after_function = wait_after_function
        self.ssm = 0
        self.cpu_type = cpu_type
        self.central_gateway = False
        self.identity: NativeModuleIdentity | None = None
        self.context: Vendor2026Context | None = None
        self._control_ssm_issued = False

    @property
    def substitution(self) -> bytes:
        """SBRUtils exported muchrSubsti: shared32-byte module data, initially zero."""
        return bytes(_SBR_SUBSTITUTION)

    @substitution.setter
    def substitution(self, value: bytes) -> None:
        if type(value) is not bytes or len(value) != 32:
            raise ValueError("Native SBR substitution requires32 bytes")
        _SBR_SUBSTITUTION[:] = value

    def wait_after(self, milliseconds):
        _uint(milliseconds, 32, "functional wait")
        if self.wait_after_function:
            self.channel.wait(milliseconds)

    def tester(self):
        self.channel.raw(0x7DF, b"\x3e\x80")
        self.wait_after(60)

    def diagnostic_mask(self):
        self.channel.raw(0x7DF, b"\x85\x02")
        self.wait_after(150)
        self.tester()
        self.channel.wait(120)

    def stop_communication(self):
        self.channel.raw(0x7DF, b"\x28\x03\x01")
        self.wait_after(100)
        self.tester()
        if not self.wait_after_function:
            self.channel.wait(100)

    def extended_session(self):
        for can_id in (0x7DF, 0x7DE, 0x782):
            self.channel.raw(can_id, b"\x10\x63")
            self.wait_after(100)
        self.channel.raw(0x7DF, b"\x10\x03")
        self.channel.wait(100)

    def start_periodic(self):
        self.runtime.call_owned(
            "start_sync_periodic",
            "stop_sync_periodic_message",
            frames=((bytes.fromhex("000007df3e80"), 0),),
            interval_ms=2500,
            retry_ms=0,
            delay_ms=0,
            count=1,
        )

    def stop_periodic(self):
        self.runtime.release("stop_sync_periodic_message")

    def unit_status(self):
        self.channel.call(b"\x22\x10\x1c", b"\x62\x10\x1c\x01", 4, 101)
        self.tester()

    def read_ssm(self, *, central_gateway=False):
        if type(central_gateway) is not bool:
            raise ValueError("Native central-gateway flag required")
        answer = self.channel.call(b"\x22\xf1\0", b"\x62\xf1\0", 6, 100)
        self.ssm = answer[4 if central_gateway else 3]
        if self._control_ssm_issued:
            active = getattr(self.runtime._device_calls, "control_export", None)
            if type(active) is not tuple or len(active) != 3:
                raise ValueError("Issued SBR SSM producer left its CONTROL scope")
            engine, _controller, _target = active
            engine.worker.publish_sbr_ssm2026(self)
        return self.ssm

    def programming_session(self):
        previous = self.runtime.call("get_timeout")
        _uint(previous, 32, "saved timeout")
        failure = None
        periodic = False
        try:
            self.runtime.call("set_timeout", milliseconds=1000)
            self.start_periodic()
            periodic = True
            self.channel.call(b"\x10\x02", b"\x50\x02", 2, 41)
        except BaseException as error:
            failure = error
            raise
        finally:
            errors = []
            if periodic:
                try:
                    self.stop_periodic()
                except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - attempt all owned releases
                    errors.append(error)
            try:
                self.runtime.call("set_timeout", cleanup=True, milliseconds=previous)
            except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - attempt all owned releases
                errors.append(error)
            if errors:
                if failure:
                    failure.add_note(
                        "SBR session cleanup failures: "
                        + ",".join(type(error).__name__ for error in errors)
                    )
                else:
                    raise errors[0]
        self.wait_after(60)
        self.tester()
        self.channel.wait(1000)

    def calc_seed_key(self, seed, key_provider, *, aes=True, encrypt=False):
        if (
            not callable(key_provider)
            or type(aes) is not bool
            or type(encrypt) is not bool
        ):
            raise ValueError(
                "Authorized crypto provider and native encryption flags required"
            )
        width = 16 if aes else 4
        if type(seed) is not bytes or len(seed) != width:
            raise ValueError("Native SBR seed width differs from selected cipher")
        secret_type = sbr_secret_type(self.cpu_type, self.ssm)
        self.runtime.check()
        key = key_provider(secret_type, seed, aes, encrypt)
        self.runtime.check()
        if type(key) is not bytes or len(key) != width:
            raise CommonResponseError(17)
        return key

    def collate_seed_key(self, key_provider, *, aes=False, encrypt=False):
        if not callable(key_provider) or type(aes) is not bool:
            raise ValueError("Authorized SBR byte transformation and AES flag required")
        self.read_ssm(central_gateway=self.central_gateway)
        width = 16 if aes else 4
        seed = self.channel.call(b"\x27\x01", b"\x67\x01", width + 2, 16)[2 : 2 + width]
        if not any(seed):
            return
        self.tester()
        key = self.calc_seed_key(seed, key_provider, aes=aes, encrypt=encrypt)
        self.channel.call(b"\x27\x02" + key, b"\x67\x02", 2, 17)
        self.tester()

    def _gateway(self):
        return VendorCAN2026(
            self.runtime,
            NativeCommunicationAddress(bytes.fromhex("0763"), bytes.fromhex("076b")),
            phase5=True,
            pending_seconds=30,
        )

    def central_gateway_routine(self, mode):
        if type(mode) is not int or mode not in (0, 1):
            raise ValueError("Native central gateway routine enum0/1 required")
        channel = self._gateway()
        identifier = channel.diag.start_filter(*_vendor_headers(channel.address))
        try:
            if mode == 1:
                self.tester()
            channel.call(
                b"\x31\x01\x02" + bytes((mode,)),
                b"\x71\x01\x02" + bytes((mode,)),
                4,
                81 if mode == 0 else 49,
            )
        finally:
            self.runtime.release("stop_filter", identifier=identifier)

    def collate_gateway(self, key_provider):
        if not callable(key_provider):
            raise TypeError("Authorized gateway byte transformation required")
        channel = self._gateway()
        identifier = channel.diag.start_filter(*_vendor_headers(channel.address))
        try:
            seed = channel.call(b"\x27\x33", b"\x67\x33", 18, 16)[2:18]
            self.start_periodic()
            try:
                self.runtime.check()
                key = key_provider(seed)
                self.runtime.check()
            finally:
                self.stop_periodic()
            self.wait_after(60)
            if type(key) is not bytes or len(key) != 256:
                raise CommonResponseError(17)
            channel.call(b"\x27\x34" + key, b"\x67\x34", 2, 17)
        finally:
            self.runtime.release("stop_filter", identifier=identifier)

    def programming_master(self, address):
        if not isinstance(address, NativeCommunicationAddress):
            raise TypeError("Native second address record required")
        channel = VendorCAN2026(self.runtime, address, phase5=True, pending_seconds=30)
        identifier = channel.diag.start_filter(*_vendor_headers(channel.address))
        try:
            SBRUtils2026(
                channel, wait_after_function=self.wait_after_function
            ).programming_session()
        finally:
            self.runtime.release("stop_filter", identifier=identifier)


def prepare_sbr(
    context: Vendor2026Context,
    runtime: NativeRuntime2026,
    *,
    key_provider,
    gateway_key_provider,
    retry_export=False,
) -> dict:
    """2026 SBR native preparation and distinct PrepareRetry short/full branch."""
    if (
        not isinstance(context, Vendor2026Context)
        or context.family != "SBR"
        or context.stage not in ("prepare", "write")
        or type(retry_export) is not bool
    ):
        raise ValueError("Exact native SBR preparation/retry context required")
    if not callable(key_provider) or not callable(gateway_key_provider):
        raise TypeError("Authorized SBR/gateway byte transformations required")
    selection = context.selection
    main_address = (
        context.address_groups[0][0]
        if context.stage == "write"
        else context.addresses[0]
    )
    channel = VendorCAN2026(runtime, main_address, phase5=True, pending_seconds=30)
    utility = SBRUtils2026(
        channel,
        wait_after_function=_flag(selection, "FlagToWaitAfterFuncReq"),
        cpu_type=selection.metadata.cpu.values.get("cputype", ""),
    )
    utility.context = context
    active = getattr(runtime._device_calls, "control_export", None)
    if active is not None:
        engine, controller, target = active
        if controller.runtime is not runtime:
            raise ValueError("Active source-issued SBR runtime required")
        utility._control_ssm_issued = True
        engine.worker._bind_sbr_ssm_producer2026(utility, target)
    central = _flag(selection, "FlagToCentralGateway")
    utility.central_gateway = central
    if retry_export and not _flag(selection, "FlagToSendAllOnPrepareRetry"):
        utility.extended_session()
        utility.collate_gateway(gateway_key_provider)
        utility.central_gateway_routine(0)
        if not central:
            utility.wait_after(220)
            utility.central_gateway_routine(1)
        return {
            "state": "prepare_completed",
            "native_branch": "retry_gateway_only",
            "physical_status": "PHYSICAL_UNCONFIRMED",
        }
    runtime.call("set_timeout", milliseconds=100)
    index = native2026_global_cpu_index(selection.metadata)
    error_kind = 2 if context.native_retry else context.native_error_kind
    if error_kind != 0 or index != 1:
        runtime.call("set_local_time_to_previous_send_time")
        retry_wait = _decimal(selection, "WaitTimeAfterIGOnAtRetry")
        channel.wait(retry_wait if context.native_writing and retry_wait else 10000)
        utility.extended_session()
        if not central or not context.native_writing:
            utility.collate_gateway(gateway_key_provider)
            utility.central_gateway_routine(0)
        utility.diagnostic_mask()
        utility.stop_communication()
        if not central:
            utility.central_gateway_routine(1)
    master, slave = _flag(selection, "MasterFlag"), _flag(selection, "SlaveFlag")
    if slave and (error_kind != 0 or index == 0):
        if len(context.addresses) < 2:
            raise ValueError("Native SBR slave requires second master address record")
        utility.programming_master(context.addresses[1])
    identifier = channel.diag.start_filter(*_vendor_headers(channel.address))
    try:

        def authorization():
            utility.collate_seed_key(
                key_provider,
                aes=_flag(selection, "FlagToEncryptLogicForAES"),
                encrypt=_flag(selection, "FlagToCalcKeyLogicForEncrypt"),
            )

        if master or slave:
            utility.unit_status()
            utility.programming_session()
            authorization()
        else:
            authorization()
            if _flag(selection, "FlagToUnitStatusCheck"):
                utility.unit_status()
            utility.programming_session()
    finally:
        runtime.release("stop_filter", identifier=identifier)
    return {
        "state": "prepare_completed",
        "native_branch": "full",
        "native_error_kind": error_kind,
        "physical_status": "PHYSICAL_UNCONFIRMED",
    }


def write_sbr(
    context: Vendor2026Context,
    runtime: NativeRuntime2026,
    *,
    notify: Callable[[str, int], None] = lambda _kind, _value: None,
) -> dict:
    """Native SBR erase/download/addressed transfer/exit/sumcheck per selected CPU."""
    if (
        not isinstance(context, Vendor2026Context)
        or context.family != "SBR"
        or context.stage != "write"
        or not callable(notify)
    ):
        raise ValueError("Exact SBR2026 writer context and progress observer required")
    progress = _sbr_control_progress2026(context, runtime)
    if progress is None:
        index = native2026_global_cpu_index(context.selection.metadata)
        files = context.files
    else:
        index = progress["target"].entry_cpu_index
        files = _sbr_control_cpu_files2026(progress, index)
    return _write_sbr_cpu(
        context,
        runtime,
        index,
        files,
        notify,
        progress,
    )


def _sbr_control_progress2026(context, runtime):
    active = getattr(runtime._device_calls, "control_export", None)
    if active is None:
        return None
    from scripts.cuw_2026 import CUWEngine2026
    from scripts.programming_2026_common import (
        NativeControlContext2026,
        NativeControlExportTarget2026,
    )

    if type(active) is not tuple or len(active) != 3:
        raise ValueError("Exact scoped SBR CONTROL export required")
    engine, controller, target = active
    control = controller.native_control_context2026(engine)
    if (
        type(engine) is not CUWEngine2026
        or type(control) is not NativeControlContext2026
        or type(target) is not NativeControlExportTarget2026
        or controller.runtime is not runtime
        or engine._controller_execution is not controller
        or engine.worker.controller is not controller
        or engine.worker.runtime is not runtime
        or engine._controller_export_target2026 is not target
        or target._context is not control
        or target.binding.operation != "write"
        or target.module_binding.module_name != "TCUWCanSBRFlashWriter.dll"
        or context.family != "SBR"
        or context.stage != "write"
        or context.identity.module_name != "TCUWCanSBRFlashWriter.dll"
        or context.selection is not target.binding
    ):
        raise ValueError("Exact source-issued SBR writer progress scope required")
    target.validate(engine, controller)
    counts, percentages = control.count_scratch, control.percentage_scratch
    capacity = min(len(counts), len(percentages), len(control.target_indices))
    if not 0 <= target.entry_cpu_index < capacity:
        raise ValueError("SBR writer entry CPU is outside CONTROL scratch")
    return {
        "context": context,
        "runtime": runtime,
        "engine": engine,
        "controller": controller,
        "target": target,
        "control": control,
        # ponytail: Load source geometry only when the native loop enters a CPU;
        # malformed future rows must not preempt current-CPU I/O.
        "files": [None] * capacity,
        "totals": [None] * capacity,
        "cumulative": [0] * capacity,
    }


def _sbr_control_cpu_files2026(progress, index):
    files = progress["files"][index]
    if files is None:
        files = _sbr_files(
            progress["control"].metadata_for_cpu(index).cpu,
            progress["context"].selection,
        )
        progress["files"][index] = files
        progress["totals"][index] = sum(file.size for file in files)
    return files


def _validate_sbr_control_progress2026(progress) -> None:
    context = progress["context"]
    expected_runtime = progress["runtime"]
    engine, controller, target, control = (
        progress[key] for key in ("engine", "controller", "target", "control")
    )
    runtime = controller.runtime
    if (
        runtime is not expected_runtime
        or type(context) is not Vendor2026Context
        or context.family != "SBR"
        or context.stage != "write"
        or context.identity.module_name != "TCUWCanSBRFlashWriter.dll"
        or context.selection is not target.binding
        or getattr(runtime._device_calls, "control_export", None)
        != (engine, controller, target)
        or engine._controller_execution is not controller
        or engine.worker.controller is not controller
        or engine.worker.runtime is not runtime
        or engine._controller_export_target2026 is not target
        or controller.native_control_context2026(engine) is not control
        or target._context is not control
    ):
        raise ValueError("SBR writer progress scope expired or was replaced")
    target.validate(engine, controller)


def _publish_sbr_control_progress2026(progress, kind, index, *, cleanup=False):
    _validate_sbr_control_progress2026(progress)
    if kind not in ("count", "percent"):
        raise ValueError("Native SBR progress callback kind required")
    control = progress["control"]
    if type(index) is not int or not 0 <= index < len(progress["files"]):
        raise ValueError("SBR writer progress CPU index is outside CONTROL scratch")
    if kind == "count":
        value = control.count_scratch[index]
        operation = "notify_progress_count"
        fields = {"cpu_index": index, "transferred_bytes": value}
    else:
        value = control.percentage_scratch[index]
        operation = "notify_progress_percent"
        fields = {"cpu_index": index, "progress": value}
    progress["controller"].runtime.call(operation, cleanup=cleanup, **fields)


def _write_sbr_cpu(
    context: Vendor2026Context,
    runtime: NativeRuntime2026,
    index: int,
    files: tuple[SBRFile, ...],
    notify,
    control_progress=None,
) -> dict:
    cpu_count = (
        len(control_progress["files"])
        if control_progress is not None
        else native2026_cpu_count(context.selection.metadata)
    )
    if index >= cpu_count or index >= len(context.address_groups):
        raise ValueError("Native SBR CPU-indexed address vector absent")
    runtime.call("set_timeout", milliseconds=5000)
    total = (
        control_progress["totals"][index]
        if control_progress is not None
        else sum(file.size for file in files)
    )
    if control_progress is None:
        completed = (
            context.native_percentages[index] == 100
            and context.native_counts[index] == total
        )
    else:
        _validate_sbr_control_progress2026(control_progress)
        completed = (
            control_progress["control"].percentage_scratch[index] == 100
            and control_progress["control"].count_scratch[index] == total
        )
    if completed:
        return {
            "state": "writer_completed",
            "transferred": 0,
            "next_cpu_index": index,
            "native_skipped_completed": True,
            "physical_status": "PHYSICAL_UNCONFIRMED",
        }
    channel = VendorCAN2026(
        runtime, context.address_groups[index][0], phase5=True, pending_seconds=30
    )
    utility = SBRUtils2026(
        channel, wait_after_function=_flag(context.selection, "FlagToWaitAfterFuncReq")
    )
    identifier = channel.diag.start_filter(*_vendor_headers(channel.address))
    transferred = 0 if control_progress is not None else context.native_counts[index]
    writing = False
    total = total or sum(file.size for file in files)
    failure = None

    def routine(file, checking):
        utility.start_periodic()
        previous = channel.pending_seconds
        channel.pending_seconds = (
            (_decimal(context.selection, "ReceveTimeoutSumCheck") or 30)
            if checking
            else 30
        )
        try:
            payload = b"\x31\x01\xff" + bytes((int(checking),))
            expected = (
                b"\x71\x01\xff"
                + bytes((int(checking),))
                + (b"\x01" if checking else b"")
            )
            channel.call(
                payload + file.area, expected, len(expected), 89 if checking else 90
            )
        finally:
            channel.pending_seconds = previous
            utility.stop_periodic()
        utility.wait_after(60)
        utility.tester()

    try:
        for file in files:
            runtime.check()
            notify("writing", 1)
            writing = True
            runtime.check()
            if file.erase:
                routine(file, False)
            answer = channel.call(b"\x34\x04" + file.area, b"\x74\x20", 4, 26)
            utility.tester()
            width = (
                min(int.from_bytes(answer[2:4], "big"), 4095) - (file.alfid >> 4) - 2
            )
            if width <= 0:
                raise CommonResponseError(26, answer)
            if file.padded and len(file.segment.data) % width:
                raise ValueError(
                    "Native padded SBR transfer would read beyond imported archive"
                )
            for sequence, offset in enumerate(
                range(0, len(file.segment.data), width), 1
            ):
                chunk = file.segment.data[offset : offset + width]
                counter = sequence & 255
                payload = (
                    bytes((0x36, counter))
                    + (file.segment.address + offset).to_bytes(4, "big")
                    + chunk
                )
                channel.call(payload, bytes((0x76, counter)), 2, 34)
                utility.tester()
                transferred += len(chunk)
                if control_progress is None:
                    runtime.check()
                    notify("count", transferred)
                    runtime.check()
                    notify("percent", transferred * 100 // total)
                else:
                    cumulative = control_progress["cumulative"][index] + len(chunk)
                    control_progress["cumulative"][index] = cumulative
                    _publish_sbr_control_progress2026(control_progress, "count", index)
                    count = int((float(cumulative) / float(total)) * float(total))
                    control_progress["control"]._store_count2026(
                        control_progress["target"], index, count & 0xFFFFFFFF
                    )
                    percentage = int((float(cumulative) / float(total)) * 100.0)
                    control_progress["control"]._store_percentage2026(
                        control_progress["target"],
                        index,
                        percentage & 0xFFFFFFFF,
                    )
                    _publish_sbr_control_progress2026(
                        control_progress, "percent", index
                    )
                runtime.check()
            channel.call(b"\x37", b"\x77", 1, 28)
            utility.tester()
            routine(file, True)
        notify("writing", 0)
        writing = False
        runtime.check()
    except (
        CommonResponseError,
        NativePassThruException2026,
        NativeTransportError,
    ) as error:
        failure = error
        error.__dict__["native_writing"] = writing
        runtime.check()
        if control_progress is None:
            runtime.check()
            notify("count", 0)
            runtime.check()
            notify("percent", 0)
        else:
            _validate_sbr_control_progress2026(control_progress)
            control_progress["control"]._store_count2026(
                control_progress["target"], index, 0
            )
            _publish_sbr_control_progress2026(
                control_progress, "count", index, cleanup=True
            )
            control_progress["control"]._store_percentage2026(
                control_progress["target"], index, 0
            )
            _publish_sbr_control_progress2026(
                control_progress, "percent", index, cleanup=True
            )
        runtime.check()
        raise
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            runtime.release("stop_filter", identifier=identifier)
        except (Exception, KeyboardInterrupt) as error:
            if failure:
                failure.add_note(
                    "SBR writer filter release failed: " + type(error).__name__
                )
            else:
                raise
    next_cpu_index = index + 1
    if (
        not _flag(context.selection, "CpuLoopBetweenPrepareAndWriteFlag")
        and index + 1 < cpu_count
    ):
        # Native ctor10b0 retains its one CParameter pointer throughout1aa0.
        next_files = (
            _sbr_control_cpu_files2026(control_progress, index + 1)
            if control_progress is not None
            else _sbr_files(
                native2026_metadata_for_cpu(context.selection.metadata, index + 1).cpu,
                context.selection,
            )
        )
        runtime.check()
        notify("next_cpu", index + 1)
        runtime.check()
        next_result = _write_sbr_cpu(
            context, runtime, index + 1, next_files, notify, control_progress
        )
        transferred += next_result["transferred"]
        next_cpu_index = next_result["next_cpu_index"]
    return {
        "state": "writer_completed",
        "transferred": transferred,
        "next_cpu_index": next_cpu_index,
        "native_error_kind": 0,
        "native_flag_964": False,
        "native_flag_978": _flag(context.selection, "CpuLoopBetweenPrepareAndWriteFlag")
        and index + 1 < cpu_count,
        "native_cpu_loop": not _flag(
            context.selection, "CpuLoopBetweenPrepareAndWriteFlag"
        ),
        "physical_status": "PHYSICAL_UNCONFIRMED",
    }


def run_native(
    context: Vendor2026Context,
    runtime: NativeRuntime2026,
    *,
    entrypoint: str | None = None,
    key_provider=None,
    gateway_key_provider=None,
    notify=lambda _kind, _value: None,
) -> dict:
    """Dispatch exact recovered callable exports, never a legacy filename alias."""
    if not isinstance(context, Vendor2026Context) or not isinstance(
        runtime, NativeRuntime2026
    ):
        raise TypeError("Bound native vendor context/runtime required")
    source = context.selection.metadata.source_container
    if not isinstance(source, CalibrationContainer):
        raise TypeError("Imported source container required for vendor revalidation")
    expected_context = bind_native_context(
        source,
        context.selection.metadata.node,
        context.observed_cids,
        context.selection,
        context.identity,
        {},
        context.observations,
    )
    if context != expected_context:
        raise ValueError(
            "Vendor execution context differs from imported source binding"
        )
    expected = {
        "get_cid": "StartGetCID",
        "prepare": "StartPrepareWrite",
        "write": "StartFlashWrite",
    }[context.stage]
    entrypoint = expected if entrypoint is None else entrypoint
    if entrypoint not in context.identity.callable_exports or entrypoint not in (
        expected,
        "PrepareRetry",
    ):
        raise ValueError("Export is absent from this exact recovered2026 identity")
    runtime.check()
    native_success = True
    try:
        if entrypoint == "PrepareRetry":
            result = (
                prepare_sbr(
                    context,
                    runtime,
                    key_provider=key_provider,
                    gateway_key_provider=gateway_key_provider,
                    retry_export=True,
                )
                if context.family == "SBR"
                else prepare_hino(context, runtime, key_provider=key_provider)
            )
        elif context.stage == "get_cid":
            result = get_identifiers(context, runtime)
        elif context.stage == "prepare":
            result = (
                prepare_sbr(
                    context,
                    runtime,
                    key_provider=key_provider,
                    gateway_key_provider=gateway_key_provider,
                )
                if context.family == "SBR"
                else prepare_hino(context, runtime, key_provider=key_provider)
            )
        else:
            result = (
                write_sbr(context, runtime, notify=notify)
                if context.family == "SBR"
                else write_hino(context, runtime, notify=notify)
            )
    except (
        CommonResponseError,
        NativePassThruException2026,
        NativeTransportError,
    ) as error:
        runtime.check()
        native_success = False
        native_error, driver_error = native_error_fields2026(error)
        result = {
            "state": "failed",
            "native_error_code": native_error,
            "driver_error_code": driver_error,
            "native_result_code": 2
            if getattr(error, "native_writing", context.native_writing)
            else 1,
            "retry_available": context.family == "SBR"
            and _flag(context.selection, "IGOffRetriableFlag"),
            "cleanup_errors": tuple(getattr(error, "__notes__", ())),
            "physical_status": "PHYSICAL_UNCONFIRMED",
        }
    runtime.check()
    native_success = result.get("native_success", native_success)
    result.update(
        native_success=native_success,
        native_return=None if entrypoint == "StartGetCID" else native_success,
        native_build="2026",
        source_sha256=context.identity.sha256,
        entrypoint=entrypoint,
    )
    return result


def bind_sbr_utility(
    identity: NativeModuleIdentity,
    context: Vendor2026Context,
    runtime: NativeRuntime2026,
) -> SBRUtils2026:
    """Bind all eighteen exact SBRUtils callable exports to concrete primitives."""
    if (
        not isinstance(identity, NativeModuleIdentity)
        or identity.module_name != "TCUWSBRUtils.dll"
        or identity.cuw_build != "2026"
        or identity != identify_native_module(identity.sha256, identity.module_name)
    ):
        raise ValueError("Exact actual2026 SBRUtils identity required")
    if not isinstance(context, Vendor2026Context) or context.family != "SBR":
        raise TypeError("Native SBR source context required")
    metadata = context.selection.metadata
    expected = bind_native_context(
        metadata.source_container,
        metadata.node,
        context.observed_cids,
        context.selection,
        context.identity,
        {},
        context.observations,
    )
    if context != expected:
        raise ValueError("SBR utility context differs from native imported source")
    utility = SBRUtils2026(
        VendorCAN2026(runtime, context.addresses[0], phase5=True, pending_seconds=30),
        wait_after_function=_flag(context.selection, "FlagToWaitAfterFuncReq"),
        cpu_type=metadata.cpu.values.get("cputype", ""),
    )
    utility.identity = identity
    utility.context = context
    utility.central_gateway = _flag(context.selection, "FlagToCentralGateway")
    return utility


def execute_sbr_utility(utility: SBRUtils2026, export: str, **arguments):
    """Literal export dispatch; providers never decide a diagnostic operation result."""
    if (
        not isinstance(utility, SBRUtils2026)
        or not isinstance(utility.identity, NativeModuleIdentity)
        or not isinstance(utility.context, Vendor2026Context)
        or utility.identity.module_name != "TCUWSBRUtils.dll"
        or utility.identity.cuw_build != "2026"
        or utility.identity
        != identify_native_module(utility.identity.sha256, utility.identity.module_name)
        or export not in utility.identity.callable_exports
    ):
        raise ValueError("Bound exact SBRUtils callable export required")
    context = utility.context
    metadata = context.selection.metadata
    expected = bind_native_context(
        metadata.source_container,
        metadata.node,
        context.observed_cids,
        context.selection,
        context.identity,
        {},
        context.observations,
    )
    if (
        context != expected
        or utility.channel.address != context.addresses[0]
        or utility.runtime is not utility.channel.runtime
        or utility.cpu_type != metadata.cpu.values.get("cputype", "")
        or utility.central_gateway != _flag(context.selection, "FlagToCentralGateway")
        or utility.wait_after_function
        != _flag(context.selection, "FlagToWaitAfterFuncReq")
    ):
        raise ValueError("SBR utility differs from imported source binding")
    if export.startswith("??0CSBRUtils@"):
        if arguments:
            raise ValueError("Constructor context is already bound")
        return utility
    utility.runtime.check()
    name = export.split("@", 1)[0].removeprefix("?")
    if name == "CalcCipherFuncF":
        return sbr_cipher_function(**arguments, substitution=utility.substitution)
    if name == "CalcSeedKeyForDES":
        result = sbr_des_key(**arguments)
        utility.substitution = arguments["substitution"]
        return result
    if name == "CalcSeedKey":
        return utility.calc_seed_key(
            **arguments,
            aes=True,
            encrypt=_flag(context.selection, "FlagToCalcKeyLogicForEncrypt"),
        )
    if name == "GetSecretInfoType":
        if arguments:
            raise ValueError("Native GetSecretInfoType takes no arguments")
        return sbr_secret_type(utility.cpu_type, utility.ssm)
    if name == "ProgrammingSessionControlForMaster":
        if arguments or len(context.addresses) < 2:
            raise ValueError("Native master method requires bound second address")
        return utility.programming_master(context.addresses[1])
    if name == "CollateSeedKey":
        return utility.collate_seed_key(
            **arguments,
            aes=_flag(context.selection, "FlagToEncryptLogicForAES"),
            encrypt=_flag(context.selection, "FlagToCalcKeyLogicForEncrypt"),
        )
    if name == "ReadSSMID":
        return utility.read_ssm(central_gateway=utility.central_gateway, **arguments)
    methods = {
        "CollateSeedKeyForCentralGW": utility.collate_gateway,
        "DiagnosticMask": utility.diagnostic_mask,
        "ExtendedDiagnosticSessionControl": utility.extended_session,
        "ProgrammingSessionControl": utility.programming_session,
        "RoutineControlForCentralGW": utility.central_gateway_routine,
        "SendTesterPresent": utility.tester,
        "StartSyncPeriodicMsg": utility.start_periodic,
        "StopCommunication": utility.stop_communication,
        "UnitStatusCheck": utility.unit_status,
        "WaitAfterFuncReq": utility.wait_after,
    }
    if name not in methods:
        raise ValueError("SBR export has no audited implementation")
    utility.runtime.check()
    result = methods[name](**arguments)
    utility.runtime.check()
    return result
