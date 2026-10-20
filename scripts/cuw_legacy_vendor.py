"""Original CUW vendor controllers and wire helpers, without PE execution.

EMPS/DCM/DH/FHI Execute is authored; complete vendor-family parity, outer recovery
consumer composition and independent source review remain separate gates.
Requests exclude the four-byte CAN identifier carried by PASSTHRU_MSG.Data.
"""

from __future__ import annotations

from collections.abc import Callable
from fractions import Fraction

from scripts.cuw_legacy_body import diagnostic
from scripts.cuw_legacy_can import CommonCAN, ExecutableCANError
from scripts.cuw_legacy_channel import ChannelState, channel_state
from scripts.cuw_legacy_engine import (
    ExecutableContext,
    ExecutableImage,
    ExecutableIO,
    ExecutableJ2534Error,
    ExecutableNativeError,
    executable_constructor_timeout,
    executable_j2534_call,
    executable_reconnect,
    executable_start_filter,
    executable_stop_filter,
    executable_sync,
    legacy_executable_bytes,
)
from scripts.j2534_2026 import j2534_indication
from scripts.programming_legacy import materialize_legacy_image


def prepare_emps(context: ExecutableContext, io: ExecutableIO) -> tuple[int, int]:
    """12 52d218/52edb8 and18 57625c/577bc8 setup before session selection.

    Acquired filters remain owned by the host runtime if a later primitive fails.
    The caller owns the separate native stop loop and outer host cleanup.
    """
    channel, frame = _emps_startup_channel(context, io)
    _emps_configure(io)
    handles: list[int] = []
    _emps_start(context, channel, frame, handles)
    return handles[0], handles[1]


def _emps_configure(io: ExecutableIO) -> None:
    result = executable_j2534_call(
        io,
        "ioctl",
        ioctl_id=2,
        input={"num_params": 1, "config": ((0x23, 2),)},
        output=None,
    )
    if result is not None:
        raise ValueError("Native SET_CONFIG must return None")


def _emps_startup_channel(
    context: ExecutableContext, io: ExecutableIO
) -> tuple[CommonCAN, bytes]:
    emps_header_pairs(context)
    image = ExecutableImage(context)
    base = {12: 0x52EDDD, 18: 0x577BED}[context.build]
    frame = b"".join(image.read(base + index * 4 + 3, 1) for index in range(6))
    return CommonCAN.from_io(
        io, frame[:4], frame[:4], state=channel_state(context)
    ), frame


def _emps_start(
    context: ExecutableContext, channel: CommonCAN, frame: bytes, handles: list[int]
) -> None:
    for request, response in emps_header_pairs(context):
        handles.append(
            executable_start_filter(
                channel.io, request, response, padding=channel.padding
            )
        )
    # 470b8c includes CLEAR_RX_BUFFER, WriteMsgs and matching TX indication.
    for _ in range(3):
        channel.write(frame[4:])
        channel.wait(100)


def emps_header_pairs(context: ExecutableContext) -> tuple[tuple[bytes, bytes], ...]:
    """Decode original12/18 startup initializer operands; the globals are BSS."""
    if (
        not isinstance(context, ExecutableContext)
        or context.build not in (12, 18)
        or context.controller != "CCanEMPS_V850E_PS2FlashWriter"
    ):
        raise ValueError("Original12/18 EMPS executable context required")
    image = ExecutableImage(context)
    operands = {
        12: ((0x52D058, 1), (0x52D06A, 1), (0x52D07C, 4), (0x52D091, 4)),
        18: ((0x5760A0, 1), (0x5760B2, 1), (0x5760C4, 4), (0x5760D9, 4)),
    }[context.build]
    headers = tuple(
        int.from_bytes(image.read(address, width), "little").to_bytes(4, "big")
        for address, width in operands
    )
    return ((headers[0], headers[1]), (headers[2], headers[3]))


def bind_emps_regions(context: ExecutableContext) -> tuple[bytes, bytes]:
    """57625c consumes loader +24/+10 and main +20/+1c after 47b1c8.

    The main count is SREC data length, distinct from the materialized span.
    Flash-code conversion follows the native main-image SREC/VBF branch.
    """
    if (
        not isinstance(context, ExecutableContext)
        or context.build not in (12, 18)
        or context.controller != "CCanEMPS_V850E_PS2FlashWriter"
    ):
        raise ValueError("Original12/18 EMPS executable context required")
    legacy_executable_bytes(context)
    # Execute dereferences +20/+24 without DCM's explicit index*0x50 term.
    main = context.native.first_image
    code = context.native.cpus[0].flash_code
    if (
        main is None
        or code is None
        or not isinstance(main.data, bytes)
        or type(main.flash_size) is not int
        or not 0 <= main.flash_size <= len(main.data) <= 64 * 1024 * 1024
        or not isinstance(code.data, bytes)
        or not 0 < len(code.data) <= 64 * 1024 * 1024
    ):
        raise ValueError("Bounded imported native EMPS image and flash-code required")
    if main.base_address is None:
        loader = code.data
    else:
        if not code.data.startswith(b"S"):
            raise ValueError("Native SREC main-image path requires SREC flash-code")
        loader = materialize_legacy_image(code.data).data
    return loader, main.data[: main.flash_size]


class LegacyVendorResponseError(ExecutableCANError):
    """Recovered native CPassThruException error code and diagnostic payload."""

    def __init__(self, code: int, response: bytes):
        super().__init__(code)
        self.response = response


class EMPSController:
    """Original12/18 CAN EMPS Execute, including native GUI/error branches.

    Native completion is distinct from the enclosing host cleanup disposition.
    A returned result is synthetic-provider evidence until physical validation.
    """

    def __init__(self, context: ExecutableContext, io: ExecutableIO):
        self.loader, self.main = bind_emps_regions(context)
        protocol = context.observations.get("protocol_id")
        if type(protocol) is not int or protocol != 6:
            raise ValueError("Actual native CAN connection protocol6 required")
        self.image = ExecutableImage(context)
        self.context, self.io = context, io
        self.channel, self.startup = _emps_startup_channel(context, io)
        current_timeout = self.channel.timeout_ms
        if current_timeout is None:
            raise ValueError("Actual source channel read timeout required")
        self.current_timeout: int = current_timeout
        self.saved_timeout = executable_constructor_timeout(context)
        # 46aadc/444718 initializes these controller fields before Execute.
        self.flag_68 = False
        self.value_78 = self.value_80 = 0
        self.status_70 = self.status(0)

    def status(self, index: int) -> int:
        base = 0x5F1A48 if self.context.build == 18 else 0x59A7F0
        return int.from_bytes(self.image.read(base + index * 4, 4), "little")

    def error(self, error: ExecutableJ2534Error | ExecutableCANError) -> None:
        category = (
            error.native_code if isinstance(error, ExecutableJ2534Error) else error.code
        )
        if type(category) is not int or not -128 <= category <= 255:
            raise ValueError("Native exception category must retain one byte")
        self.value_78 = ((category & 255) - (256 if category & 128 else 0)) & 0xFFFFFFFF
        if isinstance(error, ExecutableJ2534Error):
            self.value_80 = error.driver_status

    def error_handler(self) -> None:
        """5778a0/52ea58: prompt, optional native reconnect, typed retry."""
        executable_sync(self.io, "value_70", value=self.status_70)
        while True:
            executable_sync(
                self.io,
                "values_78_80",
                value_78=self.value_78,
                value_80=self.value_80,
            )
            executable_sync(self.io, "flag_88", value=False)
            executable_sync(self.io, "error_handler")
            if not executable_sync(self.io, "read_flag_88"):
                self.flag_68 = True
                return
            self.value_78 = self.value_80 = 0
            try:
                executable_reconnect(self.context, self.io, 6)
            except ExecutableJ2534Error as error:
                self.error(error)
                self.status_70 = self.status(3)
                executable_sync(self.io, "value_70", value=self.status_70)
                continue
            return

    def run(self) -> dict:
        self.current_timeout = channel_state(self.context).read_timeout
        handles: list[int] = []
        native_success = False
        caught = False
        wire = None
        cleanup_errors: list[str] = []
        aborted: InterruptedError | TimeoutError | None = None
        try:
            # SET_CONFIG lies outside both source CJ/CPass phase scopes.
            _emps_configure(self.io)
            try:
                _emps_start(self.context, self.channel, self.startup, handles)
                wire = select_emps_session(
                    self.context,
                    self.io,
                    channel_flag_67=self.channel.padding,
                    read_timeout_ms=self.current_timeout,
                    send_timeout_ms=self.channel.send_timeout_ms,
                )
                wire.channel.send_timeout_ms = self.channel.send_timeout_ms
                wire.channel.wait(20)
                wire.security(self.context)
                wire.write_region(self.loader, 0)
            except (ExecutableJ2534Error, ExecutableCANError) as error:
                caught = True
                self.error(error)
                self.status_70 = self.status(1)
            if not caught:
                assert wire is not None
                try:
                    wire.write_region(self.main, 1)
                    wire.reset()
                    wire.channel.wait(3000)
                    native_success = True
                except (ExecutableJ2534Error, ExecutableCANError) as error:
                    caught = True
                    self.error(error)
                    self.status_70 = self.status(2)
            try:
                for handle in handles:
                    executable_stop_filter(self.io, handle)
            except (ExecutableJ2534Error, ExecutableCANError):
                # One native scope surrounds both calls; first failure skips second.
                pass
            if caught:
                self.error_handler()
            self.channel.set_timeout(self.saved_timeout)
            executable_sync(self.io, "flag_68", value=self.flag_68)
            executable_sync(
                self.io,
                "values_78_80",
                value_78=self.value_78,
                value_80=self.value_80,
            )
            executable_sync(self.io, "owner_clear")
            executable_sync(
                self.io,
                "completion",
                outcome="success" if native_success else "failure",
            )
        except (InterruptedError, TimeoutError) as error:
            aborted = error
            try:
                # Host abort policy restores entry-current RAM, not native +ac.
                self.channel.set_timeout(self.current_timeout, cleanup=True)
            except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001 - preserve host abort
                error.add_note(
                    "Host abort timeout restoration failed: "
                    + type(cleanup_error).__name__
                )
            raise
        finally:
            # Host policy runs even when native EH does not handle cancellation.
            cleanup_errors = self.io.close()
            if aborted is not None:
                for cleanup_error in cleanup_errors:
                    aborted.add_note(
                        "Host abort resource cleanup failed: " + cleanup_error
                    )
        return {
            "controller": self.context.controller,
            "success": native_success and not cleanup_errors,
            "native_success": native_success,
            "native_flag_68": self.flag_68,
            "native_value_78": self.value_78,
            "native_value_80": self.value_80,
            "host_cleanup_errors": cleanup_errors,
        }


def emps_accept_rxstatus(rx_status: int, channel_flag_67: bool) -> bool:
    """CUW18 46f464 mode 2 accepts only 470dd8 classification 3."""
    if type(rx_status) is not int or not 0 <= rx_status <= 0xFFFFFFFF:
        raise ValueError("Native RxStatus must be a DWORD")
    if type(channel_flag_67) is not bool:
        raise TypeError("Native channel +67 flag must be a boolean")
    return j2534_indication(rx_status, channel_flag_67) == 3


def dcm_seed_key(context: ExecutableContext, seed: bytes) -> bytes:
    """5709d4/52818c: original two-byte conversion using admitted operands."""
    if (
        not isinstance(context, ExecutableContext)
        or context.controller != "CCanDCMPRLFlashWriter"
        or not isinstance(seed, bytes)
        or len(seed) != 2
    ):
        raise ValueError("Original DCM context and two-byte seed required")
    image = ExecutableImage(context)
    slots = {12: (0x5281AE, 0x5281D3), 18: (0x5709F1, 0x570A02)}[context.build]
    first, second = (image.read(slot, 1)[0] for slot in slots)
    return bytes(((seed[1] + first) & 255, (seed[0] + seed[1] + second) & 255))


class DCMWire:
    """570a38/570cd0/5716c0..571db4 wire helpers over source45d458.

    Native controller fields, header construction, countdown and region selection
    belong to the controller binding; this class does not supply those inputs.
    """

    def __init__(self, context: ExecutableContext, channel: CommonCAN):
        if (
            not isinstance(context, ExecutableContext)
            or context.controller != "CCanDCMPRLFlashWriter"
            or not isinstance(channel, CommonCAN)
            or len(channel.request) != 5
            or len(channel.response) != 5
        ):
            raise ValueError("Source-selected DCM and exact five-byte headers required")
        legacy_executable_bytes(context)
        self.context, self.channel = context, channel

    def exchange(
        self, request: bytes, expected: bytes, minimum: int, code: int
    ) -> bytes:
        self.channel.wait(100)
        return diagnostic(
            self.channel,
            request,
            expected,
            minimum,
            code,
            padding=self.channel.padding,
            busy_retries=255,
            pending_responses=149,
            wait_ms=100,
        )

    def security(self) -> None:
        response = self.exchange(b"\x27\x01", b"\x67\x01", 3, 16)
        # Native minDataSize8 permits one seed byte; the read buffer is zeroed.
        seed = response[2:4].ljust(2, b"\0")
        self.exchange(
            b"\x27\x02" + dcm_seed_key(self.context, seed), b"\x67\x02", 2, 17
        )

    def reset(self) -> None:
        self.exchange(b"\x11\x01", b"\x51\x01", 2, 24)

    def routine(self, identifier: int, stage: int, argument: int = 1) -> None:
        if (
            type(identifier) is not int
            or not 0 <= identifier <= 0xFFFF
            or any(
                type(value) is not int or not 0 <= value <= 255
                for value in (stage, argument)
            )
        ):
            raise ValueError(
                "Native DCM routine requires WORD identifier and byte fields"
            )
        tail = bytes((stage,)) + identifier.to_bytes(2, "big")
        if stage != 1:
            tail += bytes((argument,))
        self.exchange(b"\x31" + tail, b"\x71" + tail, 1 + len(tail), 25)

    def download(self, offset: int, length: int) -> None:
        if any(
            type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (offset, length)
        ):
            raise ValueError("Native DCM block offset and length require DWORDs")
        # Native right-aligned resize419ed8 retains the low three bytes.
        request = (
            b"\x34\0\x33"
            + (offset & 0xFFFFFF).to_bytes(3, "big")
            + (length & 0xFFFFFF).to_bytes(3, "big")
        )
        self.exchange(request, b"\x74\x30", 5, 26)

    def transfer(self, payload: bytes, index: int) -> None:
        if (
            not isinstance(payload, bytes)
            or not 1 <= len(payload) <= 60
            or type(index) is not int
            or not 0 <= index <= 255
        ):
            raise ValueError("Native DCM transfer needs1..60 bytes and a byte index")
        # The source checks76 plus minimum size, without comparing echoed index.
        self.exchange(b"\x36" + bytes(((index + 1) & 255,)) + payload, b"\x76", 2, 27)

    def exit(self, checksum: int) -> None:
        if type(checksum) is not int or not 0 <= checksum <= 0xFFFF:
            raise ValueError("Native DCM checksum requires a WORD")
        self.exchange(b"\x37" + checksum.to_bytes(2, "big"), b"\x77", 1, 28)

    def write_region(
        self,
        payload: bytes,
        offset: int,
        length: int,
        *,
        transferred: Callable[[int], None],
    ) -> None:
        """5295e8/571db4 contiguous block: download, chunks, unsigned sum exit."""
        if (
            type(payload) is not bytes
            or len(payload) > 64 * 1024 * 1024
            or type(offset) is not int
            or type(length) is not int
            or not 0 <= offset <= len(payload)
            or not 0 <= length <= len(payload) - offset
            or not callable(transferred)
        ):
            raise ValueError("Bounded native DCM block and progress consumer required")
        self.download(offset, length)
        for index, position in enumerate(range(0, length, 60)):
            chunk = payload[offset + position : offset + min(position + 60, length)]
            self.transfer(chunk, index & 255)
            transferred(len(chunk))
        self.exit(sum(payload[offset : offset + length]) & 0xFFFF)


def _vendor_resource(context: ExecutableContext, slot12: int, slot18: int) -> str:
    """Read a bounded source string through the admitted image's pointer slot."""
    image = ExecutableImage(context)
    slot = slot12 if context.build == 12 else slot18
    address = int.from_bytes(image.read(slot, 4), "little")
    value = bytearray()
    for offset in range(129):
        byte = image.read(address + offset, 1)
        if byte == b"\0":
            return value.decode("ascii")
        value.extend(byte)
    raise ValueError("Bounded terminated native vendor resource required")


class DCMController:
    """528598/570db0 DCM Execute through concrete native CAN operations.

    Explicit native exception identity retains catch-all phase behavior; host
    validation/cancellation errors never masquerade as native exceptions.
    """

    status = EMPSController.status
    error = EMPSController.error

    def __init__(self, context: ExecutableContext, io: ExecutableIO):
        from scripts.cuw_legacy_addresses import (
            legacy_address_inputs,
            select_legacy_addresses,
        )
        from scripts.cuw_legacy_engine import executable_cpu_type

        if (
            not isinstance(context, ExecutableContext)
            or context.controller != "CCanDCMPRLFlashWriter"
            or not isinstance(io, ExecutableIO)
            or type(context.observations.get("protocol_id")) is not int
            or context.observations.get("protocol_id") != 6
            or context.state.write_cpu_index != context.native.selected.index
            or context.native.image is None
            or context.native.first_image is None
        ):
            raise ValueError("Source-selected imported CAN DCM image required")
        context.state.validate()
        self.main = context.native.image
        size = context.native.first_image.flash_size
        if (
            type(self.main.data) is not bytes
            or type(self.main.flash_size) is not int
            or not 0 <= self.main.flash_size <= len(self.main.data)
            or type(size) is not int
            or not 0 <= size <= len(self.main.data) <= 64 * 1024 * 1024
            or (size > 0 and self.main.flash_size == 0)
        ):
            raise ValueError("Native first-WORK DCM block vector exceeds selected data")
        self.blocks = (1024,) * (size // 1024) + ((size % 1024,) if size % 1024 else ())
        self.context, self.io = context, io
        self.image = ExecutableImage(context)
        kind, config, mode, factory = legacy_address_inputs(context)
        addresses = select_legacy_addresses(
            context, kind, config, reprog_mode=mode, factory_state=factory
        )
        if not addresses:
            raise ValueError("Native DCM requires the first produced address row")
        # Execute copies exactly three bytes, then right-aligns to five bytes.
        row = addresses[0].raw
        self.channel = CommonCAN.from_io(
            io, b"\0\0" + row[1:4], b"\0\0" + row[4:7], state=channel_state(context)
        )
        self.wire = DCMWire(context, self.channel)
        saved_timeout = self.channel.timeout_ms
        assert saved_timeout is not None
        self.saved_timeout: int = saved_timeout
        self.special_kind = kind == _vendor_resource(context, 0x585480, 0x5D519C)
        self.long_wait = not self.special_kind and executable_cpu_type(
            context, 0
        ) == _vendor_resource(context, 0x5852B8, 0x5D4FD4)
        self.routine_id = 0x0201 if self.special_kind else 0x0200
        self.flag_68 = False
        self.value_78 = self.value_80 = self.written_a4 = self.percent_ac = 0
        self.countdown_b8 = 0
        self.status_70 = self.status(0)
        self.second_phase_failed = False

    def notify(self, field: str, value: int) -> None:
        if self.io.call("notification", field=field, value=value) is not None:
            raise ValueError("Native DCM scalar notification must return None")

    def transferred(self, count: int) -> None:
        if not self.countdown_b8:
            self.countdown_b8 = 660000 if self.long_wait else 15000
            self.notify("waiting_milliseconds", self.countdown_b8)
        self.written_a4 = (self.written_a4 + count * 2) & 0xFFFFFFFF
        self.notify("writing_bytes", self.written_a4)
        # Native denominator is selected main flash_size, not block-vector size.
        self.percent_ac = (
            _x87_percent(self.written_a4 // 2, self.main.flash_size) & 0xFFFFFFFF
        )
        self.notify("writing_percent", self.percent_ac)

    def error_handler(self) -> None:
        executable_sync(self.io, "value_70", value=self.status_70)
        while True:
            executable_sync(
                self.io, "values_78_80", value_78=self.value_78, value_80=self.value_80
            )
            executable_sync(self.io, "flag_88", value=False)
            executable_sync(self.io, "error_handler")
            if not executable_sync(self.io, "read_flag_88"):
                self.flag_68 = True
                return
            self.context.state.retry_mode = True
            self.value_78 = self.value_80 = 0
            if self.second_phase_failed:
                self.written_a4 = self.percent_ac = 0
                self.notify("writing_bytes", 0)
                self.notify("writing_percent", 0)
            try:
                executable_reconnect(self.context, self.io, 6)
            except ExecutableJ2534Error as error:
                self.error(error)
                self.status_70 = self.status(3)
                executable_sync(self.io, "value_70", value=self.status_70)
                continue
            return

    def run(self) -> dict:
        self.saved_timeout = channel_state(self.context).read_timeout
        handles: list[int] = []
        native_success = False
        first_failed = False
        aborted: InterruptedError | TimeoutError | None = None
        try:
            self.notify("waiting_milliseconds", 0)
            try:
                self.channel.set_timeout(10000)
                handles.append(
                    executable_start_filter(
                        self.io,
                        self.channel.request,
                        self.channel.response,
                        padding=self.channel.padding,
                    )
                )
                if self.context.state.retry_mode:
                    self.wire.reset()
                    self.channel.wait(15000)
                self.wire.security()
            except (ExecutableJ2534Error, ExecutableCANError) as error:
                first_failed = True
                self.error(error)
            except ExecutableNativeError:
                first_failed = True
            if not first_failed:
                try:
                    self.wire.routine(self.routine_id, 1)
                    offset = 0
                    for length in self.blocks:
                        self.wire.write_region(
                            self.main.data, offset, length, transferred=self.transferred
                        )
                        offset += length
                    self.wire.routine(self.routine_id, 2)
                    self.wire.reset()
                    while self.countdown_b8:
                        self.channel.wait(500)
                        self.countdown_b8 -= 500
                        self.notify("waiting_milliseconds", self.countdown_b8)
                    native_success = True
                except (ExecutableJ2534Error, ExecutableCANError) as error:
                    self.second_phase_failed = True
                    self.error(error)
                except ExecutableNativeError:
                    self.second_phase_failed = True
            try:
                for handle in handles:
                    executable_stop_filter(self.io, handle)
            except (ExecutableNativeError, ExecutableCANError):
                pass
            if first_failed or self.second_phase_failed:
                self.status_70 = self.status(1 if first_failed else 2)
                self.error_handler()
            self.channel.set_timeout(self.saved_timeout)
            executable_sync(self.io, "flag_68", value=self.flag_68)
            executable_sync(
                self.io, "values_78_80", value_78=self.value_78, value_80=self.value_80
            )
            executable_sync(self.io, "owner_clear")
            executable_sync(
                self.io,
                "completion",
                outcome="success" if native_success else "failure",
            )
        except (InterruptedError, TimeoutError) as error:
            aborted = error
            try:
                self.channel.set_timeout(self.saved_timeout, cleanup=True)
            except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001 - preserve host abort
                error.add_note(
                    "Host abort timeout restoration failed: "
                    + type(cleanup_error).__name__
                )
            raise
        finally:
            cleanup_errors = self.io.close()
            if aborted is not None:
                for error_text in cleanup_errors:
                    aborted.add_note(
                        "Host abort resource cleanup failed: " + error_text
                    )
        return {
            "controller": self.context.controller,
            "success": native_success and not cleanup_errors,
            "native_success": native_success,
            "native_flag_68": self.flag_68,
            "native_value_78": self.value_78,
            "native_value_80": self.value_80,
            "host_cleanup_errors": cleanup_errors,
        }


class EMPSWire:
    """CUW18 577a30 receive policy over complete native message primitives.

    Header and channel flag producers must be bound separately by the controller.
    This class does not supply physical observations or infer programming success.
    """

    def __init__(
        self,
        io: ExecutableIO,
        request: bytes,
        response: bytes,
        *,
        channel_flag_67: bool,
        read_timeout_ms: int,
        state: ChannelState | None = None,
    ):
        if not all(
            isinstance(header, bytes) and len(header) == 4
            for header in (request, response)
        ):
            raise ValueError("Original EMPS headers require four bytes")
        emps_accept_rxstatus(0, channel_flag_67)
        if type(read_timeout_ms) is not int or not 0 <= read_timeout_ms <= 0xFFFFFFFF:
            raise ValueError("Native read timeout requires a DWORD")
        self.io, self.request, self.response = io, request, response
        self.channel = CommonCAN(
            io,
            request,
            response,
            padding=channel_flag_67,
            read_timeout_ms=read_timeout_ms,
            state=state,
        )
        self.written_9c = 0
        self.percent_a4 = 0

    @property
    def read_timeout_ms(self) -> int:
        value = self.channel.timeout_ms
        assert value is not None
        return value

    @read_timeout_ms.setter
    def read_timeout_ms(self, value: int) -> None:
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("Native read timeout requires a DWORD")
        self.channel.timeout_ms = value

    @property
    def channel_flag_67(self) -> bool:
        return self.channel.padding

    def write(self, payload: bytes) -> None:
        if not isinstance(payload, bytes) or not 1 <= len(payload) <= 4096:
            raise ValueError("Bounded native EMPS payload required")
        self.channel.timeout_ms = self.read_timeout_ms
        self.channel.write(payload)

    def read(self, service: int, error_code: int) -> bytes:
        if any(
            type(value) is not int or not 0 <= value <= 255
            for value in (service, error_code)
        ):
            raise ValueError("Native EMPS service and exception code require bytes")
        pending = 1
        while True:
            self.channel.timeout_ms = self.read_timeout_ms
            payload = self.channel.read(mode=2, padding=self.channel_flag_67)[4:]
            if not payload.startswith(bytes((0x7F, service, 0x78))):
                self.read_timeout_ms = 1000
                self.channel.set_timeout(1000)
                return payload
            if pending >= 150:
                self.write(b"\x3e\x02")
                raise LegacyVendorResponseError(error_code, payload)
            pending += 1
            self.read_timeout_ms = 5000
            self.channel.set_timeout(5000)

    def write_region(self, payload: bytes, selector: int) -> int:
        """CUW18 576f10 block choreography; returns acknowledged byte count.

        This is a native region algorithm, not the complete Execute operation.
        """
        if not isinstance(payload, bytes) or len(payload) > 64 * 1024 * 1024:
            raise ValueError("Bounded immutable EMPS region required")
        download = emps_download_request(selector)
        stage = 1 if selector == 0 else 2
        self._exchange(
            emps_routine_request(stage),
            "routine",
            0x24 + stage,
            pending_code=0x19,
            stage=stage,
        )
        self._exchange(download, "download", 0x1A)
        position = 0
        while position < len(payload):
            chunk = payload[position : position + 0xF0]
            self._exchange(emps_transfer_request(chunk), "transfer", 0x22)
            position += len(chunk)
            if selector == 1:
                self.written_9c = (self.written_9c + len(chunk)) & 0xFFFFFFFF
                self.percent_a4 = emps_percent(position, len(payload))
                for field, value in (
                    ("writing_bytes", self.written_9c * 2 & 0xFFFFFFFF),
                    ("writing_percent", self.percent_a4),
                ):
                    if (
                        self.io.call("notification", field=field, value=value)
                        is not None
                    ):
                        raise ValueError(
                            "Native scalar progress notification must return None"
                        )
        self._exchange(b"\x37", "exit", 0x24)
        self._exchange(
            emps_routine_request(3, payload),
            "routine",
            0x27,
            pending_code=0x19,
            stage=3,
        )
        return position

    def security(self, context: ExecutableContext) -> None:
        """12 52d9e4 /18 5769a4 fixed-key exchange from admitted source bytes.

        Native key bytes stay in the explicitly supplied original executable.
        No key is generated from the seed, and no source key is embedded here.
        """
        if (
            not isinstance(context, ExecutableContext)
            or context.build not in (12, 18)
            or context.controller != "CCanEMPS_V850E_PS2FlashWriter"
        ):
            raise ValueError("Original12/18 EMPS executable context required")
        image = ExecutableImage(context)
        addresses = {
            12: (0x52DBDE, 0x52DBEF, 0x52DBF9, 0x52DC00),
            18: (0x576B5F, 0x576B74, 0x576B7B, 0x576B82),
        }[context.build]
        key = b"".join(image.read(address, 1) for address in addresses)
        self._exchange(b"\x27\x01", "seed", 0x10)
        self._exchange(b"\x27\x02" + key, "key", 0x11)

    def reset(self) -> None:
        """12 52e8c4 /18 577730: 1101, pending18 and positive51."""
        self._exchange(b"\x11\x01", "reset", 0x18)

    def _exchange(
        self,
        payload: bytes,
        operation: str,
        code: int,
        *,
        pending_code: int | None = None,
        stage: int = 1,
    ) -> bytes:
        try:
            self.write(payload)
            reply = self.read(
                payload[0], code if pending_code is None else pending_code
            )
            emps_validate_response(operation, reply, stage=stage)
        except ExecutableJ2534Error as error:
            error.native_code = code
            raise
        return reply


def select_emps_session(
    context: ExecutableContext,
    io: ExecutableIO,
    *,
    channel_flag_67: bool,
    read_timeout_ms: int,
    send_timeout_ms: int | None = None,
) -> EMPSWire:
    """12 52d770 /18 576764: ordered 109202 probes; only read9/16 retry."""
    last = b""
    try:
        for request, response in emps_header_pairs(context):
            wire = EMPSWire(
                io,
                request,
                response,
                channel_flag_67=channel_flag_67,
                read_timeout_ms=read_timeout_ms,
                state=channel_state(context),
            )
            if send_timeout_ms is not None:
                wire.channel.send_timeout_ms = send_timeout_ms
            wire.write(b"\x10\x92\x02")
            try:
                last = wire.read(0x10, 0x12)
            except ExecutableJ2534Error as error:
                if error.driver_status not in (9, 16):
                    raise
                read_timeout_ms = wire.read_timeout_ms
                continue
            read_timeout_ms = wire.read_timeout_ms
            if last.startswith(b"\x50\x92"):
                return wire
    except ExecutableJ2534Error as error:
        error.native_code = 0x12
        raise
    raise LegacyVendorResponseError(0x12, last)


def emps_percent(position: int, total: int) -> int:
    """577557/52e6c5: x87 PC64 nearest FDIV/FMUL, then truncate.

    Original runtime initialization loads CW0x1332. Binary64 host division can
    publish a different integer at exact percentage boundaries.
    """
    if (
        type(position) is not int
        or type(total) is not int
        or not 0 <= position <= total <= 64 * 1024 * 1024
        or total == 0
    ):
        raise ValueError("Bounded native EMPS progress position and total required")

    return _x87_percent(position, total)


def _x87_percent(position: int, total: int) -> int:
    """PC64 arithmetic shared by native scalar producers, including over100 DCM."""

    def rounded(value: Fraction) -> Fraction:
        if not value:
            return value
        numerator, denominator = value.numerator, value.denominator
        exponent = numerator.bit_length() - denominator.bit_length()
        if (
            numerator < denominator << exponent
            if exponent >= 0
            else numerator << -exponent < denominator
        ):
            exponent -= 1
        shift = 63 - exponent
        quotient, remainder = divmod(numerator << shift, denominator)
        if remainder * 2 > denominator or (
            remainder * 2 == denominator and quotient & 1
        ):
            quotient += 1
        return Fraction(quotient, 1 << shift)

    return int(rounded(rounded(Fraction(position, total)) * 100))


def emps_routine_request(stage: int, payload: bytes = b"") -> bytes:
    """CUW18 576c9c: 31 01/02; stage 3 adds the modulo-256 byte sum."""
    if type(stage) is not int or stage not in (1, 2, 3):
        raise ValueError("EMPS routine stage must be 1, 2 or 3")
    if not isinstance(payload, bytes):
        raise TypeError("EMPS checksum input must be bytes")
    request = bytes((0x31, stage))
    return request + bytes((sum(payload) & 0xFF,)) if stage == 3 else request


def emps_download_request(selector: int) -> bytes:
    """CUW18 576ff0: native fixed addresses and lengths, not CUW image lengths."""
    if type(selector) is not int or selector not in (0, 1):
        raise ValueError("EMPS image selector must be 0 or 1")
    start, length = (0xFF8000, 0xB8C) if selector == 0 else (0x3900, 0x38700)
    return b"\x34" + start.to_bytes(3, "big") + b"\0" + length.to_bytes(3, "big")


def emps_transfer_request(payload: bytes) -> bytes:
    """CUW18 5773a4: service 36 immediately followed by up to F0 bytes."""
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= 0xF0:
        raise ValueError("EMPS transfer payload must contain 1..240 bytes")
    return b"\x36" + payload


def emps_validate_response(operation: str, response: bytes, *, stage: int = 1) -> None:
    """Actual helper checks after 577a30; trailing response bytes are accepted.

    This does not implement the read loop's pending/timeout/error semantics.
    """
    if not isinstance(response, bytes):
        raise TypeError("EMPS diagnostic response must be bytes")
    minimum = 0
    if operation == "routine":
        emps_routine_request(stage)
        expected, code = bytes((0x71, stage)), {1: 0x25, 2: 0x26, 3: 0x27}[stage]
    elif operation == "download":
        expected, code = b"\x74\0\xf1", 0x1A
    elif operation == "transfer":
        expected, code = b"\x76", 0x22
    elif operation == "exit":
        expected, code = b"\x77", 0x24
    elif operation == "reset":
        expected, code = b"\x51", 0x18
    elif operation == "seed":
        expected, code, minimum = b"\x67\x01", 0x10, 4
    elif operation == "key":
        expected, code = b"\x67\x02", 0x11
    else:
        raise ValueError("Unknown original EMPS operation")
    if len(response) < minimum or not response.startswith(expected):
        raise LegacyVendorResponseError(code, response)


def bind_techvim_finalize(context: ExecutableContext) -> bool:
    """Bind the original12/18 predicate to imported base metadata and PE strings.

    The caller must first establish the source controller's success callback pair.
    This predicate does not perform that success check or invoke finalization.
    """
    if (
        not isinstance(context, ExecutableContext)
        or context.controller != "CTechVimFlashWriter"
    ):
        raise ValueError("Original TechVim executable context required")
    image = ExecutableImage(context)
    slots = {
        12: (0x585544, 0x585548, 0x585474, 0x585478),
        18: (0x5D5260, 0x5D5264, 0x5D5190, 0x5D5194),
    }[context.build]

    def resource(slot: int) -> str:
        address = int.from_bytes(image.read(slot, 4), "little")
        value = bytearray()
        for offset in range(128):
            byte = image.read(address + offset, 1)
            if byte == b"\0":
                return value.decode("ascii")
            value.extend(byte)
        raise ValueError("Bounded terminated native TechVim resource required")

    family_a, family_b, subtype_first, subtype_second = map(resource, slots)
    metadata = context.native.base_metadata
    contact, kind = metadata["contact_type"], metadata["kind_of_ecu"]
    return techvim_needs_finalize(
        contact == family_a,
        contact == family_b,
        kind == subtype_first,
        kind == subtype_second,
        len(context.native.cpus),
        context.native.selected.index,
    )


def techvim_needs_finalize(
    family_a: bool,
    family_b: bool,
    subtype_first: bool,
    subtype_second: bool,
    cpu_count: int,
    cpu_index: int,
) -> bool:
    """CUW18 4a2e00 predicate after matching success status pair.

    Inputs are exact native string-comparison results; this helper deliberately
    does not guess the unresolved string resources or authorize finalization.
    """
    if any(
        type(flag) is not bool
        for flag in (family_a, family_b, subtype_first, subtype_second)
    ):
        raise ValueError("TechVim comparisons must be native boolean results")
    if (
        type(cpu_count) is not int
        or type(cpu_index) is not int
        or not 0 <= cpu_index < cpu_count <= 0x7FFFFFFF
    ):
        raise ValueError("Invalid native CPU count/index")
    return (family_a and not subtype_first and not subtype_second) or (
        (family_b or subtype_first or subtype_second) and cpu_count == cpu_index + 1
    )


class DHSource:
    """Original12/18 CPU table and passive initialization operands."""

    def __init__(self, context: ExecutableContext):
        if (
            not isinstance(context, ExecutableContext)
            or context.controller != "CCanDHFlashWriter"
        ):
            raise ValueError("Source-selected DH context required")
        self.context, self.image = context, ExecutableImage(context)
        build = context.build
        from scripts.cuw_legacy_engine import executable_cpu_type

        self.cpu_type = executable_cpu_type(context, 0)
        slots18 = (0x5D504C, 0x5D50C8, 0x5D5014, 0x5D50D8, 0x5D50DC, 0x5D50E0)
        names = tuple(self.resource(slot) for slot in slots18)
        self.index = next(
            (i for i, name in enumerate(names) if self.cpu_type == name), 6
        )
        self.special = self.cpu_type == names[2]
        self.short_seed = self.cpu_type == names[5]
        table = 0x5CBD68 if build == 12 else 0x6281E4
        self.flash_address = int.from_bytes(
            self.image.read(table + self.index * 12 + 4, 4), "little"
        ).to_bytes(4, "big")
        array_address = int.from_bytes(
            self.image.read(table + self.index * 12 + 8, 4), "little"
        )
        arrays = tuple(
            int.from_bytes(self.image.read(table + i * 12 + 8, 4), "little")
            for i in (0, 2, 1, 3, 5)
        )
        start, end, constructor = (
            (0x53F528, 0x53FDC6, 0x40E310)
            if build == 12
            else (0x58A870, 0x58B10E, 0x419BDC)
        )
        code = self.image.read(start, end - start)
        operands = []
        # Static resource extraction only: admitted source has95 ushort ctor calls.
        for offset in range(len(code) - 4):
            if (
                code[offset] != 0xE8
                or start
                + offset
                + 5
                + int.from_bytes(code[offset + 1 : offset + 5], "little", signed=True)
                != constructor
            ):
                continue
            candidates = [
                index
                for index in range(max(0, offset - 14), offset - 4)
                if code[index] == 0x68
                and int.from_bytes(code[index + 1 : index + 5], "little") <= 65535
            ]
            if len(candidates) != 1:
                raise ValueError("Native DH initializer operand must be unique")
            index = candidates[0]
            operands.append(
                int.from_bytes(code[index + 1 : index + 5], "little").to_bytes(2, "big")
            )
        if len(operands) != 95 or array_address not in arrays:
            raise ValueError("Exact source DH round-array producer required")
        position = arrays.index(array_address) * 19
        self.rounds = tuple(operands[position : position + 19])
        self.pending = int.from_bytes(
            self.image.read(0x5C5008 if build == 12 else 0x621484, 4), "little"
        )
        if not 0 <= self.pending <= 65535:
            raise ValueError("Bounded native DH pending-response limit required")

    def resource(self, slot18: int) -> str:
        return _vendor_resource(self.context, slot18 - 0x4FD1C, slot18)

    def key(self, seed: bytes) -> bytes:
        from scripts.programming_2026_dh import calculate_seed_key

        # Pure codec only; protocol/state algorithms remain original12/18 here.
        return calculate_seed_key(seed, self.rounds)

    def mask(self, raw: bool = False) -> bytes:
        base = ({12: 0x53F20C, 18: 0x58A55C} if raw else {12: 0x53F184, 18: 0x58A4D4})[
            self.context.build
        ]
        return b"".join(
            self.image.read(base + index * 4 + 3, 1)
            for index in range(12 if raw else 6)
        )


class DHWire:
    """Original12/18 DH diagnostic services over the shared native channel."""

    def __init__(self, source: DHSource, channel: CommonCAN):
        self.source, self.channel = source, channel

    def exchange(
        self, request: bytes, expected: bytes, minimum: int, code: int
    ) -> bytes:
        return diagnostic(
            self.channel,
            request,
            expected,
            minimum,
            code,
            padding=self.channel.padding,
            busy_retries=255,
            pending_responses=self.source.pending,
            wait_ms=0,
        )

    def session(self) -> None:
        self.exchange(b"\x10\x85", b"\x50\x85", 2, 18)

    def security(self) -> None:
        response = self.exchange(
            b"\x27\x01", b"\x67\x01", 6 if self.source.short_seed else 7, 16
        )
        self.exchange(
            b"\x27\x02" + self.source.key(response[2:6]), b"\x67\x02\x34", 3, 17
        )

    def download(self, length: int) -> int:
        reply = self.exchange(
            b"\x34\x01\x44" + self.source.flash_address + length.to_bytes(4, "big"),
            b"\x74\x20",
            4,
            26,
        )
        return self.block_size(reply[2:4])

    def verification_download(self, length: int) -> int:
        prefix = b"\x31\x01\xf0\x11\0\x01\x44"
        reply = self.exchange(
            prefix + self.source.flash_address + length.to_bytes(4, "big"),
            b"\x71\x01\xf0\x11\x20",
            7,
            32,
        )
        return self.block_size(reply[5:7])

    @staticmethod
    def block_size(encoded: bytes) -> int:
        size = (int.from_bytes(encoded, "big") - 1) & 0xFFFFFFFF
        if not size:
            raise ValueError("Native DH block size would divide by zero")
        return size

    def transfer(self, payload: bytes) -> None:
        self.exchange(b"\x36" + payload, b"\x76", 1, 34)

    def exit(self) -> None:
        self.exchange(b"\x37", b"\x77", 1, 28)

    def verify(self) -> None:
        self.exchange(b"\x31\x01\xf0\x11\x01", b"\x71\x01\xf0\x11\0", 5, 33)

    def reset(self) -> None:
        self.exchange(b"\x11\x01", b"\x51", 1, 24)


class DHController:
    """53d4ec/588898 Execute, preserving typed EH and source CPU dispatch."""

    status = EMPSController.status
    error = EMPSController.error

    def __init__(self, context: ExecutableContext, io: ExecutableIO):
        from scripts.cuw_legacy_addresses import (
            legacy_address_inputs,
            select_legacy_addresses,
        )
        from scripts.cuw_legacy_engine import executable_constructor_send_timeout

        if not isinstance(io, ExecutableIO):
            raise TypeError("Native executable runtime required")
        if not isinstance(context, ExecutableContext):
            raise TypeError("Source-selected executable context required")
        context.state.validate()
        self.context, self.io = context, io
        self.source = DHSource(context)
        self.image = self.source.image
        state = channel_state(context)
        if (
            state.protocol != 6
            or type(context.observations.get("protocol_id")) is not int
            or context.observations.get("protocol_id") != 6
        ):
            raise ValueError("Actual initial native ISO15765 connection required")
        self.saved_read = executable_constructor_timeout(context)
        self.saved_send = executable_constructor_send_timeout(context)
        main = context.native.first_image
        if (
            main is None
            or type(main.data) is not bytes
            or type(main.flash_size) is not int
            or not 0 <= main.flash_size <= len(main.data) <= 64 * 1024 * 1024
        ):
            raise ValueError("Bounded first WORK DH main image required")
        self.main = main
        self.loader = b""
        if not self.source.special:
            record = context.native.cpus[0].flash_code
            if (
                record is None
                or type(record.data) is not bytes
                or not 0 < len(record.data) <= 64 * 1024 * 1024
            ):
                raise ValueError("Bounded first WORK DH flash code required")
            self.loader = (
                materialize_legacy_image(record.data).data
                if self.main.base_address is not None
                else record.data
            )
        kind, config, mode, factory = legacy_address_inputs(context)
        self.kind = kind
        addresses = select_legacy_addresses(
            context, kind, config, reprog_mode=mode, factory_state=factory
        )
        if not addresses:
            raise ValueError("Native DH address-factory first record required")
        row = addresses[0].raw
        self.channel = CommonCAN.from_io(
            io, b"\0\0" + row[1:3], b"\0\0" + row[4:6], state=state
        )
        self.wire = DHWire(self.source, self.channel)
        self.flag_68 = False
        self.value_78 = self.value_80 = self.written_a4 = self.percent_ac = 0
        self.status_70 = self.status(0)
        self.native_success = False

    def notify(self) -> None:
        for field, value in (
            ("writing_bytes", self.written_a4),
            ("writing_percent", self.percent_ac),
        ):
            if self.io.call("notification", field=field, value=value) is not None:
                raise ValueError("Native DH scalar notification must return None")

    def mask(self, raw: bool = False) -> None:
        frame = self.source.mask(raw)
        channel = CommonCAN.from_io(
            self.io, frame[:4], frame[:4], state=channel_state(self.context)
        )
        for _ in range(3):
            channel.write(frame[4:])
            channel.wait(100)

    def prepare(self, handles: list[int]) -> None:
        from scripts.cuw_legacy_channel import connect, disconnect

        if self.source.special:
            disconnect(self.context, self.io)
            connect(self.context, self.io, 5)
            self.mask(True)
            disconnect(self.context, self.io)
            connect(self.context, self.io, 6)
        handles.append(
            executable_start_filter(
                self.io,
                self.channel.request,
                self.channel.response,
                padding=self.channel.padding,
            )
        )
        retries = 0
        while True:
            if not self.source.special:
                if (
                    self.kind == self.source.resource(0x5D51C0)
                    and self.source.short_seed
                ):
                    self.channel.wait(15000)
                self.mask()
            self.wire.session()
            try:
                self.wire.security()
                return
            except ExecutableJ2534Error as error:
                supported = self.kind in (
                    self.source.resource(0x5D5208),
                    self.source.resource(0x5D51D4),
                ) or (
                    self.kind == self.source.resource(0x5D51C0)
                    and self.source.cpu_type
                    in (self.source.resource(0x5D50D8), self.source.resource(0x5D50E0))
                )
                if not supported or error.driver_status not in (9, 16) or retries >= 30:
                    raise
                retries += 1

    def region(self, payload: bytes, block_size: int, stage: int) -> None:
        if (
            type(payload) is not bytes
            or not 0 <= len(payload) <= 64 * 1024 * 1024
            or type(block_size) is not int
            or not 1 <= block_size <= 0xFFFFFFFF
            or min(len(payload), block_size) > 4123
            or stage not in (0, 1, 2)
        ):
            raise ValueError(
                "Bounded native DH transfer and negotiated block size required"
            )
        for offset in range(0, len(payload), block_size):
            chunk = payload[offset : offset + block_size]
            self.wire.transfer(chunk)
            if stage:
                self.written_a4 = (self.written_a4 + len(chunk)) & 0xFFFFFFFF
                self.percent_ac = (
                    (_x87_percent(offset + len(chunk), len(payload)) & 0xFFFFFFFF) >> 1
                ) + (50 if stage == 2 else 0)
            self.notify()

    def error_handler(self) -> None:
        from scripts.cuw_legacy_channel import connect, disconnect

        while True:
            executable_sync(self.io, "value_70", value=self.status_70)
            executable_sync(
                self.io, "values_78_80", value_78=self.value_78, value_80=self.value_80
            )
            executable_sync(self.io, "flag_88", value=False)
            executable_sync(self.io, "error_handler")
            if not executable_sync(self.io, "read_flag_88"):
                self.flag_68 = True
                return
            self.value_78 = self.value_80 = 0
            try:
                disconnect(self.context, self.io)
            except (ExecutableNativeError, ExecutableCANError):
                pass
            try:
                connect(self.context, self.io, 6)
                return
            except ExecutableJ2534Error as error:
                self.error(error)
                self.status_70 = self.status(3)

    def run(self) -> dict:
        handles: list[int] = []
        state = channel_state(self.context)
        entry_read, entry_send = state.read_timeout, state.send_timeout
        aborted = None
        caught = False
        try:
            self.channel.wait(1000)
            self.channel.set_timeout(200)
            self.channel.set_send_timeout(10000)
            try:
                self.prepare(handles)
            except (ExecutableJ2534Error, ExecutableCANError) as error:
                self.error(error)
                self.status_70 = self.status(1)
                caught = True
            if not caught:
                try:
                    size = self.wire.download(len(self.main.data))
                    if not self.source.special:
                        self.region(self.loader, size, 0)
                    self.region(self.main.data[: self.main.flash_size], size, 1)
                    self.wire.exit()
                    size = self.wire.verification_download(len(self.main.data))
                    self.region(self.main.data[: self.main.flash_size], size, 2)
                    self.wire.exit()
                    self.wire.verify()
                    self.wire.reset()
                    self.native_success = True
                    executable_sync(self.io, "flag_88", value=False)
                # This native phase catches only CJ/CPass; host/foreign errors propagate.
                except (ExecutableJ2534Error, ExecutableCANError) as error:
                    self.error(error)
                    self.status_70 = self.status(2)
                    caught = True
            try:
                for handle in handles:
                    executable_stop_filter(self.io, handle)
            except (ExecutableNativeError, ExecutableCANError):
                pass
            if caught:
                self.error_handler()
            self.channel.set_timeout(self.saved_read)
            self.channel.set_send_timeout(self.saved_send)
            executable_sync(self.io, "flag_68", value=self.flag_68)
            executable_sync(
                self.io, "values_78_80", value_78=self.value_78, value_80=self.value_80
            )
            executable_sync(self.io, "owner_clear")
            executable_sync(
                self.io,
                "completion",
                outcome="success" if self.native_success else "failure",
            )
        except (InterruptedError, TimeoutError) as error:
            aborted = error
            for restore, value in (
                (self.channel.set_timeout, entry_read),
                (self.channel.set_send_timeout, entry_send),
            ):
                try:
                    restore(value, cleanup=True)
                except (Exception, KeyboardInterrupt) as failure:  # noqa: BLE001 - preserve host abort
                    error.add_note(
                        "Host DH abort timeout restoration failed: "
                        + type(failure).__name__
                    )
            raise
        finally:
            cleanup_errors = self.io.close()
            if aborted is not None:
                for failure in cleanup_errors:
                    aborted.add_note(
                        "Host DH abort resource cleanup failed: " + failure
                    )
        return {
            "controller": self.context.controller,
            "success": self.native_success and not cleanup_errors,
            "native_success": self.native_success,
            "native_flag_68": self.flag_68,
            "native_value_78": self.value_78,
            "native_value_80": self.value_80,
            "host_cleanup_errors": cleanup_errors,
        }


class FHISource:
    """Original12/18 FHI static inputs, separate from2026 family logic."""

    def __init__(self, context: ExecutableContext):
        if (
            not isinstance(context, ExecutableContext)
            or context.controller != "CCanFHIFlashWriter"
        ):
            raise ValueError("Source-selected imported FHI context required")
        self.context, self.image = context, ExecutableImage(context)
        self.kind31 = context.native.base_metadata["kind_of_ecu"] == _vendor_resource(
            context, 0x5854D8, 0x5D51F4
        )
        self.wait_parameter = _vendor_resource(context, 0x58BC4C, 0x5DD5C4)
        self.width = 4 if self.kind31 else 3
        base = 0x5C06A0 if context.build == 12 else 0x61CAB8
        self.address = int.from_bytes(
            self.image.read(base + (0 if self.kind31 else 4), 4), "little"
        )
        self.encoded_address = self.address.to_bytes(4, "big")[-self.width :]
        start, end, target = (
            (0x5335A0, 0x533968, 0x40E310)
            if context.build == 12
            else (0x57CBF4, 0x57CFBC, 0x419BDC)
        )
        code = self.image.read(start, end - start)
        operands = []
        for offset in range(len(code) - 4):
            if (
                code[offset] != 0xE8
                or start
                + offset
                + 5
                + int.from_bytes(code[offset + 1 : offset + 5], "little", signed=True)
                != target
            ):
                continue
            candidates = [
                index
                for index in range(max(0, offset - 14), offset - 4)
                if code[index] == 0x68
                and int.from_bytes(code[index + 1 : index + 5], "little") <= 65535
            ]
            if len(candidates) != 1:
                raise ValueError(
                    "Unique source FHI ushort initializer operand required"
                )
            index = candidates[0]
            operands.append(
                int.from_bytes(code[index + 1 : index + 5], "little").to_bytes(2, "big")
            )
        if len(operands) != 36:
            raise ValueError(
                "Exact FHI four routine plus two sixteen-round source arrays required"
            )
        self.routines = tuple(operands[:4])
        self.rounds = tuple(operands[4:20] if self.kind31 else operands[20:36])
        self.substitution = self.image.read(
            0x5C2830 if context.build == 12 else 0x61EC48, 32
        )
        if any(value > 15 for value in self.substitution):
            raise ValueError("Native FHI substitution table must contain nibbles")
        static_base = 0x5BFB04 if context.build == 12 else 0x61BF14
        self.broadcast = int.from_bytes(
            self.image.read(static_base + 30, 2), "little"
        ).to_bytes(4, "big")
        self.filters = tuple(
            (
                int.from_bytes(
                    self.image.read(static_base + 16 + i * 2, 2), "little"
                ).to_bytes(4, "big"),
                int.from_bytes(
                    self.image.read(static_base + 22 + i * 2, 2), "little"
                ).to_bytes(4, "big"),
            )
            for i in range(3)
        )

    def key(self, seed: bytes) -> bytes:
        if type(seed) is not bytes or len(seed) != 4:
            raise ValueError("Native FHI four-byte seed required")
        left, right = int.from_bytes(seed[:2], "big"), int.from_bytes(seed[2:], "big")
        for material in reversed(self.rounds):
            value = right ^ int.from_bytes(material, "big")
            indices = (
                value & 31,
                (value >> 4) & 31,
                (value >> 8) & 31,
                ((value & 1) << 4) | (value >> 12),
            )
            packed = sum(
                self.substitution[index] << (position * 4)
                for position, index in enumerate(indices)
            )
            transformed = ((packed << 13) | ((packed & 0xFFF8) >> 3)) & 65535
            left, right = right, transformed ^ left
        return right.to_bytes(2, "big") + left.to_bytes(2, "big")


class FHIWire:
    """Original580998 multi-address diagnostic retry and pending policy."""

    def __init__(
        self,
        source: FHISource,
        channel: CommonCAN,
        request_headers: tuple[bytes, ...],
        response_headers: tuple[bytes, ...],
    ):
        for headers in (request_headers, response_headers):
            if (
                type(headers) is not tuple
                or not 1 <= len(headers) <= 5
                or any(
                    type(header) is not bytes or len(header) != 4 for header in headers
                )
            ):
                raise ValueError("Bounded native FHI four-byte header groups required")
        self.source, self.channel = source, channel
        self.requests, self.responses = request_headers, response_headers

    def exchange(
        self,
        request: bytes,
        expected: bytes,
        minimum: int,
        code: int,
        *,
        retry_wait: int = 0,
    ) -> tuple[bytes, ...]:
        from scripts.cuw_legacy_can import ExecutableCANError
        from scripts.cuw_legacy_engine import ExecutableJ2534Error

        if (
            type(request) is not bytes
            or not 1 <= len(request) <= 4124
            or type(expected) is not bytes
            or type(minimum) is not int
            or not len(expected) <= minimum <= 4124
            or type(code) is not int
            or not 0 <= code <= 255
            or type(retry_wait) is not int
            or not 0 <= retry_wait <= 0xFFFFFFFF
        ):
            raise ValueError("Bounded native FHI diagnostic fields required")
        saved = self.channel.timeout_ms
        if saved is None:
            raise ValueError("Actual FHI receive timeout required")
        retries = 0
        try:
            while True:
                self.channel.write_frames(
                    tuple(header + request for header in self.requests)
                )
                self.channel.wait(0)
                remaining, finals, negatives, pending = list(self.responses), [], 0, 0
                while remaining:
                    frames = self.channel.read_selected(tuple(remaining))
                    for frame in frames:
                        body = frame[4:]
                        if len(body) >= 3 and body[:2] == b"\x7f" + request[:1]:
                            if body[2] == 0x78:
                                continue
                            negatives += 1
                        else:
                            finals.append(body)
                        remaining.remove(frame[:4])
                    if remaining:
                        pending += 1
                        if pending > 149:
                            self.channel.write_frames(
                                tuple(header + b"\x3e" for header in self.requests)
                            )
                            raise ExecutableCANError(code)
                        if saved < 5000:
                            self.channel.set_timeout(5000)
                if negatives:
                    retries += 1
                    if retries > 3:
                        raise ExecutableCANError(code)
                    self.channel.wait(retry_wait)
                self.channel.set_timeout(saved)
                if negatives:
                    continue
                if any(
                    len(body) < minimum or not body.startswith(expected)
                    for body in finals
                ):
                    raise ExecutableCANError(code)
                return tuple(finals)
        except ExecutableJ2534Error as error:
            error.native_code = code if code < 128 else code - 256
            raise

    def session(self, selector: int) -> None:
        self.exchange(bytes((0x10, selector)), bytes((0x50, selector)), 2, 41)

    def security(self) -> None:
        seeds = self.exchange(b"\x27\x61", b"\x67\x61", 6, 16)
        self.exchange(b"\x27\x62" + self.source.key(seeds[0][2:6]), b"\x67\x62", 2, 17)

    def disable_dtc(self) -> None:
        self.exchange(b"\x85\x02", b"\xc5\x02", 2, 42, retry_wait=200)

    def communication(self) -> None:
        self.exchange(b"\x28\x03\x01", b"\x68\x03", 2, 43, retry_wait=20)

    def request_region(self, length: int, *, upload: bool = False) -> int:
        opcode = 0x35 if upload else 0x34
        request = (
            bytes((opcode, 4, self.source.width * 17))
            + self.source.encoded_address
            + (length & ((1 << (self.source.width * 8)) - 1)).to_bytes(
                self.source.width, "big"
            )
        )
        body = self.exchange(
            request, bytes((opcode + 0x40, 0x20)), 4, 44 if upload else 26
        )[0]
        size = (
            int.from_bytes(body[2:4], "big") - (1 if upload else self.source.width + 1)
        ) & 0xFFFFFFFF
        if not size:
            raise ValueError("Native FHI block size divides by zero")
        return size

    def routine(self, index: int) -> None:
        routine = self.source.routines[index]
        suffix = bytes(4) if index == 2 else b"\x01"
        if index == 2:
            suffix = b"\xff" * 4
        self.exchange(b"\x31\x01" + routine + suffix, b"\x71\x01" + routine, 4, 25)

    def transfer(self, payload: bytes, offset: int, *, verify: bool = False) -> None:
        opcode = 0xB7 if verify else 0xB6
        address = (
            (self.source.address + offset) & ((1 << (self.source.width * 8)) - 1)
        ).to_bytes(self.source.width, "big")
        expected = bytes((opcode + 0x40,)) + (payload if verify else b"")
        request = bytes((opcode,)) + address + (b"" if verify else payload)
        self.exchange(request, expected, len(expected), 45 if verify else 34)

    def exit(self) -> None:
        self.exchange(b"\x37", b"\x77", 1, 28)


class FHIController:
    """533cc8/57d328 FHI Execute over concrete shared CAN primitives."""

    status = EMPSController.status
    error = EMPSController.error

    def __init__(self, context: ExecutableContext, io: ExecutableIO):
        from scripts.cuw_legacy_addresses import (
            legacy_address_inputs,
            select_legacy_addresses,
        )
        from scripts.cuw_legacy_can import CommonCAN
        from scripts.cuw_legacy_channel import channel_state

        if not isinstance(context, ExecutableContext) or not isinstance(
            io, ExecutableIO
        ):
            raise TypeError("Source-bound native FHI context and runtime required")
        context.state.validate()
        self.context, self.io = context, io
        self.source = FHISource(context)
        self.image = self.source.image
        main = context.native.first_image
        if (
            main is None
            or type(main.data) is not bytes
            or type(main.flash_size) is not int
            or not 0 <= main.flash_size <= len(main.data) <= 64 * 1024 * 1024
        ):
            raise ValueError("Bounded first WORK FHI image required")
        self.main = main
        if channel_state(context).protocol != 6:
            raise ValueError("Actual native FHI protocol6 required")
        kind, config, mode, factory = legacy_address_inputs(context)
        self.configured = select_legacy_addresses(
            context, kind, config, reprog_mode=mode, factory_state=factory
        )
        self.programming = tuple(
            select_legacy_addresses(
                context, kind, None, reprog_mode=mode, factory_state=factory
            )
        )
        if not self.configured:
            raise ValueError("First configured FHI native address required")
        self.candidates = list(self.configured)
        if not self.programming:
            raise ValueError("First unconfigured FHI programming address required")
        self.requests, self.responses = self.headers(self.programming[:1])
        self.channel = CommonCAN.from_io(
            io, self.requests[0], self.responses[0], state=channel_state(context)
        )
        self.wire = FHIWire(self.source, self.channel, self.requests, self.responses)
        self.flag_68 = self.native_success = False
        self.value_78 = self.value_80 = self.written_9c = self.percent_a4 = 0
        self.status_70 = self.status(0)

    @staticmethod
    def headers(rows: tuple) -> tuple[tuple[bytes, ...], tuple[bytes, ...]]:
        return tuple(b"\0\0" + row.raw[1:3] for row in rows), tuple(
            b"\0\0" + row.raw[4:6] for row in rows
        )

    def group(
        self, requests: tuple[bytes, ...], responses: tuple[bytes, ...]
    ) -> FHIWire:
        return FHIWire(self.source, self.channel, tuple(requests), tuple(responses))

    def prepare(self, handles: list[int]) -> int:
        from scripts.cuw_legacy_body import diagnostic
        from scripts.cuw_legacy_can import CommonCAN
        from scripts.cuw_legacy_channel import channel_state
        from scripts.cuw_legacy_engine import (
            ExecutableJ2534Error,
            executable_start_filter,
        )

        for tx, rx in self.source.filters:
            handles.append(
                executable_start_filter(self.io, tx, rx, padding=self.channel.padding)
            )
        blocked, tcm = False, True
        for row in tuple(self.candidates):
            tx, rx = self.headers((row,))
            ch = CommonCAN.from_io(
                self.io, tx[0], rx[0], state=channel_state(self.context)
            )
            try:
                diagnostic(
                    ch,
                    b"\x09\0",
                    b"",
                    0,
                    3,
                    padding=ch.padding,
                    busy_retries=255,
                    pending_responses=149,
                )
            except ExecutableJ2534Error as error:
                if error.driver_status not in (9, 16):
                    raise
                if row.raw[0] == 0x28 and self.source.kind31:
                    self.candidates.remove(row)
                    tcm = False
                else:
                    blocked = True
                    break
        if not blocked:
            for row in self.candidates:
                self.channel.set_timeout(500 if row.raw[0] == 0x28 else 2000)
                tx, rx = self.headers((row,))
                self.group(tx, rx).session(self.source.routines[1][0])
            self.channel.set_timeout(180)
            requests = (self.source.filters[2][0], self.source.broadcast)
            responses = (self.source.filters[2][1], self.source.filters[0][1]) + (
                (self.source.filters[1][1],) if tcm else ()
            )
            self.group(requests, responses).disable_dtc()
            self.channel.wait(120)
            self.channel.set_timeout(500)
            self.group(requests[1:], responses[1:]).communication()
            self.channel.wait(100)
            self.channel.set_timeout(2000)
            self.wire.security()
            self.wire.session(self.source.routines[0][0])
        size = self.wire.request_region(len(self.main.data))
        self.channel.wait(100)
        return size

    def region(self, block_size: int, verify: bool) -> None:
        from scripts.cuw_legacy_vendor import _x87_percent

        payload = self.main.data[: self.main.flash_size]
        if (
            type(block_size) is not int
            or not 1 <= block_size <= 0xFFFFFFFF
            or min(block_size, len(payload))
            > (4123 if verify else 4123 - self.source.width)
        ):
            raise ValueError("Bounded native FHI transfer size required")
        for offset in range(0, len(payload), block_size):
            chunk = payload[offset : offset + block_size]
            self.wire.transfer(chunk, offset, verify=verify)
            self.written_9c = (self.written_9c + len(chunk)) & 0xFFFFFFFF
            self.percent_a4 = (
                (_x87_percent(offset + len(chunk), len(payload)) & 0xFFFFFFFF) >> 1
            ) + (50 if verify else 0)
            for field, value in (
                ("writing_bytes", self.written_9c),
                ("writing_percent", self.percent_a4),
            ):
                if self.io.call("notification", field=field, value=value) is not None:
                    raise ValueError("Native FHI scalar notification must return None")

    def error_handler(self) -> None:
        from scripts.cuw_legacy_channel import connect, disconnect
        from scripts.cuw_legacy_engine import (
            ExecutableJ2534Error,
            ExecutableNativeError,
            executable_sync,
        )

        while True:
            executable_sync(self.io, "value_70", value=self.status_70)
            executable_sync(
                self.io, "values_78_80", value_78=self.value_78, value_80=self.value_80
            )
            executable_sync(self.io, "flag_88", value=False)
            executable_sync(self.io, "error_handler")
            if not executable_sync(self.io, "read_flag_88"):
                self.flag_68 = True
                return
            self.value_78 = self.value_80 = 0
            try:
                disconnect(self.context, self.io)
            except ExecutableNativeError:
                pass
            try:
                connect(self.context, self.io, 6)
                self.written_9c = self.percent_a4 = 0
                for field in ("writing_bytes", "writing_percent"):
                    if self.io.call("notification", field=field, value=0) is not None:
                        raise ValueError(
                            "Native FHI scalar notification must return None"
                        )
                return
            except ExecutableJ2534Error as error:
                self.error(error)
                self.status_70 = self.status(3)

    def run(self) -> dict:
        from scripts.cuw_legacy_can import ExecutableCANError
        from scripts.cuw_legacy_engine import (
            ExecutableJ2534Error,
            ExecutableNativeError,
            executable_stop_filter,
            executable_sync,
        )

        handles: list[int] = []
        caught = False
        entry = self.channel.timeout_ms
        if entry is None:
            raise ValueError("Shared native FHI receive timeout required")
        aborted = None
        try:
            from scripts.cuw_legacy_engine import executable_parameters
            from scripts.programming_2026_common import _native_long

            parameters = executable_parameters(self.context, 0)
            text = next(
                (
                    value
                    for key, value in parameters.items()
                    if key.casefold() == self.source.wait_parameter.casefold()
                ),
                "",
            )
            self.channel.wait((_native_long(text) or 0) & 0xFFFFFFFF)
            self.channel.set_timeout(2000)
            try:
                size = self.prepare(handles)
            except (ExecutableJ2534Error, ExecutableCANError) as error:
                self.error(error)
                self.status_70 = self.status(1)
                caught = True
            if not caught:
                try:
                    self.channel.set_timeout(5000)
                    self.wire.routine(2)
                    self.channel.set_timeout(2000)
                    self.region(size, False)
                    self.wire.exit()
                    self.wire.routine(3)
                    size = self.wire.request_region(len(self.main.data), upload=True)
                    self.channel.set_timeout(10000)
                    self.region(size, True)
                    self.channel.set_timeout(2000)
                    self.wire.exit()
                    self.native_success = True
                    executable_sync(self.io, "flag_88", value=False)
                except (ExecutableJ2534Error, ExecutableCANError) as error:
                    self.error(error)
                    self.status_70 = self.status(2)
                    caught = True
            for handle in handles:
                try:
                    executable_stop_filter(self.io, handle)
                except ExecutableNativeError:
                    pass
            if caught:
                self.error_handler()
            self.channel.set_timeout(2000)
            executable_sync(self.io, "flag_68", value=self.flag_68)
            executable_sync(
                self.io, "values_78_80", value_78=self.value_78, value_80=self.value_80
            )
            executable_sync(self.io, "owner_clear")
            executable_sync(
                self.io,
                "completion",
                outcome="success" if self.native_success else "failure",
            )
        except (InterruptedError, TimeoutError) as error:
            aborted = error
            try:
                self.channel.set_timeout(entry, cleanup=True)
            except (Exception, KeyboardInterrupt) as failure:  # noqa: BLE001 - retain host abort
                error.add_note(
                    "Host FHI timeout restore failed: " + type(failure).__name__
                )
            raise
        finally:
            cleanup = self.io.close()
            if aborted is not None:
                for failure in cleanup:
                    aborted.add_note("Host FHI resource cleanup failed: " + failure)
        return {
            "controller": self.context.controller,
            "success": self.native_success and not cleanup,
            "native_success": self.native_success,
            "native_flag_68": self.flag_68,
            "native_value_78": self.value_78,
            "native_value_80": self.value_80,
            "host_cleanup_errors": cleanup,
        }
