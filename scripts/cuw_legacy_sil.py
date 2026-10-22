"""Original CUW executable SIL controllers, over explicit host primitives.

The runtime is shared host deadline policy; no CUW2026 protocol is used here.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from dataclasses import field as dataclass_field

from scripts.cuw_legacy_channel import selected_driver_delay
from scripts.cuw_legacy_engine import (
    ExecutableContext,
    ExecutableImage,
    ExecutableIO,
    ExecutableJ2534Error,
    ExecutableNativeError,
    apply_recovery_password_state,
    executable_cpu_type,
    executable_j2534_call,
    executable_new_password,
    executable_reconnect,
    executable_selected_password,
    executable_sync,
    legacy_messages,
    require_executable_standard_getter,
    set_executable_cpu_type,
)
from scripts.programming import NativeTransportError


class SilProtocolError(OSError, ExecutableNativeError):
    """Native protocol error retaining the native category and source boundary."""

    def __init__(self, code: int, address: int):
        self.native_code, self.address = code, address
        super().__init__(f"Original SIL error {code} at {address:08x}")

    @property
    def native_code(self) -> int:
        return self._native_code

    @native_code.setter
    def native_code(self, value: int) -> None:
        if type(value) is not int or not -128 <= value <= 255:
            raise ValueError("Native CPass category must fit its byte field")
        # Native handlers sign-extend +0c; the protocol-facing code retains its byte view.
        self._native_code = (value + 128) % 256 - 128

    @property
    def code(self) -> int:
        return self.native_code & 255

    @code.setter
    def code(self, value: int) -> None:
        self.native_code = value


class SilInitialCommandError(SilProtocolError):
    """Native CSetBaudRateException has its own bootstrap catch policy."""


_CID_ISSUER = object()


@dataclass(frozen=True)
class SilCIDResult:
    """Source getter output; hardware belongs to the separate worker DLL phase."""

    build: int
    container_sha256: str
    cids: tuple[str, ...]
    native_value_d68: int
    native_value_d70: int
    terminated: bool
    native_completion_pair: tuple[int, int]
    _issuer: object = dataclass_field(repr=False, compare=False)
    _issued_payload: tuple = dataclass_field(repr=False, compare=False)
    _channel: object = dataclass_field(repr=False, compare=False)

    def validate(self, context: ExecutableContext) -> None:
        from scripts.cuw_legacy_channel import channel_state

        ExecutableImage(context)
        if (
            self._issuer is not _CID_ISSUER
            or self.build != context.build
            or self.container_sha256 != context.container_sha256
            or self._channel is not channel_state(context)
            or self._issued_payload
            != (
                self.build,
                self.container_sha256,
                self.cids,
                self.native_value_d68,
                self.native_value_d70,
                self.terminated,
                self.native_completion_pair,
            )
        ):
            raise ValueError("CID result must be issued by this actual native context")


class _SilCIDTerminated(Exception):
    pass


def _unsigned(value: object, maximum: int = 0xFFFFFFFF) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("Bounded native unsigned integer required")
    return value


def emps_selection(kind_of_ecu: str, cpu_type: str) -> tuple[int, int]:
    """18:591af0/590af8; native unmatched metadata deliberately maps to zero."""
    if not all(
        isinstance(value, str) and len(value) <= 259
        for value in (kind_of_ecu, cpu_type)
    ):
        raise ValueError("Bounded imported native metadata strings required")
    return {"13": 0x32, "14": 0x34}.get(kind_of_ecu, 0), {
        "57": 0x100,
        "58": 0xF0,
        "59": 0x80,
        "60": 0xC0,
    }.get(cpu_type, 0)


def dcmprl_layout(cpu_type: str, block: int) -> tuple[int, int]:
    """18:59ba3c actual flash address and special materialized-image adjustment."""
    _unsigned(block, 65536)
    if block == 0 or not isinstance(cpu_type, str) or len(cpu_type) > 259:
        raise ValueError("One-based native block and imported CPU type required")
    if cpu_type == "34":
        adjustment = {5: 0x300E, 6: 0x31FC}.get(block, 0)
        return 0x400000 + adjustment, adjustment
    return {"32": 0x6000, "33": 0x80000}.get(cpu_type, 0), 0


def dcmprl_block_sizes(cpu_type: str, first_image_length: int) -> tuple[int, ...]:
    """18:599910 uses first materialized image Length+10, not FlashSize+1c."""
    _unsigned(first_image_length, 64 * 1024 * 1024)
    if not isinstance(cpu_type, str) or len(cpu_type) > 259:
        raise ValueError("Bounded imported native CPU type required")
    if cpu_type == "34":
        return (1024, 1024, 1024, 1024, 4, 256)
    count, remainder = divmod(first_image_length, 1024)
    return (1024,) * count + ((remainder,) if remainder else ())


def m16c_regions() -> tuple[tuple[int, int], ...]:
    """18:59d28c constructs exactly these three native regions."""
    return ((0xFA000, 0x2000), (0xFC000, 0x2000), (0xFE000, 0x2000))


class SilRaw:
    """18:483af4-485798 unframed serial primitives on an already owned channel."""

    def __init__(self, io: ExecutableIO, protocol_id: int):
        if not isinstance(io, ExecutableIO):
            raise TypeError("Actual bounded executable primitive runtime required")
        self.io = io
        self.protocol_id = _unsigned(protocol_id)
        self.memory_known = False
        self.extended_memory = False
        self.transferred = 0
        self.writing_end_block = False

    def void(self, operation: str, **values) -> None:
        result = (
            executable_j2534_call(self.io, operation, **values)
            if operation == "ioctl"
            else self.io.call(operation, **values)
        )
        if result is not None:
            raise ValueError("Void native primitive returned a value")

    def restore(self, operation: str, milliseconds: int) -> None:
        original = sys.exception()
        try:
            if (
                self.io.call(operation, milliseconds=milliseconds, cleanup=True)
                is not None
            ):
                raise ValueError("Timeout restoration primitive returned a value")
        except (Exception, KeyboardInterrupt) as error:
            if original is None:
                raise
            original.add_note(
                "Original SIL timeout restoration failed: " + type(error).__name__
            )

    def write(self, data: bytes) -> None:
        if not isinstance(data, bytes) or not 0 < len(data) <= 4128:
            raise ValueError("Bounded immutable native serial packet required")
        result = executable_j2534_call(
            self.io,
            "write_messages",
            protocol_id=self.protocol_id,
            tx_flags=0,
            data=data,
            count=1,
        )
        if type(result) is not int or result != 1:
            raise OSError("Partial or unconfirmed original SIL write")

    def read_exact(self, count: int) -> bytes:
        _unsigned(count, 4128)
        result = bytearray()
        while len(result) < count:
            frames = legacy_messages(
                executable_j2534_call(
                    self.io, "read_messages", protocol_id=self.protocol_id, count=1
                )
            )
            if len(frames) > 1:
                raise ValueError("Original serial read exceeds requested message count")
            if not frames:
                continue
            if frames[0].protocol_id != self.protocol_id:
                raise ValueError("Native serial reply belongs to another protocol")
            # 18:4840a0 intentionally consumes Data regardless of RxStatus.
            data = frames[0].data
            result.extend(data[: count - len(result)])
        return bytes(result)

    def ack(self) -> bool:
        while True:
            try:
                response = self.read_exact(1)
            except NativeTransportError as error:
                if error.code in (9, 16):
                    return False
                raise
            if response == b"\x3c":
                return True

    def handshake(self, selector: int) -> None:
        """18:484138 initial60, native baud enum (5 maps to6),05."""
        _unsigned(selector, 255)
        self.write(b"\x60")
        response = self.read_exact(1)
        if response != b"\x3c":
            raise SilInitialCommandError(1 if response == b"\xff" else 2, 0x484138)
        self.write(bytes(((0, 1, 2, 3, 4, 6)[selector] if selector < 6 else 0,)))
        if not self.ack():
            raise SilProtocolError(5, 0x484138)
        self.void("wait", milliseconds=100)
        self.write(b"\x05")
        if not self.ack():
            raise SilProtocolError(5, 0x484138)

    def initialize(
        self,
        location: bytes,
        password: int,
        *,
        padding: bool,
        p4: int = 70,
        p5: int = 80,
    ) -> None:
        """18:483bbc uses the first four LocationID bytes, reversed, and LE password."""
        from scripts.j2534_2026 import j2534_indication

        _unsigned(password)
        if type(padding) is not bool:
            raise ValueError("Observed native padding flag required")
        _unsigned(p4)
        _unsigned(p5)
        if not isinstance(location, bytes) or not 4 <= len(location) <= 128:
            raise ValueError("Imported hexadecimal LocationID with four bytes required")
        for parameter, value in ((0x14, p4), (0x15, p5)):
            self.void("ioctl", ioctl=2, config=((parameter, value),))
        result = executable_j2534_call(
            self.io,
            "ioctl",
            ioctl=5,
            input=b"\0\0" + location[:4][::-1] + password.to_bytes(4, "little"),
            output_capacity=4152,
        )
        message = legacy_messages((result,))[0]
        if message.protocol_id != self.protocol_id:
            raise ValueError("Native FAST_INIT reply belongs to another protocol")
        if j2534_indication(message.rx_status, padding) != 3:
            legacy_messages(
                executable_j2534_call(
                    self.io, "read_messages", protocol_id=self.protocol_id, count=1
                )
            )
        self.write(b"\x3c")

    def memory(self) -> bytes:
        """18:484548 probes75 then76 once; exactly8 bytes reach46be4c."""
        variants = (self.extended_memory,) if self.memory_known else (False, True)
        for extended in variants:
            self.write(b"\x76" if extended else b"\x75")
            try:
                response = self.read_exact(11 if extended else 10)
            except ExecutableNativeError:
                if self.memory_known or extended:
                    raise
                # 18:484747 / EH5f93d0 clears the initial75 read buffer.
                response = bytes(10)
            if response[0] == response[-1] == 0x3C:
                self.extended_memory = extended
                self.memory_known = True
                return response[1:9]
        raise SilProtocolError(10, 0x484548)

    def bootstrap(
        self,
        cpu_type: str,
        baud_rates: tuple[int, int, int],
        range_rows: tuple[tuple[str, tuple[tuple[int, int], ...]], ...],
    ) -> bytes:
        """18:485914 native three rates and three independent100-probe loops."""
        from scripts.cuw_legacy_can import select_block_ranges

        if (
            not isinstance(baud_rates, tuple)
            or len(baud_rates) != 3
            or any(
                type(rate) is not int or not 0 < rate <= 0xFFFFFFFF
                for rate in baud_rates
            )
            or not isinstance(cpu_type, str)
            or len(cpu_type) > 259
            or not isinstance(range_rows, tuple)
        ):
            raise ValueError(
                "Source-derived baud vector, CPU type and range rows required"
            )
        previous_initial_failure = False
        for candidate, baud in enumerate(baud_rates):
            try:
                self.void("ioctl", ioctl=2, config=((1, baud),))
                attempt = first_attempts = 0
                while attempt < 100:
                    if attempt == 0:
                        first_attempts += 1
                    try:
                        self.handshake(0)
                        previous_initial_failure = False
                    except SilInitialCommandError as error:
                        if (
                            error.code == 1
                            and attempt == 0
                            and candidate > 0
                            and first_attempts < 2
                            and previous_initial_failure
                        ):
                            continue
                        if error.code in (1, 2):
                            previous_initial_failure = True
                            raise SilProtocolError(5, 0x485914) from error
                        raise
                    attempt += 1
                memory = bytes(8)
                for _ in range(100):
                    memory = self.memory()
                for _ in range(100):
                    try:
                        if self.extended_memory:
                            sizes = sil_memory_geometry(cpu_type, memory)
                            ranges = select_block_ranges(cpu_type, sizes, range_rows)
                            if not ranges:
                                raise ValueError(
                                    "Native wide bootstrap has no first range"
                                )
                            self.block("blank", ranges[0][0], last=ranges[0][1])
                        else:
                            self.block("blank", 1)
                    except (SilProtocolError, ExecutableJ2534Error):
                        self.write(b"\x05")
                        self.read_exact(1)
                        raise
                return memory
            except (SilProtocolError, ExecutableJ2534Error) as error:
                if candidate == 2:
                    raise SilProtocolError(21, 0x485914) from error
        raise AssertionError(
            "Native bootstrap exhausted without success or native error"
        )

    def initialize_generic(
        self, context: ExecutableContext, old_password: int
    ) -> bytes:
        """12:453b58 /18:482fac initialization and source CPU descriptor gate."""
        from scripts.cuw_legacy_can import cpu_matches

        if (
            not isinstance(context, ExecutableContext)
            or context.build not in (12, 18)
            or context.controller != "CSilFlashWriter"
        ):
            raise ValueError("Original12/18 generic SIL context required")
        if (
            self.protocol_id != 3
            or type(context.observations.get("protocol_id")) is not int
            or context.observations.get("protocol_id") != 3
        ):
            raise ValueError("Actual native SIL connection protocol3 required")
        context.state.validate()
        _unsigned(old_password)
        padding = context.observations.get("channel_padding")
        if type(padding) is not bool:
            raise ValueError("Actual source-mapped native channel padding required")
        location = context.native.location_id
        if not isinstance(location, bytes) or not 4 <= len(location) <= 128:
            raise ValueError("Imported native SIL LocationID must cover four bytes")
        tables = SilTables(context)
        cpu_type = executable_cpu_type(context)
        password = (
            executable_new_password(context)
            if context.state.use_new_software_password
            else old_password
        )
        rate_base = 0x5F8934 if context.build == 18 else 0x59F8A0
        rates = tuple(tables.number(rate_base + index * 4) for index in range(3))
        self.void("ioctl", ioctl=2, config=((1, 9600),))
        self.void("ioctl", ioctl=2, config=((0x0C, 0),))
        self.initialize(location, password, padding=padding)
        dynamic = tables.dynamic_cpu(cpu_type)
        self.memory_known = not dynamic
        if not dynamic:
            self.extended_memory = tables.cpu_mode(cpu_type)
        self.bootstrap(cpu_type, (rates[0], rates[1], rates[2]), tables.range_rows())
        self.handshake(0)
        memory = self.memory()
        if dynamic and tables.cpu_mode(cpu_type) != self.extended_memory:
            replacement = tables.remap_cpu(cpu_type)
            if replacement is None:
                raise ValueError("Native detected CPU has no source remapping row")
            set_executable_cpu_type(context, context.native.selected.index, replacement)
            cpu_type = executable_cpu_type(context)
        if not cpu_matches(
            cpu_type, memory[7], self.extended_memory, tables.descriptor_rows()
        ):
            raise SilProtocolError(10, 0x482FAC)
        return memory

    def program_ranges(
        self,
        image: bytes,
        memory: bytes,
        cpu_type: str,
        kind_of_ecu: str,
        *,
        image_size: int,
        native_delay: bool,
        range_rows: tuple[tuple[str, tuple[tuple[int, int], ...]], ...] = (),
        context: ExecutableContext | None = None,
        force_grouped: bool = False,
    ) -> None:
        """18:482fac narrow /59f6bc grouped erase/write/two-verification loop."""
        from scripts.cuw_legacy_can import select_block_ranges

        if (
            not isinstance(image, bytes)
            or not isinstance(kind_of_ecu, str)
            or len(kind_of_ecu) > 259
            or type(native_delay) is not bool
            or type(force_grouped) is not bool
        ):
            raise ValueError(
                "Imported SIL image, KindOfECU and native delay Boolean required"
            )
        if context is not None and (
            not isinstance(context, ExecutableContext)
            or context.controller != "CSilOccupantDetectionFlashWriter"
        ):
            raise ValueError("Actual occupant manager end-block binding required")
        _unsigned(image_size, 64 * 1024 * 1024)
        if not image_size:
            raise ValueError("Actual native SIL image flash size is zero")
        sizes = sil_memory_geometry(cpu_type, memory)
        grouped = self.extended_memory or force_grouped
        ranges = (
            select_block_ranges(cpu_type, sizes, range_rows)
            if grouped
            else tuple((index, index) for index in range(1, len(sizes) + 1))
        )
        if not ranges:
            raise ValueError("Native SIL block geometry is empty")
        spans = []
        address = int.from_bytes(memory[:3], "big")
        for first, last in ranges:
            offset = sum(sizes[: first - 1])
            length = sum(sizes[first - 1 : last])
            if (
                not length
                or length % 1024
                or offset + length > len(image)
                or address + offset + length > 0x1000000
            ):
                raise ValueError(
                    "Native SIL image does not cover whole1024-byte block bursts"
                )
            spans.append((first, last, offset, length))
        for index, (first, last, offset, length) in enumerate(spans):
            final = last if grouped else None
            blank = (
                False
                if grouped and kind_of_ecu == "63"
                else self.block("blank", first, last=final)
            )
            self.writing_end_block = index == len(spans) - 1
            if context is not None:
                context.state.native_flag_ed6 = self.writing_end_block
            if not blank:
                self.block("erase", first, last=final)
            block = image[offset : offset + length]
            self.write_block(block, address + offset, image_size)
            self.block("inverify", first, last=final)
            self.verify_block(
                first, block, image_size, native_delay=native_delay, last=final
            )

    def status(self, retry: bool = True) -> int:
        if type(retry) is not bool:
            raise ValueError("Explicit native retry Boolean required")
        for attempt in range(3 if retry else 1):
            if attempt:
                self.void("wait", milliseconds=10)
            self.write(b"\x50")
            try:
                response = self.read_exact(3)
            except NativeTransportError:
                if not retry or attempt == 2:
                    raise
                continue
            if response[0] == response[-1] == 0x3C:
                return response[1]
        raise SilProtocolError(4, 0x484A6C)

    def block(self, operation: str, ordinal: int, *, last: int | None = None) -> bool:
        """18:484920/484bf0/485220 have different pending and failure policies."""
        _unsigned(ordinal, 65536 if last is not None else 255)
        if ordinal == 0 or operation not in ("blank", "erase", "inverify"):
            raise ValueError("Native one-based block and operation required")
        code, pending, error, address = {
            "blank": (0x35, 0x10, 11, 0x484920),
            "erase": (0x25, 0x80, 12, 0x484BF0),
            "inverify": (0x47, 0x40, 14, 0x485220),
        }[operation]
        if last is None:
            request = bytes((code, ordinal - 1))
        else:
            from scripts.cuw_legacy_can import block_range

            request = bytes((code + 1,)) + block_range(ordinal, last)
        self.write(request)
        if not self.ack():
            raise SilProtocolError(error, address)
        while True:
            self.void("wait", milliseconds=10)
            status = self.status()
            if status != pending:
                break
        if operation == "blank":
            return status == 0
        if status:
            raise SilProtocolError(error, address)
        return True

    def _packet(self, data: bytes, image_size: int) -> None:
        self.void("set_send_timeout", milliseconds=10000)
        try:
            self.write(data)
        finally:
            # Host cleanup retains the native restore even after callback failure.
            self.restore("set_send_timeout", 1000)
        self.transferred += 256
        self.void(
            "progress",
            transferred=self.transferred,
            percent=round(self.transferred * 100 / (image_size * 2)),
        )

    def write_block(self, data: bytes, address: int, image_size: int) -> None:
        """18:484d6c/485798 sends four256-byte packets per native burst."""
        _unsigned(address, 0xFFFFFF)
        _unsigned(image_size, 64 * 1024 * 1024)
        if (
            not isinstance(data, bytes)
            or not data
            or len(data) % 1024
            or not image_size
            or address + len(data) > 1 << 24
        ):
            raise ValueError("Complete native1KiB burst geometry required")
        for burst in range(0, len(data), 1024):
            self.write(b"\x41" if burst == 0 else b"\x45")
            if not self.ack():
                raise SilProtocolError(13, 0x484D6C)
            for offset in range(burst, burst + 1024, 256):
                prefix = address.to_bytes(3, "big") + b"\xff" if offset == 0 else b""
                self._packet(prefix + data[offset : offset + 256], image_size)
            self.void("set_timeout", milliseconds=2000)
            try:
                self.ack()
            finally:
                self.restore("set_timeout", 1000)
            while True:
                self.void("wait", milliseconds=5)
                status = self.status()
                if status != 0x40:
                    break
            if status:
                raise SilProtocolError(13, 0x484D6C)

    def verify_block(
        self,
        ordinal: int,
        data: bytes,
        image_size: int,
        *,
        native_delay: bool,
        last: int | None = None,
    ) -> None:
        """18:48538c sends15/ordinal,256-byte packets,20 pending status."""
        _unsigned(ordinal, 65536 if last is not None else 255)
        if type(native_delay) is not bool:
            raise ValueError("Observed native verify-delay Boolean required")
        _unsigned(image_size, 64 * 1024 * 1024)
        if (
            not ordinal
            or not isinstance(data, bytes)
            or not data
            or len(data) % 256
            or not image_size
        ):
            raise ValueError("Complete native256-byte verification geometry required")
        if last is None:
            request = bytes((0x15, ordinal - 1))
        else:
            from scripts.cuw_legacy_can import block_range

            request = b"\x16" + block_range(ordinal, last)
        self.write(request)
        if not self.ack():
            raise SilProtocolError(15, 0x48538C)
        for offset in range(0, len(data), 256):
            if last is None and native_delay:
                self.void("wait", milliseconds=20)
            self.write(data[offset : offset + 256])
            self.transferred += 256
            self.void(
                "progress",
                transferred=self.transferred,
                percent=round(self.transferred * 100 / (image_size * 2)),
            )
            self.ack()
            while True:
                self.void("wait", milliseconds=5)
                try:
                    status = self.status(retry=offset + 256 == len(data))
                except ExecutableJ2534Error:
                    if offset + 256 == len(data):
                        raise
                    status = 0
                    break
                if status != 0x20:
                    break
            if status:
                raise SilProtocolError(15, 0x48538C)


class SilKWP(SilRaw):
    """18:482004 native single-request K-line exchange and pending/busy policy."""

    def exchange(
        self,
        request: bytes,
        *,
        minimum: int,
        error: int,
        wait_ms: int = 100,
        header: bytes = b"",
        body: bytes = b"",
    ) -> bytes:
        _unsigned(minimum, 4128)
        _unsigned(error, 255)
        _unsigned(wait_ms, 60000)
        if (
            not isinstance(request, bytes)
            or not 4 <= len(request) <= 4128
            or any(
                not isinstance(value, bytes) or len(value) > 4128
                for value in (header, body)
            )
        ):
            raise ValueError(
                "Bounded actual native request and expected prefixes required"
            )
        old_timeout = _unsigned(self.io.call("get_timeout"))
        busy = 0
        try:
            while True:
                self.write(request)
                self.void("wait", milliseconds=wait_ms)
                pending = 0
                while True:
                    frames = legacy_messages(
                        executable_j2534_call(
                            self.io,
                            "read_messages",
                            protocol_id=self.protocol_id,
                            count=1,
                        )
                    )
                    if len(frames) != 1:
                        raise ValueError("One complete native K-line response required")
                    if frames[0].protocol_id != self.protocol_id:
                        raise ValueError(
                            "Native K-line reply belongs to another protocol"
                        )
                    response = frames[0].data
                    if len(response) >= 6 and response[3:5] == bytes(
                        (0x7F, request[3])
                    ):
                        if response[5] == 0x78:
                            busy = 0
                            pending += 1
                            if pending > 149:
                                stop = bytes((0x81, request[1], request[2], 0x82))
                                self.write(stop + bytes((sum(stop) & 255,)))
                                raise SilProtocolError(error, 0x482004)
                            if old_timeout < 5000:
                                self.void("set_timeout", milliseconds=5000)
                            continue
                        if response[5] == 0x21:
                            busy += 1
                            if busy > 255:
                                raise SilProtocolError(error, 0x482004)
                            break
                    if (
                        len(response) < minimum
                        or not response.startswith(header)
                        or not response[3:].startswith(body)
                    ):
                        raise SilProtocolError(error, 0x482004)
                    return response
                self.void("set_timeout", milliseconds=old_timeout)
        except SilProtocolError as native:
            # 18:48243f/12:452fc1 rewrites the caught CPass category, then rethrows.
            native.code = native.native_code = error
            raise
        finally:
            self.restore("set_timeout", old_timeout)


def emps_packet(index: int, data: bytes) -> bytes:
    """18:591390 exactly1024data bytes and one's-complement additive checksum."""
    _unsigned(index, 255)
    if not isinstance(data, bytes) or len(data) != 1024:
        raise ValueError("Exactly1024 native EMPS bytes required")
    packet = bytes((index, 4, 0)) + data
    return packet + bytes(((~sum(packet)) & 255,))


class EmpsSIL(SilKWP):
    """18:590af8/591068 original EMPS initialization and packet state machine."""

    def __init__(self, io: ExecutableIO, protocol_id: int):
        super().__init__(io, protocol_id)
        self.needs_recreate = False
        self.packet_index = 0

    def reply(self) -> bytes:
        messages = legacy_messages(
            executable_j2534_call(
                self.io, "read_messages", protocol_id=self.protocol_id, count=1
            )
        )
        if len(messages) != 1 or not messages[0].data:
            raise ValueError("One nonempty native EMPS reply required")
        if messages[0].protocol_id != self.protocol_id:
            raise ValueError("Native EMPS reply belongs to another protocol")
        data = messages[0].data
        if data[0] == 0x82 and len(data) < 2:
            raise ValueError("Native EMPS retry reply lacks packet number")
        return data

    def fast_init(self, target: int, *, padding: bool) -> None:
        from scripts.j2534_2026 import j2534_indication

        _unsigned(target, 255)
        if type(padding) is not bool:
            raise ValueError("Observed native padding flag required")
        for parameter, value in ((1, 9600), (0x14, 35), (0x15, 50)):
            self.void("ioctl", ioctl=2, config=((parameter, value),))
        request = bytes((0x81, target, 0xF1, 0x81))
        result = executable_j2534_call(
            self.io,
            "ioctl",
            ioctl=5,
            input=request + bytes((sum(request) & 255,)),
            output_capacity=4152,
        )
        message = legacy_messages((result,))[0]
        if message.protocol_id != self.protocol_id:
            raise ValueError("Native FAST_INIT reply belongs to another protocol")
        if j2534_indication(message.rx_status, padding) != 3:
            legacy_messages(
                executable_j2534_call(
                    self.io, "read_messages", protocol_id=self.protocol_id, count=1
                )
            )

    def prepare(self, target: int, count: int) -> None:
        """18:590ee0:87targetf19c0d0107ff + bigendian packet count."""
        _unsigned(target, 255)
        _unsigned(count, 0xFFFF)
        packet = bytes((0x87, target, 0xF1, 0x9C, 0x0D, 1, 7, 255)) + count.to_bytes(
            2, "big"
        )
        response = self.exchange(
            packet + bytes((sum(packet) & 255,)), minimum=12, error=12, wait_ms=0
        )
        if response[0] != 0:
            raise SilProtocolError(12, 0x590EE0)

    def transfer(
        self, image: bytes, count: int, start: int = 0, *, image_size: int
    ) -> int:
        """18:591068 distinct stale-read and same-packet retry budgets of3."""
        _unsigned(count, 256)
        _unsigned(start, count)
        _unsigned(image_size, 64 * 1024 * 1024)
        if count and not image_size:
            raise ValueError("Actual native image flash size is zero")
        if not isinstance(image, bytes) or len(image) < count * 1024:
            raise ValueError("Native EMPS image does not cover selected packet count")
        self.void("set_timeout", milliseconds=1000)
        index, retries = start, 0
        self.packet_index = start
        self.needs_recreate = False
        while index < count:
            if index == count - 1:
                self.void("set_timeout", milliseconds=10000)
            try:
                self.write(emps_packet(index, image[index * 1024 : (index + 1) * 1024]))
            except ExecutableJ2534Error as error:
                self.needs_recreate = True
                error.native_code = 13
                raise
            try:
                response = self.reply()
            except ExecutableJ2534Error as error:
                self.needs_recreate = error.driver_status in (9, 16)
                error.native_code = 13
                raise
            self.transferred += 1024
            self.void(
                "progress",
                transferred=self.transferred,
                percent=round(self.transferred * 100 / image_size),
            )
            stale = 0
            while response[0] == 0x82 and response[1] == index - 1 and stale < 3:
                stale += 1
                response = self.reply()
            if response[0] == 0x82:
                retries += 1
                if response[1] != index or retries > 3:
                    raise SilProtocolError(13, 0x591068)
                continue
            if response[0] == 0x83:
                raise SilProtocolError(13, 0x591068)
            if response[0] == 2:
                if index != count - 1:
                    raise SilProtocolError(13, 0x591068)
            elif response[0] == 1:
                if index == count - 1:
                    raise SilProtocolError(13, 0x591068)
            else:
                raise SilProtocolError(13, 0x591068)
            retries = 0
            index += 1
            self.packet_index = index
        return index


class M16CSIL(SilRaw):
    """18:59e510-59f0c4 M16C password, erase, page and verification algorithms."""

    def batch(self, messages: tuple[bytes, ...]) -> None:
        if not 0 < len(messages) <= 4096 or any(
            not isinstance(data, bytes) or not 0 < len(data) <= 4128
            for data in messages
        ):
            raise ValueError("Bounded immutable native message batch required")
        count = executable_j2534_call(
            self.io,
            "write_messages",
            protocol_id=self.protocol_id,
            tx_flags=0,
            messages=messages,
            count=len(messages),
        )
        if type(count) is not int or count != len(messages):
            raise OSError("Partial or unconfirmed original M16C batch write")

    def m16c_status(self) -> tuple[int, int] | None:
        self.write(b"\xa4")
        try:
            result = self.read_exact(2)
        except NativeTransportError as error:
            if error.code in (9, 16):
                return None
            raise
        return result[0], result[1]

    def password(self, password: int) -> None:
        _unsigned(password)
        self.batch((b"\xa0\xdf\xff\x0f\x07", password.to_bytes(4, "big") + bytes(3)))
        status = self.m16c_status()
        if status is None or status[1] & 0x0C != 0x0C:
            raise SilProtocolError(7, 0x59E510)

    def erase(self, final_address: int) -> None:
        _unsigned(final_address, 0xFFFFFF)
        self.write(b"\xa6")
        self.write(
            bytes((0xA1, (final_address >> 8) & 255, (final_address >> 16) & 255, 0xD0))
        )
        while True:
            self.void("wait", milliseconds=5)
            result = self.m16c_status()
            if result is None:
                raise SilProtocolError(12, 0x59E898)
            status, _ = result
            if status & 0x80:
                break
        if status & 0x30:
            raise SilProtocolError(12, 0x59E898)

    def page(self, address: int, data: bytes, image_size: int, *, verify: bool) -> None:
        _unsigned(address, 0xFFFFFF)
        _unsigned(image_size, 64 * 1024 * 1024)
        if (
            type(verify) is not bool
            or not isinstance(data, bytes)
            or len(data) != 256
            or address & 255
            or not image_size
        ):
            raise ValueError("Native aligned256-byte M16C page required")
        if not verify:
            self.write(b"\xa6")
        self.batch(
            (
                bytes(
                    (
                        0xA3 if verify else 0xA2,
                        (address >> 8) & 255,
                        (address >> 16) & 255,
                    )
                ),
                data,
            )
        )
        self.transferred += 256
        self.void(
            "progress",
            transferred=self.transferred,
            percent=round(self.transferred * 100 / (image_size * 2)),
        )
        while True:
            self.void("wait", milliseconds=5)
            if verify:
                self.write(b"\xa8")
                try:
                    status = self.read_exact(1)[0]
                except NativeTransportError as error:
                    if error.code in (9, 16):
                        raise SilProtocolError(15, 0x59ED24) from error
                    raise
                if status == 255:
                    continue
                if status:
                    raise SilProtocolError(15, 0x59ED24)
                break
            result = self.m16c_status()
            if result is None:
                raise SilProtocolError(13, 0x59EA6C)
            first, second = result
            if first & 0x80:
                if first & 0x30 or second & 2:
                    raise SilProtocolError(13, 0x59EA6C)
                break

    def program(self, image: bytes, password: int, *, image_size: int) -> None:
        """18:59d28c exactly3regions; eraseonce and write+verify each256-byte page."""
        _unsigned(image_size, 64 * 1024 * 1024)
        if not image_size:
            raise ValueError("Actual positive native image flash size required")
        regions = m16c_regions()
        required = sum(size for _, size in regions)
        if not isinstance(image, bytes) or len(image) < required:
            raise ValueError("Materialized M16C image must cover all native regions")
        self.password(password)
        offset = 0
        for address, size in regions:
            self.erase(address + size - 1)
            for page in range(0, size, 256):
                data = image[offset + page : offset + page + 256]
                self.page(address + page, data, image_size, verify=False)
                self.page(address + page, data, image_size, verify=True)
            offset += size


def _additive(packet: bytes) -> bytes:
    return packet + bytes((sum(packet) & 255,))


class DcmprlSIL(SilKWP):
    """18:59a2fc/59afa8/59ba3c DCMPRL literal diagnostic and image algorithms."""

    def __init__(self, io: ExecutableIO, protocol_id: int):
        super().__init__(io, protocol_id)
        self.countdown = 0

    def fast_init(self, *, padding: bool) -> None:
        """18:59adac configures25/50ms and initializes targetc7 at caller baud."""
        from scripts.j2534_2026 import j2534_indication

        if type(padding) is not bool:
            raise ValueError("Source-mapped native padding Boolean required")
        for parameter, value in ((0x14, 25), (0x15, 50)):
            self.void("ioctl", ioctl=2, config=((parameter, value),))
        result = executable_j2534_call(
            self.io,
            "ioctl",
            ioctl=5,
            input=_additive(b"\x81\xc7\xf1\x81"),
        )
        message = legacy_messages((result,))[0]
        if message.protocol_id != self.protocol_id:
            raise ValueError(
                "Native DCMPRL FAST_INIT reply belongs to another protocol"
            )
        if j2534_indication(message.rx_status, padding) != 3:
            legacy_messages(
                executable_j2534_call(
                    self.io, "read_messages", protocol_id=self.protocol_id, count=1
                )
            )

    def security(self) -> None:
        self.void("wait", milliseconds=100)
        request = _additive(b"\x82\xc7\xf1\x27\x01")
        response = self.exchange(request, minimum=7, error=16, body=b"\x67\x01")
        # 18:59a298 arithmetic is independently corroborated by static x86.
        key = bytes(
            ((response[6] + 0x3B) & 255, (response[5] + response[6] + 0x13) & 255)
        )
        self.void("wait", milliseconds=100)
        self.exchange(
            _additive(b"\x84\xc7\xf1\x27\x02" + key),
            minimum=5,
            error=17,
            body=b"\x67\x02",
        )

    def reset(self) -> None:
        self.void("wait", milliseconds=100)
        self.exchange(
            _additive(b"\x82\xc7\xf1\x11\x01"), minimum=5, error=24, body=b"\x51\x01"
        )

    def routine(self, command: int, identifier: int, value: int = 1) -> None:
        """18:59b6c4 service31 has different start and result message lengths."""
        _unsigned(command, 255)
        _unsigned(identifier, 0xFFFF)
        _unsigned(value, 255)
        parameters = bytes((command,)) + identifier.to_bytes(2, "big")
        if command != 1:
            parameters += bytes((value,))
        self.void("wait", milliseconds=100)
        self.exchange(
            _additive(
                bytes((0x84 if command == 1 else 0x85, 0xC7, 0xF1, 0x31)) + parameters
            ),
            minimum=7 if command == 1 else 8,
            error=25,
            body=b"\x71" + parameters,
        )

    def program_block(
        self,
        image: bytes,
        sizes: tuple[int, ...],
        ordinal: int,
        *,
        cpu_type: str,
        kind_of_ecu: str,
        image_size: int,
    ) -> None:
        """18:59ba3c preserves prefix sums and per-block image adjustments."""
        if (
            not isinstance(image, bytes)
            or not isinstance(sizes, tuple)
            or not 0 < len(sizes) <= 65536
            or any(type(size) is not int or not 0 < size <= 0xFFFFFF for size in sizes)
        ):
            raise ValueError(
                "Bounded original DCMPRL image and block-size vector required"
            )
        _unsigned(ordinal, len(sizes))
        _unsigned(image_size, 64 * 1024 * 1024)
        if (
            not ordinal
            or not image_size
            or not isinstance(kind_of_ecu, str)
            or len(kind_of_ecu) > 259
        ):
            raise ValueError("Native DCMPRL one-based block and flash size required")
        base, adjustment = dcmprl_layout(cpu_type, ordinal)
        prefix = sum(sizes[: ordinal - 1])
        size = sizes[ordinal - 1]
        start = adjustment + prefix
        address = base + prefix
        if start + size > len(image) or address + size > 0x1000000:
            raise ValueError("Native DCMPRL image/address span is not covered")
        self.download(address, size)
        self.transfer(
            image[start : start + size],
            cpu_type=cpu_type,
            kind_of_ecu=kind_of_ecu,
            image_size=image_size,
        )

    def download(self, address: int, size: int) -> None:
        _unsigned(address, 0xFFFFFF)
        _unsigned(size, 0xFFFFFF)
        self.void("wait", milliseconds=100)
        request = _additive(
            b"\x89\xc7\xf1\x34\x00\x33"
            + address.to_bytes(3, "big")
            + size.to_bytes(3, "big")
        )
        self.exchange(request, minimum=8, error=26, body=b"\x74\x30")

    def transfer(
        self, data: bytes, *, cpu_type: str, kind_of_ecu: str, image_size: int
    ) -> None:
        if not isinstance(data, bytes) or not 0 < len(data) <= 64 * 1024 * 1024:
            raise ValueError("Bounded immutable native DCMPRL block required")
        _unsigned(image_size, 64 * 1024 * 1024)
        if not image_size or any(
            not isinstance(value, str) or len(value) > 259
            for value in (cpu_type, kind_of_ecu)
        ):
            raise ValueError("Actual native flash size and metadata strings required")
        for sequence, offset in enumerate(range(0, len(data), 60), 1):
            packet = data[offset : offset + 60]
            self.void("wait", milliseconds=100)
            request = (
                bytes((0x82 + len(packet), 0xC7, 0xF1, 0x36, sequence & 255)) + packet
            )
            self.exchange(_additive(request), minimum=5, error=27, body=b"\x76")
            self.transferred += len(packet) * 2
            if not self.countdown:
                self.countdown = (
                    660000 if kind_of_ecu != "8" and cpu_type == "31" else 15000
                )
                self.void("countdown", milliseconds=self.countdown)
            denominator = 8712 if cpu_type == "34" else image_size * 2
            self.void(
                "progress",
                transferred=self.transferred,
                percent=round(self.transferred * 100 / denominator),
            )
        self.void("wait", milliseconds=100)
        checksum = (sum(data) & 0xFFFF).to_bytes(2, "big")
        self.exchange(
            _additive(b"\x83\xc7\xf1\x37" + checksum), minimum=4, error=28, body=b"\x77"
        )

    def finish_countdown(self) -> None:
        """18:59a748 decrements the stored native countdown in500ms steps."""
        while self.countdown:
            self.void("wait", milliseconds=500)
            self.countdown -= 500
            self.void("countdown", milliseconds=self.countdown)


def sil_memory_geometry(cpu_type: str, data: bytes) -> tuple[int, ...]:
    """18:46be4c parses3+3+1+1;46ac58 is shared original executable geometry."""
    from scripts.cuw_legacy_can import CANMemory, calc_block_sizes

    if not isinstance(data, bytes) or len(data) != 8:
        raise ValueError("Exactly8 native SIL memory-info bytes required")
    return calc_block_sizes(
        cpu_type,
        CANMemory(
            int.from_bytes(data[:3], "big"),
            int.from_bytes(data[3:6], "big"),
            data[6],
            data[7],
        ),
    )


def occupant_short_key(seed: bytes, material: bytes) -> bytes:
    """18:593c80 computes the native16-bit difference; inputs stay caller-owned."""
    if any(
        not isinstance(value, bytes) or len(value) != 2 for value in (seed, material)
    ):
        raise ValueError("Exactlytwo native seed and authorization bytes required")
    return (
        (int.from_bytes(material, "big") + ~int.from_bytes(seed, "big")) & 0xFFFF
    ).to_bytes(2, "big")


def occupant_long_key(seed: bytes, shifts: bytes) -> bytes:
    """18:56a30c modifies its six-byte working copy in native index order."""
    if any(not isinstance(value, bytes) or len(value) != 6 for value in (seed, shifts)):
        raise ValueError("Exactlysix native seed and source-table bytes required")
    result = bytearray(seed)
    for index, value in enumerate(seed):
        rotation = ((value >> (shifts[index] & 31)) & 3) + 1
        lookup = value & 7
        if lookup > 5:
            lookup -= 6
        result[index] = (
            ((value >> (8 - rotation)) | (value << rotation)) + result[lookup]
        ) & 255
    return bytes(result)


class OccupantSIL(SilKWP):
    """18:593538/593dd8/593930 actual occupant security and session packets."""

    def short_location_password(self, location: bytes, password: int) -> None:
        """18:592ebc five separate writes; zero-duration native Sleep is retained."""
        _unsigned(password)
        if not isinstance(location, bytes) or not 4 <= len(location) <= 128:
            raise ValueError("Imported hexadecimal LocationID with four bytes required")
        for index, packet in enumerate(
            (
                b"\0",
                b"\0",
                location[:2][::-1],
                location[2:4][::-1],
                password.to_bytes(4, "little"),
            )
        ):
            self.write(packet)
            if index != 4:
                self.void("wait", milliseconds=0)
        if self.read_exact(17)[0] != 0x3C:
            raise SilProtocolError(7, 0x592EBC)
        self.write(b"\x3c")

    def finish(self) -> None:
        """18:594688/484448 sends80 and reads frames until a leading3c."""
        self.write(b"\x80")
        while self.read_exact(1) != b"\x3c":
            pass

    def fast_init(self, target: int, mode: int, *, padding: bool) -> None:
        """18:482958 with null native cancellation pointer, including Sleep100."""
        from scripts.j2534_2026 import j2534_indication

        _unsigned(target, 255)
        if type(mode) is not int or mode not in (1, 3) or type(padding) is not bool:
            raise ValueError("Actual native occupant mode and padding required")
        for parameter, value in (
            (1, 9600 if mode == 1 else 10400),
            (0x14, 35 if mode == 1 else 25),
            (0x15, 50),
        ):
            self.void("ioctl", ioctl=2, config=((parameter, value),))
        result = executable_j2534_call(
            self.io,
            "ioctl",
            ioctl=5,
            input=_additive(bytes((0x81, target, 0xF1, 0x81))),
            output_capacity=4152,
        )
        message = legacy_messages((result,))[0]
        if message.protocol_id != self.protocol_id:
            raise ValueError("Native FAST_INIT reply belongs to another protocol")
        indication = j2534_indication(message.rx_status, padding)
        self.void("wait", milliseconds=100)
        if indication != 3:
            legacy_messages(
                executable_j2534_call(
                    self.io, "read_messages", protocol_id=self.protocol_id, count=1
                )
            )

    def prepare_context(self, context: ExecutableContext) -> int:
        """12:54718c /18:59327c chooses source-bound target/material and programming session."""
        if (
            not isinstance(context, ExecutableContext)
            or context.build not in (12, 18)
            or context.controller != "CSilOccupantDetectionFlashWriter"
        ):
            raise ValueError("Original12/18 occupant executable context required")
        image = ExecutableImage(context)
        padding = context.observations.get("channel_padding")
        if (
            type(padding) is not bool
            or type(context.observations.get("protocol_id")) is not int
            or context.observations["protocol_id"] != self.protocol_id
            or self.protocol_id != 3
        ):
            raise ValueError("Actual native SIL channel protocol and padding required")
        kind_pointer, target_base, shift_base = (
            (0x5D520C, 0x62B134, 0x614004)
            if context.build == 18
            else (0x5854F0, 0x5CE9E4, 0x5B7FD4)
        )
        pointer = int.from_bytes(image.read(kind_pointer, 4), "little")
        short = context.native.base_metadata["kind_of_ecu"] == _source_string(
            image, pointer
        )
        target = image.read(target_base if short else target_base + 4, 1)[0]
        self.fast_init(target, 1 if short else 3, padding=padding)
        self.void("wait", milliseconds=100)
        if short:
            challenge = image.read(target_base + 8, 2)[::-1]
            material = image.read(target_base + 12, 2)[::-1]
            self.security_short(target, challenge, material)
        else:
            self.security_long(target, image.read(shift_base, 6))
        self.programming_session(target)
        self.void("wait", milliseconds=500 if short else 1500)
        return target

    def initialize_programming(
        self, context: ExecutableContext, password: int
    ) -> bytes:
        """12:546688 /18:592740 programming initialization after security/session."""
        from scripts.cuw_legacy_body import BodyOperationError, BodyTables, cpu_matches
        from scripts.cuw_legacy_can import cpu_matches as sil_cpu_matches

        _unsigned(password)
        if (
            not isinstance(context, ExecutableContext)
            or context.build not in (12, 18)
            or context.controller != "CSilOccupantDetectionFlashWriter"
        ):
            raise ValueError("Original12/18 occupant executable context required")
        image = ExecutableImage(context)
        padding = context.observations.get("channel_padding")
        if (
            type(padding) is not bool
            or type(context.observations.get("protocol_id")) is not int
            or context.observations["protocol_id"] != self.protocol_id
            or self.protocol_id != 3
        ):
            raise ValueError("Actual native SIL channel protocol and padding required")
        short = context.native.base_metadata["kind_of_ecu"] == _source_string(
            image,
            int.from_bytes(
                image.read(0x5D520C if context.build == 18 else 0x5854F0, 4),
                "little",
            ),
        )
        location = bytes.fromhex(context.native.selected.values["locationid"])
        cpu_type = executable_cpu_type(context)
        tables = SilTables(context)
        try:
            descriptor = (
                None if short else BodyTables(context).descriptor("body", cpu_type)
            )
        except BodyOperationError as error:
            raise SilProtocolError(error.code, 0x569D5C) from error
        if not short:
            self.void("set_timeout", milliseconds=5000)
        self.void("ioctl", ioctl=2, config=((1, 9600 if short else 10400),))
        self.void("ioctl", ioctl=2, config=((0x0C, 0),))
        if short:
            self.short_location_password(location, password)
            self.extended_memory = tables.cpu_mode(cpu_type)
        else:
            self.initialize(location, password, padding=padding, p4=70, p5=170)
            assert descriptor is not None
            self.extended_memory = descriptor.wide_identifier
        self.memory_known = True
        if short:
            rates = tuple(
                int.from_bytes(
                    image.read(
                        (0x5F8934 if context.build == 18 else 0x59F8A0) + index * 4, 4
                    ),
                    "little",
                )
                for index in range(3)
            )
            self.bootstrap(
                cpu_type, (rates[0], rates[1], rates[2]), tables.range_rows()
            )
            self.handshake(0)
        memory = self.memory()
        if short:
            matched = sil_cpu_matches(
                cpu_type, memory[7], self.extended_memory, tables.descriptor_rows()
            )
        else:
            assert descriptor is not None
            matched = cpu_matches(descriptor, memory[7], self.extended_memory)
        if not matched:
            raise SilProtocolError(10, 0x592740)
        return memory

    def security_short(self, target: int, challenge: bytes, material: bytes) -> None:
        _unsigned(target, 255)
        if any(
            not isinstance(value, bytes) or len(value) != 2
            for value in (challenge, material)
        ):
            raise ValueError(
                "Exactlytwo actual selected native challenge bytes required"
            )
        response = self.exchange(
            _additive(bytes((0x84, target, 0xF1, 0x27, 1)) + challenge),
            minimum=7,
            error=16,
            header=bytes((0x84, 0xF1, target)),
            body=b"\x67\x01",
        )
        key = occupant_short_key(response[5:7], material)
        self.exchange(
            _additive(bytes((0x84, target, 0xF1, 0x27, 2)) + key),
            minimum=6,
            error=17,
            header=bytes((0x83, 0xF1, target)),
            body=b"\x67\x02\xaa",
        )

    def security_long(self, target: int, shifts: bytes) -> None:
        _unsigned(target, 255)
        if not isinstance(shifts, bytes) or len(shifts) != 6:
            raise ValueError(
                "Six source-authenticated native shift-table bytes required"
            )
        response = self.exchange(
            _additive(bytes((0x82, target, 0xF1, 0x27, 0x61))),
            minimum=12,
            error=16,
            header=bytes((0x88, 0xF1, target)),
            body=b"\x67\x61",
        )
        key = occupant_long_key(response[5:11], shifts)
        self.exchange(
            _additive(bytes((0x88, target, 0xF1, 0x27, 0x62)) + key),
            minimum=6,
            error=17,
            header=bytes((0x83, 0xF1, target)),
            body=b"\x67\x62\x34",
        )

    def programming_session(self, target: int) -> None:
        _unsigned(target, 255)
        self.exchange(
            _additive(bytes((0x82, target, 0xF1, 0x10, 2))),
            minimum=4,
            error=18,
            wait_ms=0,
            header=bytes((0x81, 0xF1, target)),
            body=b"\x50",
        )


def _source_string(image: ExecutableImage, pointer: int) -> str:
    if pointer == 0:
        return ""
    value = bytearray()
    for offset in range(32):
        byte = image.read(pointer + offset, 1)[0]
        if byte == 0:
            return bytes(value).decode("ascii")
        value.append(byte)
    raise ValueError("Native SIL CPU name exceeds recovered bound")


class SilTables:
    """12:4513d4/18:47f098 initialization plus file-backed native CPU/range rows.

    The PE has zero name cells until native initialization copies string pointers.
    Only the two recovered initializer spans are decoded; no PE is executed.
    """

    def __init__(self, context: ExecutableContext):
        self.image = ExecutableImage(context)
        cpu_start, range_start, self.cpu_base, self.range_base = (
            (0x47F12C, 0x47F2EA, 0x5F731C, 0x5F7470)
            if context.build == 18
            else (0x451468, 0x451626, 0x59EC90, 0x59EDE4)
        )
        self.names: dict[int, int] = {}
        cpu = self.image.read(cpu_start, 0x1AE)
        for load, store in (
            (rb"\xa1(.{4})", rb"\x89\x46(.{1})|\x89\x86(.{4})"),
            (rb"\x8b\x15(.{4})", rb"\x89\x16|\x89\x56(.{1})|\x89\x96(.{4})"),
            (rb"\x8b\x0d(.{4})", rb"\x89\x4e(.{1})|\x89\x8e(.{4})"),
        ):
            for match in re.finditer(load + b"(?:" + store + b")", cpu, re.DOTALL):
                source, *offsets = match.groups()
                offset = next((value for value in offsets if value is not None), b"\0")
                destination = self.cpu_base + int.from_bytes(offset, "little")
                self.names[destination] = self.number(int.from_bytes(source, "little"))
        ranges = self.image.read(range_start, 0x5A)
        for pattern in (
            rb"\xa1(.{4})\xa3(.{4})",
            rb"\x8b\x15(.{4})\x89\x15(.{4})",
            rb"\x8b\x0d(.{4})\x89\x0d(.{4})",
        ):
            for match in re.finditer(pattern, ranges, re.DOTALL):
                source, destination = (
                    int.from_bytes(v, "little") for v in match.groups()
                )
                self.names[destination] = self.number(source)
        if set(self.names) != {
            *(self.cpu_base + index * 8 for index in range(41)),
            *(self.range_base + index * 44 for index in range(8)),
        }:
            raise ValueError(
                "Original SIL initializer does not cover its exact name cells"
            )
        start = 0x47F358 if context.build == 18 else 0x451694
        code = self.image.read(start, 0x79)
        registers: dict[int, int] = {}
        cells: dict[int, int] = {}
        cursor = 0
        while cursor < len(code):
            opcode = code[cursor]
            if opcode == 0xA1:
                registers[0] = self.number(
                    int.from_bytes(code[cursor + 1 : cursor + 5], "little")
                )
                cursor += 5
            elif opcode == 0x8B and code[cursor + 1] in (0x0D, 0x15, 0x35, 0x3D):
                registers[(code[cursor + 1] >> 3) & 7] = self.number(
                    int.from_bytes(code[cursor + 2 : cursor + 6], "little")
                )
                cursor += 6
            elif opcode == 0x89 and code[cursor + 1] == 0x13:
                cells[0] = registers[2]
                cursor += 2
            elif opcode == 0x89 and code[cursor + 1] in (0x43, 0x4B, 0x53, 0x73, 0x7B):
                cells[code[cursor + 2]] = registers[(code[cursor + 1] >> 3) & 7]
                cursor += 3
            else:
                raise ValueError(
                    "Unrecognized original CPU-remapping initialization assignment"
                )
        if set(cells) != set(range(0, 0x48, 4)):
            raise ValueError("Original CPU-remapping table has incomplete assignments")
        self.remapping = tuple(
            (self.string(cells[index]), self.string(cells[index + 4]))
            for index in range(0, 0x48, 8)
        )

    def number(self, address: int) -> int:
        return int.from_bytes(self.image.read(address, 4), "little")

    def name(self, address: int) -> str:
        pointer = self.names.get(address, self.number(address))
        return self.string(pointer)

    def string(self, pointer: int) -> str:
        return _source_string(self.image, pointer)

    def dynamic_cpu(self, cpu_type: str) -> bool:
        """18:47f4ec six literal comparisons, shared with first six mapping keys."""
        if not isinstance(cpu_type, str) or len(cpu_type) > 259:
            raise ValueError("Bounded normalized native CPU type required")
        return cpu_type in {name for name, _ in self.remapping[:6]}

    def cpu_mode(self, cpu_type: str) -> bool:
        """18:47f484 first matching CPU row, defaultfalse after42rows."""
        if not isinstance(cpu_type, str) or len(cpu_type) > 259:
            raise ValueError("Bounded normalized native CPU type required")
        return next(
            (mode for name, _, mode in self.descriptor_rows() if name == cpu_type),
            False,
        )

    def remap_cpu(self, cpu_type: str) -> str | None:
        """18:47f614 exact nine initialized string pairs, no guessed CPU alias."""
        if not isinstance(cpu_type, str) or len(cpu_type) > 259:
            raise ValueError("Bounded normalized native CPU type required")
        return next(
            (replacement for name, replacement in self.remapping if name == cpu_type),
            None,
        )

    def descriptor_rows(self) -> tuple[tuple[str, int, bool], ...]:
        return tuple(
            (
                self.name(row),
                self.image.read(row + 4, 1)[0],
                bool(self.image.read(row + 5, 1)[0]),
            )
            for row in (self.cpu_base + index * 8 for index in range(42))
        )

    def range_rows(self) -> tuple[tuple[str, tuple[tuple[int, int], ...]], ...]:
        return tuple(
            (
                self.name(row),
                tuple(
                    (self.number(row + 4 + index * 8), self.number(row + 8 + index * 8))
                    for index in range(5)
                ),
            )
            for row in (self.range_base + index * 44 for index in range(9))
        )


class EmpsController:
    """12:544a44/54551c and18:590af8/5915a0 controller retry chronology.

    Fields +68/+78/+80/+88 belong to this controller, not saved recovery.
    The GUI callback reads a user's retry choice, never a programming result.
    """

    def __init__(self, context: ExecutableContext, io: ExecutableIO):
        if (
            not isinstance(context, ExecutableContext)
            or context.controller != "CSilEMPS_V850E_PS1_2FlashWriter"
        ):
            raise ValueError("Original12/18 EMPS executable context required")
        context.state.validate()
        self.image = ExecutableImage(context)
        if (
            context.observations.get("protocol_id") != 3
            or type(context.observations.get("protocol_id")) is not int
        ):
            raise ValueError("Actual native SIL connection protocol3 required")
        padding = context.observations.get("channel_padding")
        if type(padding) is not bool:
            raise ValueError("Actual source-mapped native channel padding required")
        first = context.native.first_image
        if first is None:
            raise ValueError("Imported native first CPU image required")
        self.target, self.count = emps_selection(
            context.native.base_metadata["kind_of_ecu"],
            executable_cpu_type(context, 0),
        )
        if (
            not isinstance(first.data, bytes)
            or not 0 < len(first.data) <= 64 * 1024 * 1024
            or type(first.flash_size) is not int
            or not 0 < first.flash_size <= 64 * 1024 * 1024
            or len(first.data) < self.count * 1024
        ):
            raise ValueError("Imported first image does not cover native EMPS count")
        self.context, self.io = context, io
        self.raw = EmpsSIL(io, 3)
        self.padding = padding
        self.firmware = first
        self.terminal = False
        self.flag_88 = False
        self.value_78 = self.value_80 = 0

    def status(self, index: int) -> int:
        _unsigned(index, 2)
        base = 0x5F1A4C if self.context.build == 18 else 0x59A7F4
        return int.from_bytes(self.image.read(base + index * 4, 4), "little")

    def error(self, error: ExecutableNativeError) -> None:
        if not isinstance(error, (ExecutableJ2534Error, SilProtocolError)):
            return
        self.value_78 = error.native_code & 0xFFFFFFFF
        if isinstance(error, ExecutableJ2534Error):
            self.value_80 = error.driver_status

    def error_handler(self, status: int, recreate: bool) -> None:
        while True:
            executable_sync(self.io, "value_70", value=status)
            executable_sync(
                self.io,
                "values_78_80",
                value_78=self.value_78,
                value_80=self.value_80,
            )
            self.flag_88 = False
            executable_sync(self.io, "flag_88", value=False)
            executable_sync(self.io, "error_handler")
            self.flag_88 = executable_sync(self.io, "read_flag_88")
            if not self.flag_88:
                self.terminal = True
                return
            if not recreate:
                return
            self.value_78 = self.value_80 = 0
            try:
                # Frozen shared helper owns disconnect/close/unload/open/filter.
                executable_reconnect(self.context, self.io, 3)
            except ExecutableJ2534Error as error:
                self.error(error)
                status = self.status(2)
                continue
            return

    def run(self) -> dict:
        old_read = _unsigned(self.io.call("get_timeout"))
        old_send = _unsigned(self.io.call("get_send_timeout"))
        success = False
        try:
            if self.context.build == 12:
                self.raw.void("wait", milliseconds=2000)
            try:
                self.raw.fast_init(self.target, padding=self.padding)
            except ExecutableNativeError as error:
                if isinstance(error, ExecutableJ2534Error):
                    self.error(error)
                self.error_handler(self.status(0), True)
            else:
                self.raw.void("set_timeout", milliseconds=60000)
                failed = False
                try:
                    self.raw.prepare(self.target, self.count)
                except ExecutableNativeError as error:
                    failed = True
                    self.error(error)
                self.raw.void("set_send_timeout", milliseconds=20000)
                while True:
                    if self.flag_88 and not self.raw.needs_recreate:
                        failed = True
                        self.raw.void("wait", milliseconds=3000)
                    elif not failed:
                        try:
                            self.raw.transfer(
                                self.firmware.data,
                                self.count,
                                self.raw.packet_index,
                                image_size=self.firmware.flash_size,
                            )
                            success = True
                            self.raw.void("wait", milliseconds=2500)
                        except ExecutableNativeError as error:
                            failed = True
                            self.error(error)
                    if not failed:
                        break
                    self.error_handler(self.status(1), self.raw.needs_recreate)
                    if self.terminal:
                        break
                    failed = False
        finally:
            try:
                self.raw.restore("set_timeout", old_read)
            finally:
                self.raw.restore("set_send_timeout", old_send)
        executable_sync(self.io, "flag_68", value=self.terminal)
        executable_sync(
            self.io,
            "values_78_80",
            value_78=self.value_78,
            value_80=self.value_80,
        )
        executable_sync(self.io, "owner_clear")
        executable_sync(
            self.io, "completion", outcome="success" if success else "failure"
        )
        return {
            "controller": self.context.controller,
            "success": success,
            "packet_index": self.raw.packet_index,
            "native_flag_68": self.terminal,
            "native_value_78": self.value_78,
            "native_value_80": self.value_80,
        }


class DcmprlController:
    """12:54ccf8 /18:59a748 initial/program/error-dialog/final callback flow."""

    def __init__(self, context: ExecutableContext, io: ExecutableIO):
        if (
            not isinstance(context, ExecutableContext)
            or context.controller != "CSilDCMPRLFlashWriter"
        ):
            raise ValueError("Original12/18 DCMPRL executable context required")
        context.state.validate()
        self.image = ExecutableImage(context)
        if (
            type(context.observations.get("protocol_id")) is not int
            or context.observations.get("protocol_id") != 3
        ):
            raise ValueError("Actual native SIL connection protocol3 required")
        padding = context.observations.get("channel_padding")
        if type(padding) is not bool:
            raise ValueError("Actual source-mapped native channel padding required")
        selected, first = context.native.image, context.native.first_image
        if selected is None or first is None:
            raise ValueError("Imported selected and first native CPU images required")
        if any(
            not isinstance(item.data, bytes)
            or not 0 < len(item.data) <= 64 * 1024 * 1024
            or type(item.flash_size) is not int
            or not 0 < item.flash_size <= 64 * 1024 * 1024
            for item in (selected, first)
        ):
            raise ValueError(
                "Immutable materialized native images and FlashSize required"
            )
        self.context, self.io, self.padding = context, io, padding
        self.firmware = selected
        self.cpu_type = executable_cpu_type(context, 0)
        self.kind = context.native.base_metadata["kind_of_ecu"]
        self.sizes = dcmprl_block_sizes(self.cpu_type, len(first.data))
        prefix = 0
        for ordinal, size in enumerate(self.sizes, 1):
            address, adjustment = dcmprl_layout(self.cpu_type, ordinal)
            if (
                prefix + adjustment + size > len(selected.data)
                or address + prefix + size > 0x1000000
            ):
                raise ValueError(
                    "Imported DCMPRL image does not cover native block spans"
                )
            prefix += size
        self.raw = DcmprlSIL(io, 3)
        self.value_78 = self.value_80 = 0
        self.terminal = False

    def status(self, index: int) -> int:
        _unsigned(index, 2)
        base = 0x5F1A4C if self.context.build == 18 else 0x59A7F4
        return int.from_bytes(self.image.read(base + index * 4, 4), "little")

    def error(self, error: ExecutableNativeError) -> None:
        if not isinstance(error, (ExecutableJ2534Error, SilProtocolError)):
            return
        self.value_78 = error.native_code & 0xFFFFFFFF
        if isinstance(error, ExecutableJ2534Error):
            self.value_80 = error.driver_status

    def error_handler(self, status: int, program_failed: bool) -> None:
        executable_sync(self.io, "value_70", value=status)
        while True:
            executable_sync(
                self.io, "values_78_80", value_78=self.value_78, value_80=self.value_80
            )
            executable_sync(self.io, "flag_88", value=False)
            executable_sync(self.io, "error_handler")
            if not executable_sync(self.io, "read_flag_88"):
                self.terminal = True
                return
            self.context.state.retry_mode = True
            self.value_78 = self.value_80 = 0
            if program_failed:
                self.raw.transferred = 0
                self.raw.void("progress", transferred=0, percent=0)
            try:
                executable_reconnect(self.context, self.io, 3)
            except ExecutableNativeError as error:
                self.error(error)
                executable_sync(self.io, "value_70", value=self.status(2))
                continue
            # Native59acbb jumps to59ad0f finalization, not the programming phase.
            return

    def run(self) -> dict:
        old_read = _unsigned(self.io.call("get_timeout"))
        success = initial_failed = program_failed = False
        self.raw.countdown = 0
        self.raw.void("countdown", milliseconds=0)
        try:
            try:
                self.raw.void("set_timeout", milliseconds=10000)
                self.raw.void("ioctl", ioctl=2, config=((1, 10400),))
                self.raw.void(
                    "ioctl",
                    ioctl=2,
                    config=(
                        (0x0C, 10 if self.kind == "8" or self.cpu_type == "31" else 2),
                    ),
                )
                self.raw.fast_init(padding=self.padding)
                if self.context.state.retry_mode:
                    self.raw.reset()
                    self.raw.void("wait", milliseconds=15000)
                    self.raw.fast_init(padding=self.padding)
                self.raw.security()
            except ExecutableNativeError as error:
                initial_failed = True
                self.error(error)
            if not initial_failed:
                try:
                    identifier = 0x0201 if self.kind == "8" else 0x0200
                    self.raw.routine(1, identifier)
                    for ordinal in range(1, len(self.sizes) + 1):
                        self.raw.program_block(
                            self.firmware.data,
                            self.sizes,
                            ordinal,
                            cpu_type=self.cpu_type,
                            kind_of_ecu=self.kind,
                            image_size=self.firmware.flash_size,
                        )
                    self.raw.routine(2, identifier)
                    self.raw.reset()
                    self.raw.finish_countdown()
                    success = True
                except ExecutableNativeError as error:
                    program_failed = True
                    self.error(error)
            if initial_failed or program_failed:
                self.error_handler(
                    self.status(0 if initial_failed else 1), program_failed
                )
        finally:
            self.raw.restore("set_timeout", old_read)
        executable_sync(self.io, "flag_68", value=self.terminal)
        executable_sync(
            self.io, "values_78_80", value_78=self.value_78, value_80=self.value_80
        )
        executable_sync(self.io, "owner_clear")
        executable_sync(
            self.io, "completion", outcome="success" if success else "failure"
        )
        return {
            "controller": self.context.controller,
            "success": success,
            "transferred": self.raw.transferred,
            "countdown": self.raw.countdown,
            "retry_mode": self.context.state.retry_mode,
            "native_flag_68": self.terminal,
            "native_value_78": self.value_78,
            "native_value_80": self.value_80,
        }


class GenericSilController:
    """12:453b58 /18:482fac complete native generic Execute chronology.

    Selected password RAM and the selected driver's +10 enum come from their
    source producers, independently of the transport mode/driver-kind enum.
    """

    def __init__(
        self,
        context: ExecutableContext,
        io: ExecutableIO,
    ):
        if (
            not isinstance(context, ExecutableContext)
            or context.controller != "CSilFlashWriter"
        ):
            raise ValueError(
                "Original generic SIL context and driver predicate required"
            )
        old_password = executable_selected_password(context)
        context.state.validate()
        self.image = ExecutableImage(context)
        firmware = context.native.image
        if (
            firmware is None
            or not isinstance(firmware.data, bytes)
            or not 0 < len(firmware.data) <= 64 * 1024 * 1024
            or type(firmware.flash_size) is not int
            or not 0 < firmware.flash_size <= 64 * 1024 * 1024
        ):
            raise ValueError("Imported selected native CPU image required")
        self.context, self.io, self.firmware = context, io, firmware
        self.old_password = old_password
        self.native_delay = selected_driver_delay(context)
        self.raw = SilRaw(io, 3)
        self.value_78 = self.value_80 = 0
        self.terminal = False

    def status(self, index: int) -> int:
        _unsigned(index, 2)
        base = 0x5F1A4C if self.context.build == 18 else 0x59A7F4
        return int.from_bytes(self.image.read(base + index * 4, 4), "little")

    def error(self, error: ExecutableNativeError) -> None:
        if not isinstance(error, (ExecutableJ2534Error, SilProtocolError)):
            return
        self.value_78 = error.native_code & 0xFFFFFFFF
        if isinstance(error, ExecutableJ2534Error):
            self.value_80 = error.driver_status

    def error_handler(self, *, program_failed: bool) -> None:
        executable_sync(self.io, "value_70", value=self.status(int(program_failed)))
        apply_recovery_password_state(
            self.context,
            self.io,
            self.raw.writing_end_block if program_failed else False,
            self.value_78,
        )
        while True:
            executable_sync(
                self.io, "values_78_80", value_78=self.value_78, value_80=self.value_80
            )
            executable_sync(self.io, "flag_88", value=False)
            executable_sync(self.io, "error_handler")
            retry = executable_sync(self.io, "read_flag_88")
            if program_failed:
                self.raw.transferred = 0
                self.raw.void("progress", transferred=0, percent=0)
            if not retry:
                self.terminal = True
                return
            if not program_failed:
                self.value_78 = self.value_80 = 0
            try:
                executable_reconnect(self.context, self.io, 3)
            except (ExecutableJ2534Error, SilProtocolError) as error:
                self.error(error)
                executable_sync(self.io, "value_70", value=self.status(2))
                continue
            return

    def run(self) -> dict:
        initial_failed = program_failed = success = False
        try:
            memory = self.raw.initialize_generic(self.context, self.old_password)
        except ExecutableNativeError as error:
            initial_failed = True
            self.error(error)
        else:
            try:
                self.raw.program_ranges(
                    self.firmware.data,
                    memory,
                    executable_cpu_type(self.context),
                    self.context.native.base_metadata["kind_of_ecu"],
                    image_size=self.firmware.flash_size,
                    native_delay=self.native_delay
                    and executable_cpu_type(self.context)
                    == _source_string(
                        self.image,
                        int.from_bytes(
                            self.image.read(
                                0x5D4F7C if self.context.build == 18 else 0x585260, 4
                            ),
                            "little",
                        ),
                    ),
                    range_rows=SilTables(self.context).range_rows(),
                )
                self.context.state.use_new_software_password = False
                success = True
            except ExecutableNativeError as error:
                program_failed = True
                self.error(error)
        if initial_failed or program_failed:
            self.error_handler(program_failed=program_failed)
        executable_sync(self.io, "flag_68", value=self.terminal)
        executable_sync(
            self.io, "values_78_80", value_78=self.value_78, value_80=self.value_80
        )
        executable_sync(self.io, "owner_clear")
        executable_sync(
            self.io, "completion", outcome="success" if success else "failure"
        )
        return {
            "controller": self.context.controller,
            "success": success,
            "transferred": self.raw.transferred,
            "native_flag_68": self.terminal,
            "native_value_78": self.value_78,
            "native_value_80": self.value_80,
        }


class OccupantController(GenericSilController):
    """12:546688 /18:592740 security, programming and manager-flag branches."""

    def __init__(self, context: ExecutableContext, io: ExecutableIO):
        if (
            not isinstance(context, ExecutableContext)
            or context.controller != "CSilOccupantDetectionFlashWriter"
        ):
            raise ValueError("Original occupant SIL executable context required")
        old_password = executable_selected_password(context)
        context.state.validate()
        self.image = ExecutableImage(context)
        self.context, self.io = context, io
        self.old_password = old_password
        self.raw = OccupantSIL(io, 3)
        firmware = context.native.image
        if (
            firmware is None
            or not isinstance(firmware.data, bytes)
            or not 0 < len(firmware.data) <= 64 * 1024 * 1024
            or type(firmware.flash_size) is not int
            or not 0 < firmware.flash_size <= 64 * 1024 * 1024
        ):
            raise ValueError("Imported selected occupant image required")
        self.firmware = firmware
        pointer = 0x5D520C if context.build == 18 else 0x5854F0
        self.short = context.native.base_metadata["kind_of_ecu"] == _source_string(
            self.image, int.from_bytes(self.image.read(pointer, 4), "little")
        )
        for field in ("native_flag_ed6", "native_flag_ed7"):
            if type(getattr(context.state, field, None)) is not bool:
                raise ValueError("Actual source manager occupant BOOL fields required")
        self.value_78 = self.value_80 = 0
        self.terminal = False

    def error_handler(self, *, program_failed: bool) -> None:
        executable_sync(self.io, "value_70", value=self.status(int(program_failed)))
        apply_recovery_password_state(
            self.context,
            self.io,
            self.context.state.native_flag_ed6,
            self.value_78,
        )
        executable_sync(
            self.io, "values_78_80", value_78=self.value_78, value_80=self.value_80
        )
        executable_sync(self.io, "flag_88", value=False)
        executable_sync(self.io, "error_handler")
        if not executable_sync(self.io, "read_flag_88"):
            self.terminal = True
            return
        self.value_78 = self.value_80 = 0
        executable_reconnect(self.context, self.io, 3)

    def run(self) -> dict:
        old_read = None if self.short else _unsigned(self.io.call("get_timeout"))
        initial_failed = program_failed = success = False
        try:
            try:
                self.raw.prepare_context(self.context)
            except ExecutableNativeError as error:
                initial_failed = True
                self.error(error)
            if not initial_failed or self.context.state.native_flag_ed7:
                if initial_failed:
                    self.raw.void("wait", milliseconds=1000)
                    initial_failed = False
                try:
                    password = (
                        executable_new_password(self.context)
                        if self.context.state.use_new_software_password
                        else self.old_password
                    )
                    memory = self.raw.initialize_programming(self.context, password)
                    try:
                        self.raw.program_ranges(
                            self.firmware.data,
                            memory,
                            executable_cpu_type(self.context),
                            self.context.native.base_metadata["kind_of_ecu"],
                            image_size=self.firmware.flash_size,
                            native_delay=False,
                            range_rows=SilTables(self.context).range_rows(),
                            context=self.context,
                            force_grouped=True,
                        )
                        if not self.short:
                            self.raw.finish()
                    except ExecutableNativeError:
                        self.context.state.native_flag_ed7 = True
                        program_failed = True
                        raise
                    self.context.state.use_new_software_password = False
                    self.context.state.native_flag_ed6 = False
                    self.context.state.native_flag_ed7 = False
                    success = True
                except ExecutableNativeError as error:
                    initial_failed = True
                    self.error(error)
                    if isinstance(error, (ExecutableJ2534Error, SilProtocolError)):
                        self.raw.transferred = 0
                        self.raw.void("progress", transferred=0, percent=0)
            if initial_failed or program_failed:
                self.error_handler(program_failed=program_failed)
        finally:
            if old_read is not None:
                self.raw.restore("set_timeout", old_read)
        executable_sync(self.io, "flag_68", value=self.terminal)
        executable_sync(
            self.io, "values_78_80", value_78=self.value_78, value_80=self.value_80
        )
        executable_sync(self.io, "owner_clear")
        executable_sync(
            self.io, "completion", outcome="success" if success else "failure"
        )
        return {
            "controller": self.context.controller,
            "success": success,
            "transferred": self.raw.transferred,
            "native_flag_68": self.terminal,
            "native_value_78": self.value_78,
            "native_value_80": self.value_80,
        }


class M16CController(GenericSilController):
    """12:54f758 /18:59d28c other-CPU bootstrap and full M16C Execute."""

    def __init__(
        self,
        context: ExecutableContext,
        io: ExecutableIO,
    ):
        if (
            not isinstance(context, ExecutableContext)
            or context.controller != "CSilM16CFlashWriter"
        ):
            raise ValueError(
                "Original M16C context and actual selected password vector required"
            )
        context.state.validate()
        self.image = ExecutableImage(context)
        padding = context.observations.get("channel_padding")
        if (
            type(padding) is not bool
            or type(context.observations.get("protocol_id")) is not int
            or context.observations["protocol_id"] != 3
        ):
            raise ValueError("Actual native SIL channel protocol and padding required")
        firmware = context.native.image
        if (
            firmware is None
            or not isinstance(firmware.data, bytes)
            or len(firmware.data) < sum(size for _, size in m16c_regions())
            or len(firmware.data) > 64 * 1024 * 1024
            or type(firmware.flash_size) is not int
            or not 0 < firmware.flash_size <= 64 * 1024 * 1024
        ):
            raise ValueError("Imported image covering all actual M16C regions required")
        self.context, self.io, self.firmware = context, io, firmware
        self.raw = M16CSIL(io, 3)
        self.padding = padding
        self.value_78 = self.value_80 = 0
        self.value_70 = self.status_constructor()
        self.terminal = False

    def status_constructor(self) -> int:
        address = 0x5F1A48 if self.context.build == 18 else 0x59A7F0
        return int.from_bytes(self.image.read(address, 4), "little")

    def error_handler(self, *, program_failed: bool) -> None:
        executable_sync(self.io, "value_70", value=self.value_70)
        executable_sync(
            self.io, "values_78_80", value_78=self.value_78, value_80=self.value_80
        )
        executable_sync(self.io, "flag_88", value=False)
        executable_sync(self.io, "error_handler")
        if not executable_sync(self.io, "read_flag_88"):
            self.terminal = True
            return
        self.value_78 = self.value_80 = 0
        executable_reconnect(self.context, self.io, 3)

    def run(self) -> dict:
        failed = success = False
        selected = self.context.native.selected.index
        try:
            self.raw.void("ioctl", ioctl=2, config=((1, 9600),))
            self.raw.void("ioctl", ioctl=2, config=((0x0C, 0),))
            pointer = 0x5D4F94 if self.context.build == 18 else 0x585278
            types = {
                _source_string(
                    self.image,
                    int.from_bytes(self.image.read(pointer + offset, 4), "little"),
                )
                for offset in (0, 4)
            }
            other = next(
                (
                    cpu
                    for cpu in self.context.cpus
                    if cpu.selected.index != selected
                    and executable_cpu_type(self.context, cpu.selected.index) in types
                ),
                None,
            )
            if other is None:
                failed = True
            else:
                location = other.location_id
                if location is None:
                    raise ValueError("Imported bootstrap CPU LocationID required")
                self.raw.initialize(
                    location,
                    executable_selected_password(self.context, other.selected.index),
                    padding=self.padding,
                )
                try:
                    self.raw.handshake(0)
                except ExecutableNativeError as error:
                    raise SilProtocolError(
                        5, 0x59D28C if self.context.build == 18 else 0x54F758
                    ) from error
        except ExecutableNativeError as error:
            failed = True
            self.value_70 = self.status(0)
            if isinstance(error, (ExecutableJ2534Error, SilProtocolError)):
                self.error(error)
        if not failed:
            try:
                self.raw.void("set_timeout", milliseconds=2000)
                try:
                    self.raw.program(
                        self.firmware.data,
                        executable_selected_password(self.context, selected),
                        image_size=self.firmware.flash_size,
                    )
                finally:
                    self.raw.restore("set_timeout", 1000)
                success = True
            except ExecutableNativeError as error:
                failed = True
                self.value_70 = self.status(1)
                if isinstance(error, (ExecutableJ2534Error, SilProtocolError)):
                    self.error(error)
                self.raw.transferred = 0
                self.raw.void("progress", transferred=0, percent=0)
        if failed:
            self.error_handler(program_failed=False)
        executable_sync(self.io, "flag_68", value=self.terminal)
        executable_sync(
            self.io, "values_78_80", value_78=self.value_78, value_80=self.value_80
        )
        executable_sync(self.io, "owner_clear")
        executable_sync(
            self.io, "completion", outcome="success" if success else "failure"
        )
        return {
            "controller": self.context.controller,
            "success": success,
            "transferred": self.raw.transferred,
            "native_flag_68": self.terminal,
            "native_value_78": self.value_78,
            "native_value_80": self.value_80,
        }


class _SilCIDGetter(SilRaw):
    """12:451d90/18:48122c original serial CID getter and its raw KWP helpers."""

    def __init__(
        self,
        context: ExecutableContext,
        io: ExecutableIO,
        terminated: Callable[[], bool],
    ):
        from scripts.cuw_legacy_channel import channel_state

        if not isinstance(context, ExecutableContext) or not callable(terminated):
            raise TypeError(
                "Actual imported SIL context and native termination reader required"
            )
        require_executable_standard_getter(context, "CSilCIDGetter")
        self.tables = SilTables(context)
        self.channel = channel_state(context)
        self.context = context
        self.terminated = terminated
        self.cids: list[str] = []
        self.value_d68 = self.value_d70 = 0
        self.cancelled = False
        self.completion_pair = (0x50, 0x54)
        super().__init__(io, 3)

    def stopped(self) -> bool:
        value = self.terminated()
        if type(value) is not bool:
            raise ValueError("Native getter termination reader must return BOOL")
        if value:
            self.cancelled = True
        return value

    def check(self) -> None:
        if self.stopped():
            raise _SilCIDTerminated

    def timeout(self, value: int) -> None:
        self.void("set_timeout", milliseconds=value)
        self.channel.read_timeout = value

    def reply(self) -> bytes:
        messages = legacy_messages(
            executable_j2534_call(self.io, "read_messages", protocol_id=3, count=1)
        )
        if len(messages) > 1:
            raise ValueError("Original CID getter requested one native message")
        if not messages:
            return b""
        if messages[0].protocol_id != 3:
            raise ValueError("Native CID reply belongs to another protocol")
        return messages[0].data

    def receive(self, request: bytes, error: int = 3) -> bytes:
        """18:4824b8 receives only; pending budget149, no busy retransmission."""
        old = self.channel.read_timeout
        pending = 0
        try:
            try:
                while True:
                    self.check()
                    response = self.reply()
                    if len(response) >= 6 and response[3:6] == bytes(
                        (0x7F, request[3], 0x78)
                    ):
                        pending += 1
                        if pending > 149:
                            self.write(
                                _additive(bytes((0x81, request[1], request[2], 0x82)))
                            )
                            raise SilProtocolError(error, 0x4824B8)
                        if old < 5000:
                            self.timeout(5000)
                        continue
                    if len(response) < 3:
                        raise SilProtocolError(error, 0x4824B8)
                    return response
            except _SilCIDTerminated:
                return b""
            except SilProtocolError as native:
                native.code = native.native_code = error
                raise
        finally:
            self.restore("set_timeout", old)
            self.channel.read_timeout = old

    def exchange(self, request: bytes) -> bytes:
        """18:482004 sends once, retries busy21, and delegates pending78 reads."""
        old = self.channel.read_timeout
        busy = 0
        try:
            while True:
                self.write(request)
                self.void("wait", milliseconds=100)
                pending = 0
                while True:
                    self.check()
                    response = self.reply()
                    if len(response) >= 6 and response[3:5] == bytes(
                        (0x7F, request[3])
                    ):
                        if response[5] == 0x78:
                            busy = 0
                            pending += 1
                            if pending > 149:
                                self.write(
                                    _additive(
                                        bytes((0x81, request[1], request[2], 0x82))
                                    )
                                )
                                raise SilProtocolError(3, 0x482004)
                            if old < 5000:
                                self.timeout(5000)
                            continue
                        if response[5] == 0x21:
                            busy += 1
                            if busy > 255:
                                raise SilProtocolError(3, 0x482004)
                            break
                    if len(response) < 3:
                        raise SilProtocolError(3, 0x482004)
                    return response
                self.timeout(old)
        except _SilCIDTerminated:
            return b""
        except SilProtocolError as native:
            native.code = native.native_code = 3
            raise
        finally:
            self.restore("set_timeout", old)
            self.channel.read_timeout = old

    def target(self, mode: int, variant: int) -> int:
        # 18:482d3c and12:4538ec literal target-address matrix.
        value = {
            0: {0: 0x10, 2: 0x16},
            1: {0: 0x13, 2: 0x16},
            2: {0: 0x10, 1: 0x19},
            3: {0: 0x13, 1: 0x19, 2: 0x16},
        }.get(mode, {}).get(variant)
        if value is None:
            raise SilProtocolError(3, 0x482D3C)
        return value

    def initialize_cid(self, mode: int, target: int) -> None:
        from scripts.j2534_2026 import j2534_indication

        try:
            self.void("ioctl", ioctl=2, config=((1, 9600 if mode == 1 else 10400),))
            self.check()
            if mode:
                for parameter, value in ((0x14, 35 if mode == 1 else 25), (0x15, 50)):
                    self.void("ioctl", ioctl=2, config=((parameter, value),))
                    self.check()
                result = executable_j2534_call(
                    self.io,
                    "ioctl",
                    ioctl=5,
                    input=_additive(bytes((0x81, target, 0xF1, 0x81))),
                    output_capacity=4152,
                )
                message = legacy_messages((result,))[0]
                if message.protocol_id != 3:
                    raise ValueError("CID FAST_INIT reply belongs to another protocol")
                indicated = (
                    j2534_indication(message.rx_status, self.channel.padding) == 3
                )
                self.check()
                self.void("wait", milliseconds=100)
                self.check()
                if not indicated:
                    self.reply()
            else:
                result = executable_j2534_call(
                    self.io, "ioctl", ioctl=4, input=b"\x33", output_capacity=256
                )
                if not isinstance(result, bytes) or len(result) > 256:
                    raise ValueError(
                        "Bounded native FIVE_BAUD_INIT output bytes required"
                    )
                self.check()
        except _SilCIDTerminated:
            return

    def append_quartet(self, buffer: bytearray, ordinal: int, response: bytes) -> None:
        slot = (ordinal - 1) % 4
        buffer[slot * 4 : slot * 4 + 4] = response[6:10]
        if slot == 3:
            self.cids.append(bytes(buffer).split(b"\0", 1)[0].decode("latin1"))

    def collect(self, mode: int, variant: int) -> None:
        self.void("ioctl", ioctl=8, input=None)
        target = self.target(mode, variant)
        self.initialize_cid(mode, target)
        # Fast GetCID sleeps even when its initialization helper returned early.
        if not mode and self.stopped():
            return
        self.void("wait", milliseconds=100)
        if self.stopped():
            return
        header = bytes((0x82, target, 0xF1)) if mode else b"\x68\x6a\xf1"
        count_request = _additive(header + b"\x09\x03")
        count = 0
        if mode:
            response = self.exchange(count_request)
            while not self.stopped():
                if len(response) < 6 or not response[5] or response[5] % 4:
                    raise SilProtocolError(3, 0x481AC8)
                if response[2] == target:
                    count = response[5]
                    break
                response = self.receive(count_request)
            # Native fast helper continues after an exchange returned on Terminated.
            self.void("wait", milliseconds=100)
            data_request = _additive(header + b"\x09\x04")
            response = self.exchange(data_request)
            ordinal, buffer = 1, bytearray(16)
            while not self.stopped():
                if len(response) >= 10 and response[4] == 4 and response[2] == target:
                    self.append_quartet(buffer, ordinal, response)
                    ordinal += 1
                    if ordinal > count:
                        break
                if self.stopped():
                    return
                response = self.receive(data_request)
        else:
            self.write(count_request)
            if self.stopped():
                return
            self.void("wait", milliseconds=100)
            if self.stopped():
                return
            while not self.stopped():
                response = self.reply()
                if len(response) < 6 or not response[5] or response[5] % 4:
                    raise SilProtocolError(3, 0x4815EC)
                if response[2] == target:
                    count = response[5]
                    break
            if self.stopped():
                return
            self.void("wait", milliseconds=100)
            if self.stopped():
                return
            data_request = _additive(header + b"\x09\x04")
            self.write(data_request)
            if self.stopped():
                return
            self.void("wait", milliseconds=100)
            if self.stopped():
                return
            ordinal, buffer = 1, bytearray(16)
            while ordinal <= count and not self.stopped():
                response = self.reply()
                if len(response) >= 10 and response[4] == 4 and response[2] == target:
                    self.append_quartet(buffer, ordinal, response)
                    if self.stopped():
                        return
                    ordinal += 1
        self.void("ioctl", ioctl=8, input=None)

    def run(self) -> SilCIDResult:
        from scripts.cuw_legacy_channel import connect, disconnect

        image = self.tables.image
        build = self.context.build
        modes = image.read(0x5F81F0 if build == 18 else 0x59F15C, 4)
        kind = self.context.native.base_metadata["kind_of_ecu"]
        base = 0x5D517C if build == 18 else 0x585460
        first, second = self.tables.name(base), self.tables.name(base + 4)
        variant = 0 if kind == first else 2 if kind == second else 3
        try:
            try:
                connect(self.context, self.io, 3)
                self.timeout(1000)
                self.void("wait", milliseconds=1000)
                for index, mode in enumerate(modes):
                    try:
                        self.collect(mode, variant)
                    except SilProtocolError:
                        if index == len(modes) - 1:
                            raise
                        continue
                    try:
                        if kind == first and mode in (2, 3):
                            self.collect(mode, 1)
                    except SilProtocolError:
                        pass
                    break
                # 18:4814d2 /12:45203d reads Terminated again after helper completion.
                self.check()
                self.completion_pair = (0x48, 0x4C)
            except _SilCIDTerminated:
                self.completion_pair = (0x58, 0x5C)
            except ExecutableNativeError as error:
                if isinstance(error, (ExecutableJ2534Error, SilProtocolError)):
                    self.value_d68 = error.native_code & 0xFFFFFFFF
                if isinstance(error, ExecutableJ2534Error):
                    self.value_d70 = error.driver_status
        except BaseException:
            # Host failures stay outside native EH; release owned channel resources.
            original = sys.exception()
            try:
                disconnect(self.context, self.io)
            except (Exception, KeyboardInterrupt) as cleanup:
                if original is None:
                    raise
                original.add_note(
                    "Original CID channel cleanup failed: " + type(cleanup).__name__
                )
            raise
        disconnect(self.context, self.io)
        payload = (
            build,
            self.context.container_sha256,
            tuple(self.cids),
            self.value_d68,
            self.value_d70,
            self.cancelled,
            self.completion_pair,
        )
        return SilCIDResult(*payload, _CID_ISSUER, payload, self.channel)


def discover_sil_cids(
    context: ExecutableContext, io: ExecutableIO, *, terminated: Callable[[], bool]
) -> SilCIDResult:
    """Execute the actual factory-admitted original generic serial CID getter."""
    return _SilCIDGetter(context, io, terminated).run()


def execute_sil(context: ExecutableContext, io: ExecutableIO) -> dict:
    """Concrete original12/18 Execute dispatch over source-selected controller RAM.

    Generic SIL reads the actual selected library record through the source
    driver-name classifier; no caller-supplied delay predicate is admitted.
    """
    if not isinstance(context, ExecutableContext) or not isinstance(io, ExecutableIO):
        raise TypeError("Actual source-selected SIL context and runtime required")
    context.state.validate()
    if context.controller == "CSilFlashWriter":
        return GenericSilController(context, io).run()
    if context.controller == "CSilEMPS_V850E_PS1_2FlashWriter":
        return EmpsController(context, io).run()
    if context.controller == "CSilOccupantDetectionFlashWriter":
        return OccupantController(context, io).run()
    if context.controller == "CSilDCMPRLFlashWriter":
        return DcmprlController(context, io).run()
    if context.controller == "CSilM16CFlashWriter":
        return M16CController(context, io).run()
    raise ValueError("Source-selected executable controller is not a SIL writer")
