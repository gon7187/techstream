"""Original CUW executable CAN helpers over injected J2534 primitives."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from functools import wraps
from typing import TYPE_CHECKING, ParamSpec, TypeVar

from scripts.cuw_legacy_engine import (
    ExecutableIO,
    ExecutableJ2534Error,
    ExecutableNativeError,
    executable_j2534_call,
    legacy_messages,
)
from scripts.j2534_2026 import NativeMessage, j2534_indication
from scripts.programming import NativeTransportError
from scripts.programming_2026_common import (  # noqa: F401 - source-proven pure codec exports
    basic_conversion,
    seed_key_four_round,
)
from scripts.programming_vendor import NativeTransportError as VendorTransportError

if TYPE_CHECKING:
    from scripts.cuw_legacy_channel import ChannelState
    from scripts.cuw_legacy_engine import ExecutableState


class ExecutableCANError(ValueError, ExecutableNativeError):
    """Native CPassThruException, distinct from driver and host failures."""

    def __init__(self, code: int):
        self.code = code
        super().__init__(f"Native executable CAN error {code}")

    @property
    def native_code(self) -> int:
        return self._native_code

    @native_code.setter
    def native_code(self, value: int) -> None:
        if type(value) is not int or not -128 <= value <= 255:
            raise ValueError("Native CPass category must fit its byte field")
        self._native_code = (value + 128) % 256 - 128

    @property
    def code(self) -> int:
        return self.native_code & 255

    @code.setter
    def code(self, value: int) -> None:
        self.native_code = value


_P = ParamSpec("_P")
_R = TypeVar("_R")


def _phase(code: int, *, pass_thru: bool = False):
    """Original typed EH: mutate CJ2534 category, optionally replace CPass."""

    def decorate(function: Callable[_P, _R]) -> Callable[_P, _R]:
        @wraps(function)
        def call(*args: _P.args, **kwargs: _P.kwargs) -> _R:
            try:
                return function(*args, **kwargs)
            except ExecutableJ2534Error as error:
                error.native_code = code
                raise
            except ExecutableCANError as error:
                if pass_thru:
                    raise ExecutableCANError(code) from error
                raise

        return call

    return decorate


class ExecutableCANResponseError(ExecutableCANError):
    """Native comparison failure with a bounded private response for caller EH."""

    def __init__(self, code: int, response: bytes, response_size: int):
        if (
            not isinstance(response, bytes)
            or len(response) > 4095
            or type(response_size) is not int
            or not 0 <= response_size <= 4100
        ):
            raise ValueError("Bounded actual native response required")
        self.response = response
        self.response_size = response_size
        super().__init__(code)


@dataclass
class CANTransferState:
    """Execute-local by-reference BOOL, distinct from saved WritingEndBlock."""

    end_block: bool = False
    native_state: ExecutableState | None = None

    def update(self, value: bool) -> None:
        if type(value) is not bool:
            raise ValueError("Native end-block output must be BOOL")
        self.end_block = value
        if self.native_state is not None:
            self.native_state.native_flag_ed6 = value

    def validate(self) -> None:
        if type(self.end_block) is not bool:
            raise ValueError("Native local end-block state must be BOOL")


class CANProgress:
    """Native cached count/percent arrays, virtual38/3c and fragment accounting.

    Counts include writing and verification, hence the two-image denominator.
    Reporting does not attest an ECU commit or supply a resume cursor.
    """

    def __init__(self, io: ExecutableIO, image_sizes: tuple[int, ...]):
        if (
            not isinstance(image_sizes, tuple)
            or not 0 < len(image_sizes) <= 128
            or any(
                type(size) is not int or not 0 < size <= 64 * 1024 * 1024
                for size in image_sizes
            )
        ):
            raise ValueError("Bounded imported CPU image sizes required")
        self.io, self.image_sizes = io, image_sizes
        self.counts = [0] * len(image_sizes)
        self.percentages = [0] * len(image_sizes)

    def publish_counts(self) -> None:
        if (
            self.io.call(
                "notification", field="writing_bytes", values=tuple(self.counts)
            )
            is not None
        ):
            raise ValueError("Native count notification must return None")

    def publish_percentages(self) -> None:
        if (
            self.io.call(
                "notification", field="writing_percent", values=tuple(self.percentages)
            )
            is not None
        ):
            raise ValueError("Native percentage notification must return None")

    def account(self, cpu_index: int, length: int) -> None:
        if (
            type(cpu_index) is not int
            or not 0 <= cpu_index < len(self.counts)
            or type(length) is not int
            or not 0 < length <= 4124
        ):
            raise ValueError("Bounded native CPU progress fragment required")
        self.counts[cpu_index] = (self.counts[cpu_index] + length) & 0xFFFFFFFF
        self.publish_counts()
        # VA45c818 doubles the image length before division;5b20b0 truncates.
        self.percentages[cpu_index] = int(
            self.counts[cpu_index] / (self.image_sizes[cpu_index] * 2) * 100
        )
        self.publish_percentages()

    def account_phase(
        self, cpu_index: int, length: int, completed: int, base: int
    ) -> None:
        """VA58859c: count publication, then phasecompleted/imageLength*50+base."""
        if (
            type(cpu_index) is not int
            or not 0 <= cpu_index < len(self.image_sizes)
            or type(length) is not int
            or not 0 < length <= 1024
            or type(completed) is not int
            or not 0 <= completed <= self.image_sizes[cpu_index]
            or type(base) is not int
            or base not in (0, 50)
        ):
            raise ValueError("Bounded native ZV progress phase required")
        self.counts[cpu_index] = (self.counts[cpu_index] + length) & 0xFFFFFFFF
        self.publish_counts()
        self.percentages[cpu_index] = int(
            completed / self.image_sizes[cpu_index] * 50 + base
        )
        self.publish_percentages()


@dataclass(frozen=True)
class CANMemory:
    """GetMemoryInfo output consumed by CFlashWriter::CalcBlockSizes."""

    address: int
    end_address: int
    block_size_kib: int
    firmware_descriptor: int


def calc_block_sizes(cpu_type: str, memory: CANMemory) -> tuple[int, ...]:
    """CFlashWriter::CalcBlockSizes VA46ac58, original numeric CPU strings.

    The19/73 branch deliberately discards a remainder below4KiB, matching the
    original signed division. These are executable rules, not catalog geometry.
    """
    if (
        not isinstance(cpu_type, str)
        or len(cpu_type) > 259
        or not isinstance(memory, CANMemory)
    ):
        raise ValueError("Bounded native CPU type and memory descriptor required")
    if any(
        type(value) is not int
        for value in (
            memory.address,
            memory.end_address,
            memory.block_size_kib,
            memory.firmware_descriptor,
        )
    ) or not (
        0 <= memory.address <= memory.end_address <= 0xFFFFFFFF
        and 0 <= memory.block_size_kib <= 255
        and 0 <= memory.firmware_descriptor <= 255
    ):
        raise ValueError("Bounded native memory fields required")
    length = memory.end_address - memory.address + 1
    if length > 64 * 1024 * 1024:
        raise ValueError("Host memory geometry budget exceeded")
    if cpu_type in ("4", "5", "6"):
        if length < 65536:
            raise ValueError("Native fixed-prefix geometry underflows memory")
        return (
            (65536, length - 65536)
            if length <= 0x80000
            else (65536, 0x70000, length - 0x80000)
        )
    if cpu_type == "7":
        return (0x4000, 0x58000)
    if cpu_type in ("19", "73"):
        return (0x1000,) * (length // 0x1000)
    size = 0x40000 if cpu_type == "216" else memory.block_size_kib * 1024
    if size == 0:
        raise ValueError("Native memory block-size divisor is zero")
    count, remainder = divmod(length, size)
    if count + bool(remainder) > 65536:
        raise ValueError("Host block-count budget exceeded")
    return (size,) * count + ((remainder,) if remainder else ())


def cpu_matches(
    cpu_type: str,
    descriptor: int,
    extended: bool,
    rows: tuple[tuple[str, int, bool], ...],
) -> bool:
    """VA46cb1c: first CPU row, then exact identifier AND mode comparison."""
    if (
        not isinstance(cpu_type, str)
        or len(cpu_type) > 259
        or type(descriptor) is not int
        or not 0 <= descriptor <= 255
        or type(extended) is not bool
        or not isinstance(rows, tuple)
        or len(rows) > 1024
    ):
        raise ValueError("Bounded native CPU descriptor/mode/table required")
    identified = descriptor & 0x7F if extended else descriptor >> 4 & 7
    for name, expected, mode in rows:
        if (
            not isinstance(name, str)
            or len(name) > 259
            or type(expected) is not int
            or not 0 <= expected <= 255
            or type(mode) is not bool
        ):
            raise ValueError(
                "Native CPU table row requires bounded name, byte and BOOL"
            )
        if name == "":
            return False
        if name == cpu_type:
            return expected == identified and mode == extended
    raise ValueError("Native CPU table has no sentinel or matching row")


def block_range(first: int, last: int) -> bytes:
    """Native one-based inclusive block numbers encoded as two BE16 values."""
    if (
        any(type(value) is not int for value in (first, last))
        or not 1 <= first <= last <= 65536
    ):
        raise ValueError("Native one-based bounded block interval required")
    return (first - 1).to_bytes(2, "big") + (last - 1).to_bytes(2, "big")


def original_location_id(value: str) -> bytes:
    """4199f8/40e134 zeroed256-byte array, with native two-character strtoul."""
    import re

    from scripts.cuw_legacy_engine import ExecutableForeignNativeError

    if (
        not isinstance(value, str)
        or not value.isascii()
        or len(value) > 512
        or "\0" in value
    ):
        raise ValueError("Bounded actual ASCII native LocationID required")
    if len(value) & 1:
        raise ExecutableForeignNativeError("Native byte-array text has odd length")
    result = bytearray(256)
    for index in range(0, len(value), 2):
        pair = value[index : index + 2]
        if re.fullmatch(r"[ \t\n\r\v\f]*[+-]?[0-9a-fA-F]+", pair) is None:
            raise ExecutableForeignNativeError(
                "Native byte-array conversion did not consume its pair"
            )
        result[index // 2] = int(pair, 16) & 255
    return bytes(result[:8])


def location_headers(location_id: bytes) -> tuple[bytes, bytes]:
    """VA41a1e4 plus45ea.. CBytes(two bytes).SetNum(4), independent of DLL tables."""
    if not isinstance(location_id, bytes) or len(location_id) != 8:
        raise ValueError("Imported native eight-byte LocationID required")
    return b"\0\0" + location_id[2:4], b"\0\0" + location_id[0:2]


def parse_zv_records(image: bytes) -> tuple[tuple[int, int], ...]:
    """VA587d8c: version0 header5/version1 header7 plus BE16 payload length."""
    if not isinstance(image, bytes) or not 0 < len(image) <= 64 * 1024 * 1024:
        raise ValueError("Bounded imported ZV image required")
    result = []
    offset = 0
    while offset < len(image):
        if (
            len(image) - offset < 5
            or image[offset : offset + 2] != b"ZV"
            or image[offset + 2] not in (0, 1)
        ):
            raise ValueError("Native ZV record header is truncated or unsupported")
        header = 5 if image[offset + 2] == 0 else 7
        size = header + int.from_bytes(image[offset + 3 : offset + 5], "big")
        if size > len(image) - offset or len(result) >= 65536:
            raise ValueError(
                "Native ZV record exceeds imported image or host count budget"
            )
        result.append((offset, size))
        offset += size
    return tuple(result)


def ccan_m16c_extra_regions(cpu_type: str) -> tuple[tuple[int, int], ...]:
    """VA4600d6..461d*: fixed(address,size) rows built in the initially empty vector."""
    if not isinstance(cpu_type, str) or len(cpu_type) > 128:
        raise ValueError("Bounded normalized native CPU type required")
    if cpu_type == "18":
        return (
            (0xE8000, 0x8000),
            (0xF0000, 0x8000),
            (0xF8000, 0x4000),
            (0xFC000, 0x2000),
            (0xFE000, 0x2000),
        )
    if cpu_type == "17":
        return ((0xFA000, 0x2000), (0xFC000, 0x2000), (0xFE000, 0x2000))
    if cpu_type == "54":
        return (
            *((index * 0x2000, 0x2000) for index in range(8)),
            *((0x10000 + index * 0x10000, 0x10000) for index in range(9)),
            (0xA0000, 0x20000),
        )
    if cpu_type == "90":
        return ((0xFF0000, 0x10000),)
    return ()


def ccan_prepare_mode(kind_of_ecu: str, selected_cpu_type: str) -> tuple[int, bool]:
    """VA4650*: mode60 for Kind51/CPU11; Kind3 also repeats after110ms."""
    if any(
        not isinstance(value, str) or len(value) > 128
        for value in (kind_of_ecu, selected_cpu_type)
    ):
        raise ValueError("Bounded normalized native kind and CPU type required")
    special = kind_of_ecu == "51" and selected_cpu_type == "11"
    return (0x60 if special else 2, kind_of_ecu == "3" or special)


def can_finish_ack(kind_of_ecu: str, cpu_types: tuple[str, ...]) -> bool:
    """VA47f770: Kind0 with anyCPU216 or Kind1 with anyCPU22."""
    if (
        not isinstance(kind_of_ecu, str)
        or len(kind_of_ecu) > 128
        or not isinstance(cpu_types, tuple)
        or len(cpu_types) > 128
        or any(not isinstance(value, str) or len(value) > 128 for value in cpu_types)
    ):
        raise ValueError("Bounded original kind and ordered CPU types required")
    return (kind_of_ecu == "0" and "216" in cpu_types) or (
        kind_of_ecu == "1" and "22" in cpu_types
    )


def ccan_functional_header(
    cpu_types: tuple[str, ...], location_ids: tuple[bytes, ...]
) -> bytes:
    """VA464e*/4626*:41448c uses CPU0/CPU1's final LocationID word.

    First CPU types17/54/90/18 select CPU1. This selection is independent of
    the CPU currently being written and of the DLL parameter address catalog.
    """
    if (
        not isinstance(cpu_types, tuple)
        or not isinstance(location_ids, tuple)
        or not 0 < len(cpu_types) == len(location_ids) <= 128
        or any(not isinstance(value, str) or len(value) > 128 for value in cpu_types)
        or any(
            not isinstance(value, bytes) or len(value) != 8 for value in location_ids
        )
    ):
        raise ValueError(
            "Ordered original CPU types and eight-byte LocationIDs required"
        )
    index = int(cpu_types[0] in ("17", "54", "90", "18"))
    if index >= len(location_ids):
        raise ValueError("Native functional-header selection requires CPU1")
    return b"\0\0" + location_ids[index][6:8]


def select_block_ranges(
    cpu_type: str,
    block_sizes: tuple[int, ...],
    rows: tuple[tuple[str, tuple[tuple[int, int], ...]], ...],
) -> tuple[tuple[int, int], ...]:
    """VA46c050: first matching row or empty-name sentinel, lastend0=CPUcount."""
    if (
        not isinstance(cpu_type, str)
        or len(cpu_type) > 259
        or not isinstance(block_sizes, tuple)
        or not 0 < len(block_sizes) <= 65536
        or any(
            type(size) is not int or not 0 <= size <= 0xFFFFFFFF for size in block_sizes
        )
    ):
        raise ValueError("Bounded native CPU and block-size vector required")
    if not isinstance(rows, tuple) or not 0 < len(rows) <= 1024:
        raise ValueError("Bounded native block-range table required")
    for name, pairs in rows:
        if (
            not isinstance(name, str)
            or len(name) > 259
            or not isinstance(pairs, tuple)
            or len(pairs) > 5
        ):
            raise ValueError("Native block-range row requires name and up to5pairs")
        if name not in (cpu_type, ""):
            continue
        selected = []
        for first, last in pairs:
            if (
                type(first) is not int
                or type(last) is not int
                or not 0 <= first <= 65536
                or not 0 <= last <= 65536
            ):
                raise ValueError("Bounded native block-range pair required")
            if first == 0:
                break
            selected.append((first, last))
        if not selected:
            raise ValueError("Native range table selected an empty interval vector")
        if selected[-1][1] == 0:
            selected[-1] = (selected[-1][0], len(block_sizes))
        for first, last in selected:
            block_range(first, last)
            if last > len(block_sizes):
                raise ValueError("Native range table references absent blocks")
        return tuple(selected)
    raise ValueError("Native range table has no matching row or sentinel")


def check_id_payloads(
    location: bytes, password: int, *, swap_endian: bool = False
) -> tuple[bytes, ...]:
    """VA45a4c0/45c86c five-frame layout; material is explicitly supplied."""
    if not isinstance(location, bytes) or len(location) != 8:
        raise ValueError("Native eight-byte LocationID required")
    if (
        type(password) is not int
        or not 0 <= password <= 0xFFFFFFFF
        or type(swap_endian) is not bool
    ):
        raise ValueError("Native password DWORD and endian BOOL required")
    key = password.to_bytes(4, "little")
    if swap_endian:
        location = b"".join(
            location[index : index + 2][::-1] for index in range(0, 8, 2)
        )
        key = key[::-1]
    return (
        b"\x00",
        b"\x00",
        bytes(location[index] for index in (7, 6, 3, 2, 1, 0)),
        location[4:6][::-1],
        key,
    )


class CommonCAN:
    """CCanCommonFlashWriter raw frame policy, Cuw18 VA45a9f0..45cddc.

    Addresses include the four-byte CAN identifier and optional extension byte.
    ReadSpecifiedCanMsg selects by these header bytes before returning a frame.
    No original library or transport is loaded here.
    """

    def __init__(
        self,
        io: ExecutableIO,
        request: bytes,
        response: bytes,
        *,
        padding: bool,
        read_timeout_ms: int | None = None,
        send_timeout_ms: int | None = None,
        state: ChannelState | None = None,
    ):
        for address in (request, response):
            if not isinstance(address, bytes) or len(address) not in (4, 5):
                raise ValueError("Native four/five-byte CAN header required")
        if type(padding) is not bool:
            raise ValueError("Explicit native channel padding BOOL required")
        for timeout in (read_timeout_ms, send_timeout_ms):
            if timeout is not None and (
                type(timeout) is not int or not 0 <= timeout <= 0xFFFFFFFF
            ):
                raise ValueError("Native unsigned channel timeout required")
        if state is not None:
            from scripts.cuw_legacy_channel import ChannelState

            if not isinstance(state, ChannelState):
                raise TypeError("Actual mutable native channel state required")
        self.state = state
        self.io, self.request, self.response, self._padding = (
            io,
            request,
            response,
            padding,
        )
        self.received = 0
        self.received_bytes = 0
        self._timeout_ms = read_timeout_ms
        self._send_timeout_ms = send_timeout_ms

    @property
    def padding(self) -> bool:
        return self._padding if self.state is None else self.state.padding

    @padding.setter
    def padding(self, value: bool) -> None:
        if type(value) is not bool:
            raise ValueError("Native channel padding must be BOOL")
        if self.state is None:
            self._padding = value
        else:
            self.state.padding = value

    @property
    def timeout_ms(self) -> int | None:
        return self._timeout_ms if self.state is None else self.state.read_timeout

    @timeout_ms.setter
    def timeout_ms(self, value: int | None) -> None:
        if self.state is None:
            self._timeout_ms = value
        elif type(value) is int and 0 <= value <= 0xFFFFFFFF:
            self.state.read_timeout = value
        else:
            raise ValueError("Native shared receive timeout must be uint32")

    @property
    def send_timeout_ms(self) -> int | None:
        return self._send_timeout_ms if self.state is None else self.state.send_timeout

    @send_timeout_ms.setter
    def send_timeout_ms(self, value: int | None) -> None:
        if self.state is None:
            self._send_timeout_ms = value
        elif type(value) is int and 0 <= value <= 0xFFFFFFFF:
            self.state.send_timeout = value
        else:
            raise ValueError("Native shared send timeout must be uint32")

    @classmethod
    def from_io(
        cls,
        io: ExecutableIO,
        request: bytes,
        response: bytes,
        *,
        state: ChannelState | None = None,
    ) -> CommonCAN:
        """Bind native channel RAM, or read explicitly injected standalone fields."""
        if state is not None:
            from scripts.cuw_legacy_channel import ChannelState

            if not isinstance(state, ChannelState):
                raise TypeError("Actual mutable native channel state required")
        padding = io.call("get_channel_padding") if state is None else state.padding
        read_timeout = io.call("get_timeout") if state is None else state.read_timeout
        send_timeout = (
            io.call("get_send_timeout") if state is None else state.send_timeout
        )
        if (
            type(padding) is not bool
            or type(read_timeout) is not int
            or type(send_timeout) is not int
            or not 0 <= read_timeout <= 0xFFFFFFFF
            or not 0 <= send_timeout <= 0xFFFFFFFF
        ):
            raise ValueError("Native channel state getters require BOOL/uint32 results")
        return cls(
            io,
            request,
            response,
            padding=padding,
            read_timeout_ms=read_timeout,
            send_timeout_ms=send_timeout,
            state=state,
        )

    def write(self, payload: bytes) -> None:
        self._write(payload, self.request[:4])

    def _write(self, payload: bytes, header: bytes) -> None:
        if (
            not isinstance(header, bytes)
            or len(header) not in (4, 5)
            or not isinstance(payload, bytes)
            or not 0 < len(payload) <= 4128 - len(header)
        ):
            raise ValueError("Bounded nonempty native CAN payload required")
        if self.send_timeout_ms is not None and (
            type(self.send_timeout_ms) is not int
            or not 0 <= self.send_timeout_ms <= 0xFFFFFFFF
        ):
            raise ValueError("Native unsigned send timeout required")
        protocol = 6 if self.state is None else self.state.protocol
        if type(protocol) is not int or protocol not in (5, 6):
            raise ValueError("Source-proven raw CAN protocol5 or6 required")
        self.clear_receive()
        flags = (
            (0x80 if len(header) == 5 else 0) | (0x40 if self.padding else 0)
            if protocol == 6
            else 0
        )
        if self.send_timeout_ms is None:
            accepted = executable_j2534_call(
                self.io,
                "write_messages",
                protocol_id=protocol,
                tx_flags=flags,
                data=header + payload,
                count=1,
            )
        else:
            accepted = executable_j2534_call(
                self.io,
                "write_messages",
                protocol_id=protocol,
                tx_flags=flags,
                data=header + payload,
                count=1,
                timeout_ms=self.send_timeout_ms,
            )
        if type(accepted) is not int or accepted != 1:
            raise ValueError("WriteMsgs must accept exactly one native message")
        # VA470bc1 skips transmit indication entirely outside protocol6.
        if protocol == 6:
            self.indication(header[:4])

    def write_many(self, payloads: tuple[bytes, ...]) -> None:
        if (
            not isinstance(payloads, tuple)
            or not 1 <= len(payloads) <= 5
            or any(
                not isinstance(payload, bytes) or not 0 < len(payload) <= 4124
                for payload in payloads
            )
        ):
            raise ValueError("Bounded native CAN message batch required")
        self.write_frames(tuple(self.request[:4] + payload for payload in payloads))

    def write_frames(self, messages: tuple[bytes, ...]) -> None:
        """470b8c: one raw batch, then only the first frame's TX indication."""
        if (
            not isinstance(messages, tuple)
            or not 1 <= len(messages) <= 5
            or any(
                not isinstance(frame, bytes) or not 4 <= len(frame) <= 4128
                for frame in messages
            )
        ):
            raise ValueError("Bounded complete native CAN frame batch required")
        if self.send_timeout_ms is not None and (
            type(self.send_timeout_ms) is not int
            or not 0 <= self.send_timeout_ms <= 0xFFFFFFFF
        ):
            raise ValueError("Native unsigned send timeout required")
        protocol = 6 if self.state is None else self.state.protocol
        if type(protocol) is not int or protocol not in (5, 6):
            raise ValueError("Source-proven raw CAN protocol5 or6 required")
        self.clear_receive()
        if self.send_timeout_ms is None:
            accepted = executable_j2534_call(
                self.io,
                "write_messages",
                protocol_id=protocol,
                tx_flags=0x40 if protocol == 6 and self.padding else 0,
                messages=messages,
                count=len(messages),
            )
        else:
            accepted = executable_j2534_call(
                self.io,
                "write_messages",
                protocol_id=protocol,
                tx_flags=0x40 if protocol == 6 and self.padding else 0,
                messages=messages,
                count=len(messages),
                timeout_ms=self.send_timeout_ms,
            )
        if type(accepted) is not int or accepted != len(messages):
            raise ValueError("WriteMsgs did not accept the entire native batch")
        if protocol == 6:
            self.indication(messages[0][:4])

    def clear_receive(self) -> None:
        """VA46f028: CLEAR_RX_BUFFER occurs before every raw WriteMsgs."""
        if (
            executable_j2534_call(self.io, "ioctl", ioctl_id=8, input=None, output=None)
            is not None
        ):
            raise ValueError("Native clear-RX ioctl primitive must return None")

    def set_timeout(self, milliseconds: int, *, cleanup: bool = False) -> None:
        if type(milliseconds) is not int or not 0 <= milliseconds <= 0xFFFFFFFF:
            raise ValueError("Native unsigned receive timeout required")
        if type(cleanup) is not bool:
            raise ValueError("Explicit host cleanup BOOL required")
        self.timeout_ms = milliseconds
        if (
            self.io.call("set_timeout", milliseconds=milliseconds, cleanup=cleanup)
            is not None
        ):
            raise ValueError("Native receive-timeout field primitive must return None")

    def set_send_timeout(self, milliseconds: int, *, cleanup: bool = False) -> None:
        if type(milliseconds) is not int or not 0 <= milliseconds <= 0xFFFFFFFF:
            raise ValueError("Native unsigned send timeout required")
        if type(cleanup) is not bool:
            raise ValueError("Explicit host cleanup BOOL required")
        self.send_timeout_ms = milliseconds
        if (
            self.io.call("set_send_timeout", milliseconds=milliseconds, cleanup=cleanup)
            is not None
        ):
            raise ValueError("Native send-timeout field primitive must return None")

    def _read_messages(self, count: int) -> tuple[NativeMessage, ...]:
        if type(count) is not int or not 1 <= count <= 5:
            raise ValueError("Bounded native CAN receive count required")
        if self.timeout_ms is not None and (
            type(self.timeout_ms) is not int or not 0 <= self.timeout_ms <= 0xFFFFFFFF
        ):
            raise ValueError("Native unsigned channel receive timeout required")
        result = (
            executable_j2534_call(self.io, "read_messages", protocol_id=6, count=count)
            if self.timeout_ms is None
            else executable_j2534_call(
                self.io,
                "read_messages",
                protocol_id=6,
                count=count,
                timeout_ms=self.timeout_ms,
            )
        )
        frames = legacy_messages(result)
        if len(frames) > count:
            raise ValueError("ReadMsgs exceeded the requested native frame count")
        for message in frames:
            if message.protocol_id != 6 or not 4 <= len(message.data) <= 4128:
                raise ValueError("Bounded full native CAN frame required")
            self.received += 1
            self.received_bytes += len(message.data)
            if self.received > 65536 or self.received_bytes > 16 * 1024 * 1024:
                raise ValueError("Host CAN receive budget exceeded")
        return frames

    def _read_message(self) -> NativeMessage:
        frames = self._read_messages(1)
        if len(frames) != 1:
            raise ValueError("ReadMsgs must return one full native frame")
        return frames[0]

    def read_selected(self, headers: tuple[bytes, ...]) -> tuple[bytes, ...]:
        """46f648: collect one class3 frame per full header, in arrival order."""
        if (
            self.state is None
            or self.state.protocol != 6
            or not isinstance(headers, tuple)
            or not 1 <= len(headers) <= 5
            or any(
                not isinstance(header, bytes) or len(header) not in (4, 5)
                for header in headers
            )
        ):
            raise ValueError("Bound protocol6 and bounded full CAN headers required")
        pending = list(headers)
        output: list[bytes] = []
        while pending:
            for message in self._read_messages(len(pending)):
                for index, header in enumerate(pending):
                    if (
                        message.data.startswith(header)
                        and j2534_indication(message.rx_status, self.padding) == 3
                    ):
                        output.append(message.data)
                        del pending[index]
                        break
        return tuple(output)

    def indication(self, header: bytes, *, padding: bool | None = None) -> int:
        """VA470cd8: await matching header with indication other than4."""
        if not isinstance(header, bytes) or len(header) not in (4, 5):
            raise ValueError("Native indication header required")
        if padding is None:
            padding = self.padding
        if type(padding) is not bool:
            raise ValueError("Native channel padding BOOL required")
        while True:
            message = self._read_message()
            if message.data.startswith(header):
                result = j2534_indication(message.rx_status, padding)
                if result != 4:
                    return result

    def read(self, *, mode: int = 0, padding: bool | None = None) -> bytes:
        if type(mode) is not int or mode not in (0, 1, 2):
            raise ValueError("Native ReadSpecifiedCanMsg mode0/1/2 required")
        if padding is None:
            padding = self.padding
        if type(padding) is not bool or padding != self.padding:
            raise ValueError("Read padding must agree with native channel state")
        if mode == 1 and self.indication(self.response) != 1:
            raise ExecutableJ2534Error(1, 999)
        while True:
            message = self._read_message()
            if message.data.startswith(self.response) and (
                mode != 2 or j2534_indication(message.rx_status, bool(padding)) == 3
            ):
                return message.data

    def wait(self, milliseconds: int) -> None:
        if type(milliseconds) is not int or not 0 <= milliseconds <= 0xFFFFFFFF:
            raise ValueError("Native unsigned wait required")
        if self.io.call("wait", milliseconds=milliseconds) is not None:
            raise ValueError("Native wait primitive must return None")

    def _progress(self, callback: Callable[[int], None], length: int) -> None:
        try:
            callback(length)
        except (Exception, KeyboardInterrupt):
            self.io.check()
            raise
        self.io.check()

    def ack(self) -> bool:
        """VA45ae98: only native driver errors9/16 become false."""
        try:
            while True:
                frame = self.read()
                if len(frame) == 5 and frame[4] == 0x3C:
                    return True
        except (NativeTransportError, VendorTransportError) as error:
            if error.code in (9, 16):
                return False
            raise

    def command(self, payload: bytes, *, error_code: int) -> None:
        self.write(payload)
        if not self.ack():
            raise ExecutableCANError(error_code)

    def _status_once(self) -> int:
        """VA45a9f0: raw50, ACK, status frame, ACK."""
        self.command(b"\x50", error_code=4)
        frame = self.read()
        if len(frame) < 5:
            raise ValueError("Status frame lacks native status byte")
        status = frame[4]
        if not self.ack():
            raise ExecutableCANError(4)
        return status

    def status(self, retry: bool = True) -> int:
        """VA45abd0: three retries only for native CPassThru errors."""
        if type(retry) is not bool:
            raise ValueError("Native status retry BOOL required")
        for attempt in range(4 if retry else 1):
            try:
                return self._status_once()
            except ExecutableCANError:
                if attempt == (3 if retry else 0):
                    raise
        raise AssertionError("Unreachable native status loop")

    def poll(
        self,
        *,
        wait_ms: int,
        busy: int | None = None,
        error_code: int,
        retry: bool = True,
    ) -> int:
        while True:
            self.wait(wait_ms)
            status = self.status(retry=retry)
            if status == 0:
                return status
            if (busy is None and status & 0xF == 0) or status == busy:
                continue
            raise ExecutableCANError(error_code)

    @_phase(10)
    def memory(self, wide: bool = False) -> CANMemory:
        """VA45b41c: opcode76, ACK, 9/11 payload bytes, ACK."""
        if type(wide) is not bool:
            raise ValueError("Native memory width BOOL required")
        self.command(b"\x76", error_code=10)
        frame = self.read(mode=1)
        expected = 15 if wide else 13
        if len(frame) != expected:
            raise ExecutableCANError(10)
        value = frame[4:-1]
        width = 4 if wide else 3
        result = CANMemory(
            int.from_bytes(value[:width], "big"),
            int.from_bytes(value[width : width * 2], "big"),
            value[width * 2],
            value[width * 2 + 1],
        )
        if not self.ack():
            raise ExecutableCANError(10)
        return result

    def finish(
        self, *, acknowledge: bool = True, request_header: bytes | None = None
    ) -> None:
        """VA45acac/45ad4c preserve optional extended address header."""
        if type(acknowledge) is not bool:
            raise ValueError("Native finish ACK BOOL required")
        try:
            self._write(
                b"\x80", self.request if request_header is None else request_header
            )
            if acknowledge and not self.ack():
                raise ExecutableCANError(35)
        except ExecutableJ2534Error as error:
            if acknowledge:
                error.native_code = 35
            raise

    def diagnostic_mask(self) -> None:
        """VA45a42c: three literal a027 frames with100ms after each."""
        for _ in range(3):
            self.write(b"\xa0\x27")
            self.wait(100)

    @_phase(7)
    def check_id(
        self,
        location: bytes,
        password: int,
        *,
        swap_endian: bool = False,
        first_timeout_ms: int = 0,
        interframe_ms: int | None = None,
    ) -> bytes:
        payloads = check_id_payloads(location, password, swap_endian=swap_endian)
        if type(first_timeout_ms) is not int or not 0 <= first_timeout_ms <= 0xFFFFFFFF:
            raise ValueError("Native unsigned first-response timeout required")
        if interframe_ms is None:
            self.write_many(payloads)
        else:
            if type(interframe_ms) is not int or not 0 <= interframe_ms <= 0xFFFFFFFF:
                raise ValueError("Native unsigned interframe wait required")
            for index, payload in enumerate(payloads):
                self.write(payload)
                if index != 4:
                    self.wait(interframe_ms)
        if not self.ack():
            raise ExecutableCANError(7)
        if first_timeout_ms:
            self.set_timeout(first_timeout_ms)
        response = self.read(mode=1)
        self.write(b"\x3c")
        return response

    @_phase(19)
    def change_cpu(self) -> None:
        """VA45b268: opcode65 and native ACK error19."""
        self.command(b"\x65", error_code=19)

    def prepare_reprogramming(self, native_error_code: int) -> None:
        """VA45afa8:05 ACK, optional13/15 zero fill and3000ms retry wait."""
        if (
            type(native_error_code) is not int
            or not 0 <= native_error_code <= 0xFFFFFFFF
        ):
            raise ValueError("Native saved error category DWORD required")
        attempt = 1
        while True:
            self.write(b"\x05")
            if self.ack():
                return
            if native_error_code not in (13, 15):
                raise ExecutableCANError(20)
            self.write(bytes(1024 if native_error_code == 13 else 256))
            received = False
            try:
                while True:
                    frame = self.read()
                    if len(frame) == 5 and frame[4] in (0x3C, 0xFF):
                        received = True
                        break
            except (NativeTransportError, VendorTransportError):
                # Native catch is around the response read only, not the write
                # or host boundary. The attempt==3 test is literal native code.
                pass
            if not received and attempt == 3:
                raise ExecutableCANError(20)
            attempt += 1
            self.wait(3000)

    @staticmethod
    def _ordinary_block_command(opcode: int, index: int, wide: bool) -> bytes:
        if type(wide) is not bool or type(index) is not int:
            raise ValueError("Native block index and width required")
        if not 1 <= index <= (65536 if wide else 256):
            raise ValueError("Native block index exceeds command width")
        return bytes((opcode + int(wide),)) + (
            block_range(index, index) if wide else bytes((index - 1,))
        )

    @_phase(11)
    def ordinary_check_block(self, index: int, *, wide: bool) -> bool:
        """VA4658b4:35/index or36/repeatedBE16index, exact busy10."""
        self.command(self._ordinary_block_command(0x35, index, wide), error_code=11)
        while True:
            self.wait(10)
            status = self.status()
            if status != 0x10:
                return status == 0

    @_phase(12)
    def ordinary_erase(self, index: int, *, wide: bool) -> None:
        """VA465a7c:25/26; only80 is the native erase busy status."""
        self.command(self._ordinary_block_command(0x25, index, wide), error_code=12)
        self.poll(wait_ms=10, busy=0x80, error_code=12)

    @_phase(14)
    def ordinary_inverify(self, index: int, *, wide: bool) -> None:
        """VA46623c:47/48; only40 continues polling."""
        self.command(self._ordinary_block_command(0x47, index, wide), error_code=14)
        self.poll(wait_ms=10, busy=0x40, error_code=14)

    def _verify_status(self, *, busy: int | None, final: bool) -> None:
        status = 0
        while True:
            self.wait(5)
            try:
                status = self.status(retry=final)
            except ExecutableCANError:
                if final:
                    raise
                # Native EH retains the prior status, including a previous busy.
                break
            if status == 0 or not (
                (busy is None and status & 0xF == 0) or status == busy
            ):
                break
        if status:
            raise ExecutableCANError(15)

    @_phase(15, pass_thru=True)
    def ordinary_verify(
        self,
        index: int,
        data: bytes,
        *,
        wide: bool,
        progress: Callable[[int], None] | None = None,
    ) -> None:
        """VA466430:15/16, fixed256-byte fragments and exact busy20.

        The ordinary helper differs from virtual45bbd4's low-nibble busy test.
        CPU geometry and the image slice must already have been validated.
        """
        command = self._ordinary_block_command(0x15, index, wide)
        if (
            not isinstance(data, bytes)
            or not 0 < len(data) <= 64 * 1024 * 1024
            or len(data) % 256
        ):
            raise ValueError("Bounded native verify data in256-byte units required")
        if progress is not None and not callable(progress):
            raise TypeError("Callable native progress notification required")
        self.command(command, error_code=15)
        for offset in range(0, len(data), 256):
            self.write(data[offset : offset + 256])
            if progress is not None:
                self._progress(progress, 256)
            if not self.ack():
                raise ExecutableCANError(15)
            self._verify_status(busy=0x20, final=offset + 256 == len(data))

    @_phase(11)
    def check_block(self, first: int, last: int) -> bool:
        self.command(b"\x36" + block_range(first, last), error_code=11)
        while True:
            self.wait(10)
            status = self.status()
            if status != 0x10:
                return status == 0

    @_phase(12)
    def erase(self, first: int, last: int) -> None:
        self.command(b"\x26" + block_range(first, last), error_code=12)
        self.poll(wait_ms=10, error_code=12)

    @_phase(14)
    def inverify(self, first: int, last: int) -> None:
        self.command(b"\x48" + block_range(first, last), error_code=14)
        self.poll(wait_ms=10, busy=0x40, error_code=14)

    @_phase(15, pass_thru=True)
    def verify(
        self,
        first: int,
        last: int,
        data: bytes,
        *,
        progress: Callable[[int], None] | None = None,
    ) -> None:
        """VA45bbd4: fixed256-byte data frames; final status enables retries."""
        if (
            not isinstance(data, bytes)
            or not 0 < len(data) <= 64 * 1024 * 1024
            or len(data) % 256
        ):
            raise ValueError("Bounded native verify data in256-byte units required")
        if progress is not None and not callable(progress):
            raise TypeError("Callable native progress notification required")
        interval = block_range(first, last)
        self.command(b"\x16" + interval, error_code=15)
        for offset in range(0, len(data), 256):
            self.write(data[offset : offset + 256])
            if progress is not None:
                self._progress(progress, 256)
            if not self.ack():
                raise ExecutableCANError(15)
            self._verify_status(busy=None, final=offset + 256 == len(data))

    @_phase(13, pass_thru=True)
    def ordinary_write_block(
        self,
        address: int,
        data: bytes,
        *,
        progress: Callable[[int], None] | None = None,
    ) -> None:
        """VA465c74: always24-bit address and exact40 busy, even extended blocks."""
        self._write_block(
            address, data, wide=False, initial_wait_ms=0, progress=progress, busy=0x40
        )

    @_phase(13, pass_thru=True)
    def write_block(
        self,
        address: int,
        data: bytes,
        *,
        wide: bool = False,
        initial_wait_ms: int = 0,
        progress: Callable[[int], None] | None = None,
    ) -> None:
        """VA45c0c0: range write with low-nibble busy statuses."""
        self._write_block(
            address,
            data,
            wide=wide,
            initial_wait_ms=initial_wait_ms,
            progress=progress,
            busy=None,
        )

    def _write_block(
        self,
        address: int,
        data: bytes,
        *,
        wide: bool = False,
        initial_wait_ms: int = 0,
        progress: Callable[[int], None] | None = None,
        busy: int | None,
    ) -> None:
        """VA45c0c0/45c700:41→address+ff→1024data, then45→1024data.

        The caller selects the native block interval and slices the imported
        image. No synthetic padding or geometry is inferred here.
        """
        if (
            type(wide) is not bool
            or type(address) is not int
            or not 0 <= address < 1 << (32 if wide else 24)
        ):
            raise ValueError("Native three/four-byte write address required")
        if (
            not isinstance(data, bytes)
            or not 0 < len(data) <= 64 * 1024 * 1024
            or len(data) % 1024
        ):
            raise ValueError("Bounded native write data in1024-byte units required")
        if type(initial_wait_ms) is not int or not 0 <= initial_wait_ms <= 0xFFFFFFFF:
            raise ValueError("Native unsigned initial data wait required")
        if progress is not None and not callable(progress):
            raise TypeError("Callable native progress notification required")
        self.command(b"\x41", error_code=13)
        self.write(address.to_bytes(4 if wide else 3, "big") + b"\xff")
        if initial_wait_ms:
            self.wait(initial_wait_ms)
        for offset in range(0, len(data), 1024):
            if offset:
                self.command(b"\x45", error_code=13)
            self.write(data[offset : offset + 1024])
            if progress is not None:
                self._progress(progress, 1024)
            if not self.ack():
                raise ExecutableCANError(13)
            self.poll(wait_ms=5, busy=busy, error_code=13)

    @_phase(29, pass_thru=True)
    def zv_write(
        self, image: bytes, *, progress: Callable[[int, int, int], None] | None = None
    ) -> None:
        """VA587f5c:42/record-count,1024-byte fragments, exactbusy40."""
        self._zv_transfer(image, verify=False, progress=progress)

    @_phase(30, pass_thru=True)
    def zv_verify(
        self, image: bytes, *, progress: Callable[[int, int, int], None] | None = None
    ) -> None:
        """VA58827c:17/record-count,1024-byte fragments, exactbusy20."""
        self._zv_transfer(image, verify=True, progress=progress)

    def _zv_transfer(
        self,
        image: bytes,
        *,
        verify: bool,
        progress: Callable[[int, int, int], None] | None,
    ) -> None:
        records = parse_zv_records(image)
        if progress is not None and not callable(progress):
            raise TypeError("Callable native ZV progress notification required")
        code = 30 if verify else 29
        command = (
            bytes((0x17 if verify else 0x42, 0, 0))
            + (len(records) - 1).to_bytes(2, "big")
            + b"\xff"
        )
        self.command(command, error_code=code)
        for record_offset, record_size in records:
            for offset in range(0, record_size, 1024):
                part = image[
                    record_offset + offset : record_offset
                    + min(record_size, offset + 1024)
                ]
                self.write(part)
                if progress is not None:
                    completed = record_offset + offset + len(part)
                    self._progress(
                        lambda length, completed=completed: progress(
                            length, completed, 50 if verify else 0
                        ),
                        len(part),
                    )
                if not self.ack():
                    raise ExecutableCANError(code)
                self.poll(
                    wait_ms=5,
                    busy=0x20 if verify else 0x40,
                    error_code=code,
                    retry=True,
                )

    def is_finished(self) -> None:
        """VA45cddc:3e with native header/flags, then any matching mode0frame."""
        self._write(b"\x3e", self.request)
        self.read()

    @_phase(10)
    def memory_ordinary(self) -> tuple[CANMemory, bool]:
        """CCanFlashWriter VA465590:75, native ACK-only fallback76."""
        self.write(b"\x75")
        extended = not self.ack()
        if extended:
            self.command(b"\x76", error_code=10)
        frame = self.read(mode=1)
        if len(frame) != (13 if extended else 12):
            raise ExecutableCANError(10)
        value = frame[4:12]
        result = CANMemory(
            int.from_bytes(value[:3], "big"),
            int.from_bytes(value[3:6], "big"),
            value[6],
            value[7],
        )
        if not self.ack():
            raise ExecutableCANError(10)
        return result, extended

    def m16c_status(self) -> tuple[int, int] | None:
        """VA466d08: rawA4, status/detail bytes; only read9/16→false."""
        self.write(b"\xa4")
        try:
            frame = self.read()
        except (NativeTransportError, VendorTransportError) as error:
            if error.code in (9, 16):
                return None
            raise
        if len(frame) < 6:
            raise ValueError("Native M16C status requires two response bytes")
        return frame[4], frame[5]

    def m16c_query(self) -> int | None:
        """4676f8/441e1c: A8 write outside the read-only CJ9/16 catch."""
        self.write(b"\xa8")
        try:
            frame = self.read()
        except ExecutableJ2534Error as error:
            if error.driver_status in (9, 16):
                return None
            raise
        if len(frame) < 5:
            raise ValueError("Native M16C A8 response requires its first data byte")
        return frame[4]

    def m16c_password(self, cpu_type: str, password: int) -> None:
        """VA466900: two-message password batch and detail-bit check."""
        if (
            not isinstance(cpu_type, str)
            or len(cpu_type) > 259
            or type(password) is not int
            or not 0 <= password <= 0xFFFFFFFF
        ):
            raise ValueError("Native CPU string and supplied password DWORD required")
        prefix = {
            "54": bytes.fromhex("a0f0ff0b07"),
            "90": bytes.fromhex("a00200df07"),
        }.get(cpu_type, bytes.fromhex("a0dfff0f07"))
        suffix = bytes.fromhex("726638") if cpu_type in ("54", "90") else bytes(3)
        self.write_many((prefix, password.to_bytes(4, "big") + suffix))
        status = self.m16c_status()
        if status is None or status[1] & 0xC != 0xC:
            raise ExecutableCANError(7)

    def m16c_erase(self, end_address: int) -> None:
        """VA466eb8: clearA6, eraseA1(mid,high,d0), pollA4 bit80."""
        if type(end_address) is not int or not 0 <= end_address <= 0xFFFFFF:
            raise ValueError("Native24-bit erase end address required")
        self.write(b"\xa6")
        self.write(bytes((0xA1, end_address >> 8 & 255, end_address >> 16 & 255, 0xD0)))
        while True:
            self.wait(5)
            status = self.m16c_status()
            if status is None:
                raise ExecutableCANError(12)
            if status[0] & 0x80:
                if status[0] & 0x30:
                    raise ExecutableCANError(12)
                return

    def m16c_page(
        self,
        address: int,
        data: bytes,
        *,
        verify: bool = False,
        progress: Callable[[int], None] | None = None,
    ) -> None:
        """VA4670bc/4673e4: atomic command+256data batch; A4/A8 status."""
        if (
            type(address) is not int
            or not 0 <= address <= 0xFFFFFF
            or address & 255
            or not isinstance(data, bytes)
            or len(data) != 256
            or type(verify) is not bool
        ):
            raise ValueError("Native aligned24-bit page and256data bytes required")
        if progress is not None and not callable(progress):
            raise TypeError("Callable native progress notification required")
        if not verify:
            self.write(b"\xa6")
        self.write_many(
            (
                bytes(
                    (0xA3 if verify else 0xA2, address >> 8 & 255, address >> 16 & 255)
                ),
                data,
            )
        )
        if progress is not None:
            self._progress(progress, 256)
        while True:
            self.wait(5)
            if verify:
                self.write(b"\xa8")
                try:
                    frame = self.read()
                except (NativeTransportError, VendorTransportError) as error:
                    if error.code in (9, 16):
                        raise ExecutableCANError(15) from error
                    raise
                if len(frame) < 5:
                    raise ValueError("Native M16C verification status byte missing")
                if frame[4] == 255:
                    continue
                if frame[4] != 0:
                    raise ExecutableCANError(15)
            else:
                status = self.m16c_status()
                if status is None:
                    raise ExecutableCANError(13)
                if status[0] & 0x80 == 0:
                    continue
                if status[0] & 0x30 or status[1] & 2:
                    raise ExecutableCANError(13)
            return


def collate_seed_key(
    channel: CommonCAN, key_provider: Callable[[bytes], bytes]
) -> None:
    """VA463e80:271/272 with four-byte seed and explicitly supplied key.

    Native embedded authorization material is never extracted or reported.
    The caller binds its authorized key provider to the selected imported CPU.
    """
    from scripts.cuw_legacy_body import diagnostic

    if not isinstance(channel, CommonCAN) or not callable(key_provider):
        raise TypeError("Native CAN channel and explicit key provider required")
    try:
        response = diagnostic(
            channel, b"\x27\x01", b"\x67\x01", 6, 16, padding=channel.padding
        )
        try:
            key = key_provider(response[2:6])
        except (Exception, KeyboardInterrupt):
            channel.io.check()
            raise
        channel.io.check()
        if not isinstance(key, bytes) or len(key) != 4:
            raise ValueError("Authorized key provider must return exactly four bytes")
    except ExecutableJ2534Error as error:
        if error.driver_status in (9, 16):
            raise ExecutableCANError(22) from error
        raise
    except ExecutableCANError as error:
        if (
            getattr(error, "response_size", None) == 7
            and getattr(error, "response", b"")[:2] == b"\x7f\x27"
        ):
            raise ExecutableCANError(23) from error
        raise
    channel.wait(100)
    diagnostic(channel, b"\x27\x02" + key, b"\x67\x02", 2, 17, padding=channel.padding)


def change_reprogramming_mode(channel: CommonCAN, mode: int) -> None:
    """VA4654a8: caller mode byte,50 prefix only, native caller error18."""
    from scripts.cuw_legacy_body import diagnostic

    if (
        not isinstance(channel, CommonCAN)
        or type(mode) is not int
        or not 0 <= mode <= 255
    ):
        raise ValueError("Native channel and reprogramming mode byte required")
    diagnostic(channel, bytes((0x10, mode)), b"\x50", 1, 18, padding=channel.padding)


def ordinary_flash_blocks(
    channel: CommonCAN,
    cpu_type: str,
    memory: CANMemory,
    image: bytes,
    *,
    wide: bool,
    progress: Callable[[int], None] | None = None,
    begin_writing: Callable[[], None] | None = None,
    set_error: Callable[[int], None] | None = None,
    native_failures: list[ExecutableNativeError] | None = None,
) -> None:
    """VA462127..46228f ordinary branch: blank/optional erase/write/inverify/verify.

    This is the block loop only. Parent-controller preparation, CPU selection,
    filters, password state, finishing and recovery remain the caller's work.
    All image/geometry intervals are checked before the first destructive command.
    """
    if not isinstance(channel, CommonCAN):
        raise TypeError("Native CAN channel required")
    if type(wide) is not bool:
        raise ValueError("Native block width BOOL required")
    sizes = calc_block_sizes(cpu_type, memory)
    total = sum(sizes)
    if (
        not isinstance(image, bytes)
        or not 0 < len(image) <= 64 * 1024 * 1024
        or total > len(image)
        or not sizes
        or len(sizes) > (65536 if wide else 256)
        or any(size <= 0 or size % 1024 for size in sizes)
        or memory.address + total > 1 << 24
    ):
        raise ValueError("Native ordinary block geometry exceeds materialized image")
    if progress is not None and not callable(progress):
        raise TypeError("Callable native progress notification required")
    offset = 0
    for index, size in enumerate(sizes, 1):
        channel.io.check()
        try:
            if begin_writing is not None:
                begin_writing()
            if not channel.ordinary_check_block(index, wide=wide):
                channel.ordinary_erase(index, wide=wide)
            part = image[offset : offset + size]
            if set_error is not None:
                set_error(13)
            channel.ordinary_write_block(
                memory.address + offset, part, progress=progress
            )
            if set_error is not None:
                set_error(99)
            channel.ordinary_inverify(index, wide=wide)
            if set_error is not None:
                set_error(15)
            channel.ordinary_verify(index, part, wide=wide, progress=progress)
            if set_error is not None:
                set_error(99)
        except ExecutableNativeError as error:
            if native_failures is None:
                raise
            native_failures.append(error)
        offset += size


def m16c_flash_regions(
    channel: CommonCAN,
    image: bytes,
    regions: tuple[tuple[int, int], ...],
    *,
    progress: Callable[[int], None] | None = None,
    begin_writing: Callable[[], None] | None = None,
    native_failures: list[ExecutableNativeError] | None = None,
) -> None:
    """VA461afe/599224: erase region, interleaved256-byte program and verify.

    Source regions remain ordered, including overlaps. Image data is consumed
    consecutively across regions rather than addressed relative to an SREC base.
    Password exchange and receive-timeout ownership belong to the controller.
    """
    if not isinstance(channel, CommonCAN):
        raise TypeError("Native CAN channel required")
    if (
        not isinstance(image, bytes)
        or not 0 < len(image) <= 64 * 1024 * 1024
        or not isinstance(regions, tuple)
        or not 0 < len(regions) <= 65536
        or any(
            not isinstance(row, tuple)
            or len(row) != 2
            or any(type(value) is not int for value in row)
            or row[0] < 0
            or row[0] % 256
            or row[1] <= 0
            or row[1] % 256
            or row[0] + row[1] > 1 << 24
            for row in regions
        )
        or sum(size for _, size in regions) > len(image)
    ):
        raise ValueError(
            "Bounded imported M16C image and aligned native regions required"
        )
    if progress is not None and not callable(progress):
        raise TypeError("Callable native progress notification required")
    image_offset = 0
    for address, size in regions:
        channel.io.check()
        try:
            if begin_writing is not None:
                begin_writing()
            channel.m16c_erase(address + size - 1)
            for offset in range(0, size, 256):
                part = image[image_offset + offset : image_offset + offset + 256]
                channel.m16c_page(address + offset, part, progress=progress)
                channel.m16c_page(
                    address + offset, part, verify=True, progress=progress
                )
        except ExecutableNativeError as error:
            if native_failures is None:
                raise
            native_failures.append(error)
        image_offset += size
    channel.wait(3000)


def _release_can_filters(
    io: ExecutableIO, filters: list[int], primary: BaseException | None
) -> None:
    """Both native preparation functions release all their acquired filters."""
    from scripts.cuw_legacy_engine import executable_stop_filter

    cleanup_errors: list[BaseException] = []
    for filter_id in filters:
        try:
            executable_stop_filter(io, filter_id)
        except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - attempt every owned cleanup
            cleanup_errors.append(error)
    observed = primary or (cleanup_errors[0] if cleanup_errors else None)
    try:
        io.check()
    except (InterruptedError, TimeoutError) as boundary:
        if observed is not None:
            raise boundary from observed
        raise
    if cleanup_errors:
        if primary is not None:
            for error in cleanup_errors:
                primary.add_note("CAN filter cleanup failed: " + type(error).__name__)
        else:
            first, *others = cleanup_errors
            for error in others:
                first.add_note("CAN filter cleanup failed: " + type(error).__name__)
            raise first


def prepare_can_addresses(
    io: ExecutableIO,
    addresses,
    functional_header: bytes,
    key_provider: Callable[[int, bytes], bytes],
    *,
    mode: int,
    repeat_mode: bool,
    retry_mode: bool,
    state: ChannelState | None = None,
) -> tuple[int, ...]:
    """VA464254 concrete preparation loop after the native address producer.

    Every filter is acquired before security starts. Only CPass22/23 exclude a
    target. No accepted target is permitted solely by the native retry BOOL.
    The caller derives mode/repetition and functional header from native metadata.
    """
    import sys

    from scripts.cuw_legacy_addresses import CAddress
    from scripts.cuw_legacy_engine import executable_start_filter

    if (
        not isinstance(io, ExecutableIO)
        or not isinstance(addresses, tuple)
        or len(addresses) > 4
        or any(not isinstance(address, CAddress) for address in addresses)
        or not isinstance(functional_header, bytes)
        or len(functional_header) != 4
        or not callable(key_provider)
        or type(mode) is not int
        or not 0 <= mode <= 255
        or type(repeat_mode) is not bool
        or type(retry_mode) is not bool
    ):
        raise ValueError("Bounded source-produced CAN preparation inputs required")
    channels = tuple(
        CommonCAN.from_io(io, row.request_header, row.response_header, state=state)
        for row in addresses
    )
    filters: list[int] = []
    accepted: list[int] = []
    try:
        for channel in channels:
            filters.append(
                executable_start_filter(
                    io, channel.request, channel.response, padding=channel.padding
                )
            )
        for index, channel in enumerate(channels):
            try:
                collate_seed_key(
                    channel, lambda seed, index=index: key_provider(index, seed)
                )
                accepted.append(index)
            except ExecutableCANError as error:
                if error.code not in (22, 23):
                    raise
            channel.wait(100)
        if not accepted and not retry_mode:
            raise ExecutableCANError(17)
        if accepted:
            for _ in range(3):
                channels[0]._write(b"\xa0\x27", functional_header)
                channels[0].wait(100)
            for index in accepted:
                change_reprogramming_mode(channels[index], mode)
                if repeat_mode:
                    channels[index].wait(110)
                    change_reprogramming_mode(channels[index], mode)
    finally:
        _release_can_filters(io, filters, sys.exception())
    io.check()
    return tuple(accepted)


def p5_diagnostic(
    channel: CommonCAN,
    request: bytes,
    expected: bytes,
    minimum_response: int,
    error_code: int,
    *,
    wait_ms: int = 0,
) -> bytes:
    """VA45d898 calls with null native cancellation pointer, as used by CP5.

    NRC78 is receive-only, timed in whole local seconds with midnight rollover.
    The fixed native pending deadline is180s and pending receive timeout5530ms.
    NRC21 is not resent. Host cancellation/deadlines never emit timeout cleanup.
    """
    import sys

    if (
        not isinstance(channel, CommonCAN)
        or not isinstance(request, bytes)
        or not 0 < len(request) <= 4095
        or not isinstance(expected, bytes)
        or type(minimum_response) is not int
        or not len(expected) <= minimum_response <= 4095
        or type(error_code) is not int
        or not 0 <= error_code <= 127
        or type(wait_ms) is not int
        or not 0 <= wait_ms <= 0xFFFFFFFF
        or type(channel.timeout_ms) is not int
        or not 0 <= channel.timeout_ms <= 0xFFFFFFFF
    ):
        raise ValueError(
            "Bounded CP5 diagnostic inputs and actual channel timeout required"
        )
    saved_timeout = channel.timeout_ms
    first_pending: int | None = None
    try:
        channel._write(request, channel.request)
        channel.wait(wait_ms)
        while True:
            frame = channel.read(mode=2)
            payload = frame[len(channel.request) :]
            if len(frame) >= 7 and payload[:3] == b"\x7f" + request[:1] + b"\x78":
                if first_pending is None:
                    first_pending = channel.io.read_local_seconds_of_day()
                now = channel.io.read_local_seconds_of_day()
                elapsed = (now - first_pending) % 86400
                if elapsed >= 180:
                    channel._write(b"\x3e", channel.request)
                    raise ExecutableCANResponseError(error_code, payload, len(frame))
                if saved_timeout < 5530:
                    channel.set_timeout(5530)
                continue
            if len(payload) < minimum_response or (
                expected and not payload.startswith(expected)
            ):
                raise ExecutableCANResponseError(error_code, payload, len(frame))
            return payload
    except ExecutableJ2534Error as error:
        error.native_code = error_code
        raise
    finally:
        primary = sys.exception()
        restoration_error: BaseException | None = None
        if channel.timeout_ms != saved_timeout:
            try:
                channel.set_timeout(saved_timeout, cleanup=True)
            except (Exception, KeyboardInterrupt) as cleanup_error:  # noqa: BLE001 - retain primary while checking host boundary
                restoration_error = cleanup_error
        try:
            channel.io.check()
        except (InterruptedError, TimeoutError) as boundary:
            observed = primary or restoration_error
            if observed is not None:
                raise boundary from observed
            raise
        if restoration_error is not None:
            if primary is None:
                raise restoration_error
            primary.add_note(
                "CP5 timeout restoration failed: " + type(restoration_error).__name__
            )


def p5_collate_seed_key(
    channel: CommonCAN, key_provider: Callable[[bytes], bytes]
) -> None:
    """VA598e68: four-byte key,45d898 policy, no CCan's100ms delay or22/23 catch."""
    if not callable(key_provider):
        raise TypeError("Explicit authorized four-byte key provider required")
    response = p5_diagnostic(channel, b"\x27\x01", b"\x67\x01", 6, 16)
    try:
        key = key_provider(response[2:6])
    except (Exception, KeyboardInterrupt):
        channel.io.check()
        raise
    channel.io.check()
    if not isinstance(key, bytes) or len(key) != 4:
        raise ValueError("Authorized key provider must return exactly four bytes")
    p5_diagnostic(channel, b"\x27\x02" + key, b"\x67\x02", 2, 17)


def p5_prepare_routine(channel: CommonCAN) -> None:
    """VA599128:31011003/71011003, native caller code25."""
    p5_diagnostic(channel, b"\x31\x01\x10\x03", b"\x71\x01\x10\x03", 4, 25)


def p5_session_control(channel: CommonCAN) -> None:
    """VA598c88:1002/5002 with four timing bytes, source wrong-SID27 catch."""
    try:
        p5_diagnostic(channel, b"\x10\x02", b"\x50\x02", 6, 41)
    except ExecutableJ2534Error as error:
        if error.driver_status in (9, 16):
            raise ExecutableCANError(55) from error
        raise
    except ExecutableCANResponseError as error:
        # This is literally7f27 in the original even though the requestSID is10.
        if error.response_size == 7 and error.response[:2] == b"\x7f\x27":
            raise ExecutableCANError(56) from error
        raise


def prepare_ccan_imported(
    context, io: ExecutableIO, key_provider: Callable[[int, bytes], bytes]
) -> tuple[int, ...]:
    """Bind original18 CCan preparation to actual imported CPU/address producers.

    This stage helper does not execute the controller's write/recovery tail.
    Its key provider receives the source-produced target index and four seed bytes.
    """
    from scripts.cuw_legacy_addresses import (
        legacy_address_inputs,
        select_legacy_addresses,
    )
    from scripts.cuw_legacy_channel import channel_state
    from scripts.cuw_legacy_engine import ExecutableContext, executable_cpu_type

    if (
        not isinstance(context, ExecutableContext)
        or context.controller != "CCanFlashWriter"
        or not callable(key_provider)
    ):
        raise ValueError(
            "Source-bound original18 CCan context and explicit key provider required"
        )
    context.state.validate()
    kind, config, reprog_mode, factory_state = legacy_address_inputs(context)
    addresses = select_legacy_addresses(
        context, kind, config, reprog_mode=reprog_mode, factory_state=factory_state
    )
    required_index = int(executable_cpu_type(context, 0) in ("17", "54", "90", "18"))
    rows = {row.selected.index: row for row in context.cpus}
    if required_index not in rows:
        raise ValueError("Native functional-header CPU row is not bound")
    location = original_location_id(
        rows[required_index].selected.values.get("locationid", "")
    )
    functional_header = b"\0\0" + location[6:8]
    mode, repeat_mode = ccan_prepare_mode(kind, executable_cpu_type(context))
    return prepare_can_addresses(
        io,
        addresses,
        functional_header,
        key_provider,
        mode=mode,
        repeat_mode=repeat_mode,
        retry_mode=context.state.retry_mode,
        state=channel_state(context),
    )


def flash_shrink_imported(
    context,
    channel: CommonCAN,
    image_cpu_index: int,
    progress_cpu_index: int,
    *,
    extended: bool,
    persist: bool,
    memory: CANMemory | None = None,
    progress: CANProgress | None = None,
    transfer: CANTransferState | None = None,
    begin_writing: bool = False,
) -> None:
    """VA584254 source-selected shrink stage, including range-index padding.

    This helper preserves CPU15/16's descriptor-only alternate check without
    mutating the CPU type. It does not own the caller's filters or finish/retry.
    """
    from scripts.cuw_legacy_engine import (
        ExecutableContext,
        executable_cpu_type,
        set_executable_error_code,
    )
    from scripts.cuw_legacy_sil import SilTables

    if (
        not isinstance(context, ExecutableContext)
        or not isinstance(channel, CommonCAN)
        or type(extended) is not bool
        or type(persist) is not bool
        or type(image_cpu_index) is not int
        or type(progress_cpu_index) is not int
        or not 0 <= progress_cpu_index < len(context.cpu_types)
        or (memory is not None and not isinstance(memory, CANMemory))
        or (progress is not None and not isinstance(progress, CANProgress))
    ):
        raise ValueError("Source-bound original18 shrink-stage inputs required")
    transfer = CANTransferState() if transfer is None else transfer
    if not isinstance(transfer, CANTransferState):
        raise TypeError("Native local transfer BOOL state required")
    transfer.validate()
    native = next(
        (row for row in context.cpus if row.selected.index == image_cpu_index), None
    )
    if native is None or native.image is None:
        raise ValueError("Imported materialized shrink CPU image required")
    image = native.image.data
    cpu_type = executable_cpu_type(context, image_cpu_index)
    verify_type = executable_cpu_type(context, progress_cpu_index)
    tables = SilTables(context)
    descriptors = tables.descriptor_rows()
    if memory is None:
        memory = channel.memory(wide=False)
    if not cpu_matches(cpu_type, memory.firmware_descriptor, extended, descriptors):
        if cpu_type not in ("15", "16"):
            raise ExecutableCANError(10)
        alternate = tables.remap_cpu(cpu_type)
        if alternate is None or not cpu_matches(
            alternate, memory.firmware_descriptor, extended, descriptors
        ):
            raise ExecutableCANError(10)
    sizes = calc_block_sizes(cpu_type, memory)
    ranges = select_block_ranges(cpu_type, sizes, tables.range_rows())
    if not ranges:
        raise ValueError("Native shrink range table is empty")
    if ranges[0][0] != 1:
        sizes = (0,) * (ranges[0][0] - 1) + sizes
    plans = []
    for first, last in ranges:
        if last > len(sizes):
            raise ValueError("Native shrink range exceeds padded block geometry")
        offset = sum(sizes[: first - 1])
        length = sum(sizes[first - 1 : last])
        if (
            not 0 < length <= len(image) - offset
            or length % 1024
            or memory.address + offset + length > 1 << 24
        ):
            raise ValueError("Native shrink range exceeds materialized CPU image")
        plans.append((first, last, offset, length))
    if progress is not None and not 0 <= progress_cpu_index < len(progress.image_sizes):
        raise ValueError("Native progress CPU slot is not bound")
    account = (
        None
        if progress is None
        else lambda length: progress.account(progress_cpu_index, length)
    )
    if begin_writing:
        if context.recovery_store is None:
            raise ValueError("Actual original recovery store required before writing")
        context.recovery_store.begin_writing(channel.io)
    for index, (first, last, offset, length) in enumerate(plans):
        channel.io.check()
        blank = cpu_type != "22" and channel.check_block(first, last)
        if not blank:
            channel.erase(first, last)
        transfer.update(index + 1 == len(plans))
        if context.recovery_store is not None:
            context.recovery_store.set_field(
                channel.io, "WritingEndBlock", transfer.end_block
            )
        else:
            context.state.writing_end_block = transfer.end_block
            if (
                persist
                and channel.io.call(
                    "write_recovery_bool",
                    key="WritingEndBlock",
                    value=transfer.end_block,
                )
                is not None
            ):
                raise ValueError("Native recovery BOOL writer must return None")
        part = image[offset : offset + length]
        set_executable_error_code(context, channel.io, 13, persist=persist)
        channel.write_block(memory.address + offset, part, progress=account)
        set_executable_error_code(context, channel.io, 99, persist=persist)
        if verify_type not in ("19", "73"):
            channel.inverify(first, last)
        set_executable_error_code(context, channel.io, 15, persist=persist)
        channel.verify(first, last, part, progress=account)
        set_executable_error_code(context, channel.io, 99, persist=persist)


def prepare_p5_addresses(
    io: ExecutableIO,
    addresses,
    functional_header: bytes,
    key_provider: Callable[[int, bytes], bytes],
    *,
    retry_mode: bool,
    state: ChannelState | None = None,
) -> tuple[int, ...]:
    """VA597e28: session-select targets, security, functional mask, routines.

    Unlike CCan this source has no100ms per-target seed delay. Routines are
    separated by10ms, and the empty nonretry target set throws41.
    """
    import sys

    from scripts.cuw_legacy_addresses import P5Address
    from scripts.cuw_legacy_engine import executable_start_filter

    if (
        not isinstance(io, ExecutableIO)
        or not isinstance(addresses, tuple)
        or len(addresses) > 4
        or any(not isinstance(row, P5Address) for row in addresses)
        or not isinstance(functional_header, bytes)
        or len(functional_header) != 4
        or not callable(key_provider)
        or type(retry_mode) is not bool
    ):
        raise ValueError(
            "Source-produced seven-byte P5 targets and explicit native state required"
        )
    channels = tuple(
        CommonCAN.from_io(io, row.request_header, row.response_header, state=state)
        for row in addresses
    )
    filters: list[int] = []
    accepted: list[int] = []
    try:
        for channel in channels:
            filters.append(
                executable_start_filter(
                    io, channel.request, channel.response, padding=channel.padding
                )
            )
        for index, channel in enumerate(channels):
            try:
                p5_session_control(channel)
                accepted.append(index)
            except ExecutableCANError as error:
                if error.code not in (55, 56):
                    raise
        if not accepted and not retry_mode:
            raise ExecutableCANError(41)
        for index in accepted:
            p5_collate_seed_key(
                channels[index], lambda seed, index=index: key_provider(index, seed)
            )
        if accepted:
            for _ in range(3):
                channels[0]._write(b"\xa0\x27", functional_header)
                channels[0].wait(100)
        for offset, index in enumerate(accepted):
            p5_prepare_routine(channels[index])
            if offset + 1 != len(accepted):
                channels[index].wait(10)
    finally:
        _release_can_filters(io, filters, sys.exception())
    io.check()
    return tuple(accepted)


def p5_cpu_order(context) -> tuple[int, ...]:
    """Original12 40e90c / original18 41a29c initialize the local index vector."""
    from scripts.cuw_legacy_engine import ExecutableContext

    if (
        not isinstance(context, ExecutableContext)
        or context.controller != "CP5CanFlashWriter"
    ):
        raise TypeError("Imported original P5 controller context required")
    context.state.validate()
    indices = tuple(row.selected.index for row in context.cpus)
    if not 0 < len(indices) <= 4 or indices != tuple(range(len(indices))):
        raise ValueError("Native P5 index vector requires contiguous runtime CPU rows")
    return indices


def prepare_p5_imported(
    context, io: ExecutableIO, key_provider: Callable[[int, bytes], bytes]
) -> tuple[int, ...]:
    """Bind original18 CP5 preparation to its distinct seven-byte address factory."""
    from scripts.cuw_legacy_addresses import AddressConfig, select_p5_addresses
    from scripts.cuw_legacy_channel import channel_state
    from scripts.cuw_legacy_engine import ExecutableContext, executable_cpu_type

    if (
        not isinstance(context, ExecutableContext)
        or context.controller != "CP5CanFlashWriter"
    ):
        raise ValueError("Source-bound original18 CP5 context required")
    context.state.validate()
    kind = context.native.base_metadata["kind_of_ecu"]
    observed = context.observations["observed_cids"]
    if not isinstance(observed, tuple):
        raise TypeError("Actual ordered P5 observed CID tuple required")
    config = AddressConfig(observed)
    addresses = select_p5_addresses(context, kind, config)
    order = p5_cpu_order(context)
    index = int(executable_cpu_type(context, 0) == "90")
    if index >= len(order):
        raise ValueError("Native P5 functional header requires CPU1")
    index = order[index]
    native = next((row for row in context.cpus if row.selected.index == index), None)
    if native is None:
        raise ValueError("Native P5 functional-header CPU row is not bound")
    return prepare_p5_addresses(
        io,
        addresses,
        b"\0\0"
        + original_location_id(native.selected.values.get("locationid", ""))[6:8],
        key_provider,
        retry_mode=context.state.retry_mode,
        state=channel_state(context),
    )


def r32c_block_sizes(context, cpu_type: str) -> tuple[int, ...]:
    """VA583c08/583cd0: authenticated CPU136 table, KiB/count pairs."""
    from scripts.cuw_legacy_engine import ExecutableContext, ExecutableImage

    if not isinstance(context, ExecutableContext):
        raise TypeError("Source-bound original R32C context required")
    image = ExecutableImage(context)
    initializer, name_cell, table = (
        (0x5839B1, 0x5D5158, 0x620078)
        if context.build == 18
        else (0x539419, 0x58543C, 0x5C3C54)
    )
    expected = (
        b"\xa1"
        + name_cell.to_bytes(4, "little")
        + b"\xa3"
        + table.to_bytes(4, "little")
    )
    if image.read(initializer, 10) != expected:
        raise ValueError("Native R32C name initializer differs")
    pointer = int.from_bytes(image.read(name_cell, 4), "little")
    name = bytearray()
    for index in range(129):
        value = image.read(pointer + index, 1)[0]
        if value == 0:
            break
        name.append(value)
    else:
        raise ValueError("Native R32C CPU name exceeds host bound")
    if cpu_type != name.decode("ascii"):
        raise ExecutableCANError(10)
    row = image.read(table, 136)
    count = int.from_bytes(row[4:8], "little")
    if not 0 < count < 65536:
        raise ValueError("Native R32C block count outside WORD iterator bounds")
    sizes: list[int] = []
    for offset in range(8, len(row), 8):
        size = int.from_bytes(row[offset : offset + 4], "little") * 1024
        repetitions = int.from_bytes(row[offset + 4 : offset + 8], "little")
        if (
            not size
            or not repetitions
            or repetitions > count - len(sizes)
            or size * repetitions > 64 * 1024 * 1024 - sum(sizes)
        ):
            raise ValueError("Native R32C geometry table is inconsistent")
        sizes.extend([size] * repetitions)
        if len(sizes) == count:
            return tuple(sizes)
    raise ValueError("Native R32C table omits required blocks")


def flash_r32c_imported(
    context,
    channel: CommonCAN,
    image_cpu_index: int,
    progress_cpu_index: int,
    transfer: CANTransferState,
    *,
    extended: bool,
    persist: bool,
    progress: CANProgress | None = None,
) -> None:
    """VA5839c4: memory76, fixed source table, per-block erase/write/inverify/verify.

    The local end-block BOOL is set before the final erase. This source does not
    persist WritingEndBlock; that differs from the shrink stage584254.
    """
    from scripts.cuw_legacy_engine import (
        ExecutableContext,
        executable_cpu_type,
        set_executable_error_code,
    )
    from scripts.cuw_legacy_sil import SilTables

    if (
        not isinstance(context, ExecutableContext)
        or not isinstance(channel, CommonCAN)
        or not isinstance(transfer, CANTransferState)
        or type(extended) is not bool
        or type(persist) is not bool
        or type(image_cpu_index) is not int
        or type(progress_cpu_index) is not int
    ):
        raise ValueError("Source-bound original18 R32C stage inputs required")
    transfer.validate()
    native = next(
        (row for row in context.cpus if row.selected.index == image_cpu_index), None
    )
    if native is None or native.image is None:
        raise ValueError("Imported materialized R32C CPU image required")
    cpu_type = executable_cpu_type(context, progress_cpu_index)
    sizes = r32c_block_sizes(context, cpu_type)
    data = native.image.data
    if sum(sizes) > len(data) or any(size % 1024 for size in sizes):
        raise ValueError("Native R32C geometry exceeds imported CPU image")
    if progress is not None and (
        not isinstance(progress, CANProgress)
        or not 0 <= progress_cpu_index < len(progress.image_sizes)
    ):
        raise ValueError("Bounded native progress slot required")
    memory = channel.memory(wide=False)
    if not cpu_matches(
        cpu_type,
        memory.firmware_descriptor,
        extended,
        SilTables(context).descriptor_rows(),
    ):
        raise ExecutableCANError(10)
    if memory.address + sum(sizes) > 1 << 24:
        raise ValueError("Native R32C address span exceeds24bits")
    account = (
        None
        if progress is None
        else lambda length: progress.account(progress_cpu_index, length)
    )
    offset = 0
    for index, size in enumerate(sizes, 1):
        if index == len(sizes):
            transfer.update(True)
        channel.erase(index, index)
        part = data[offset : offset + size]
        set_executable_error_code(context, channel.io, 13, persist=persist)
        channel.write_block(memory.address + offset, part, progress=account)
        set_executable_error_code(context, channel.io, 99, persist=persist)
        channel.inverify(index, index)
        set_executable_error_code(context, channel.io, 15, persist=persist)
        channel.verify(index, index, part, progress=account)
        set_executable_error_code(context, channel.io, 99, persist=persist)
        offset += size


def transfer_zv_imported(
    context,
    channel: CommonCAN,
    cpu_index: int,
    *,
    extended: bool,
    progress: CANProgress | None = None,
    begin_writing: bool = False,
) -> None:
    """VA587ad4 transfer component; caller owns429ff4 begin-writing chronology."""
    from scripts.cuw_legacy_engine import ExecutableContext, executable_cpu_type
    from scripts.cuw_legacy_sil import SilTables

    if (
        not isinstance(context, ExecutableContext)
        or not isinstance(channel, CommonCAN)
        or type(cpu_index) is not int
        or type(extended) is not bool
    ):
        raise ValueError("Source-bound original18 ZV transfer inputs required")
    native = next(
        (row for row in context.cpus if row.selected.index == cpu_index), None
    )
    if native is None or native.image is None:
        raise ValueError("Imported materialized ZV CPU image required")
    data = native.image.data
    parse_zv_records(data)
    cpu_type = executable_cpu_type(context, cpu_index)
    tables = SilTables(context)
    memory = channel.memory(wide=False)
    if not cpu_matches(
        cpu_type, memory.firmware_descriptor, extended, tables.descriptor_rows()
    ):
        alternate = tables.remap_cpu(cpu_type) if cpu_type == "87" else None
        if alternate is None or not cpu_matches(
            alternate, memory.firmware_descriptor, extended, tables.descriptor_rows()
        ):
            raise ExecutableCANError(10)
    if progress is not None and (
        not isinstance(progress, CANProgress)
        or not 0 <= cpu_index < len(progress.image_sizes)
        or progress.image_sizes[cpu_index] != len(data)
    ):
        raise ValueError("Actual ZV image-length progress slot required")
    account = (
        None
        if progress is None
        else lambda length, completed, base: progress.account_phase(
            cpu_index, length, completed, base
        )
    )
    if begin_writing and context.native.base_metadata["contact_type"] == "CAN":
        if context.recovery_store is None:
            raise ValueError(
                "Actual original recovery store required before ZV writing"
            )
        context.recovery_store.begin_writing(channel.io)
    channel.zv_write(data, progress=account)
    channel.zv_verify(data, progress=account)


def legacy_diagnostic(
    channel: CommonCAN,
    request: bytes,
    expected: bytes,
    minimum_response: int,
    error_code: int,
    *,
    busy_retries: int,
    pending_reads: int,
) -> bytes:
    """45d458 native count-based NRC21/78 policy, null native cancel pointer."""
    if (
        not isinstance(channel, CommonCAN)
        or not isinstance(request, bytes)
        or not request
        or len(request) > 4095
        or not isinstance(expected, bytes)
        or not len(expected) <= minimum_response <= 4095
        or type(error_code) is not int
        or not 0 <= error_code <= 127
        or any(
            type(value) is not int or not 0 <= value <= 0xFFFF
            for value in (busy_retries, pending_reads)
        )
    ):
        raise ValueError("Bounded original diagnostic inputs required")
    saved_timeout = channel.timeout_ms
    if type(saved_timeout) is not int or not 0 <= saved_timeout <= 0xFFFFFFFF:
        raise ValueError("Actual native read timeout required")
    retries = 0
    try:
        while True:
            channel._write(request, channel.request)
            channel.wait(0)
            pending = 0
            while True:
                frame = channel.read(mode=2)
                payload = frame[len(channel.request) :]
                if len(frame) >= 7 and payload[:3] == b"\x7f" + request[:1] + b"\x78":
                    retries = 0
                    pending += 1
                    if pending > pending_reads:
                        channel._write(b"\x3e", channel.request)
                        raise ExecutableCANResponseError(
                            error_code, payload, len(frame)
                        )
                    if saved_timeout < 5000:
                        channel.set_timeout(5000)
                    continue
                break
            channel.set_timeout(saved_timeout)
            if len(frame) >= 7 and payload[:3] == b"\x7f" + request[:1] + b"\x21":
                retries += 1
                if retries <= busy_retries:
                    continue
                raise ExecutableCANResponseError(error_code, payload, len(frame))
            if len(payload) < minimum_response or (
                expected and not payload.startswith(expected)
            ):
                raise ExecutableCANResponseError(error_code, payload, len(frame))
            return payload
    except ExecutableJ2534Error as error:
        error.native_code = error_code
        raise
    finally:
        import sys

        primary = sys.exception()
        try:
            if channel.timeout_ms != saved_timeout:
                channel.set_timeout(saved_timeout, cleanup=True)
        except Exception as cleanup_error:
            if primary is None:
                raise
            primary.add_note(
                "Legacy diagnostic timeout restoration failed: "
                + type(cleanup_error).__name__
            )
        channel.io.check()


def cancel_automatic_ig_off(channel: CommonCAN) -> None:
    """56646c diagnostics, including the reachable1070 fallback omitted by Ghidra."""
    mode = 0
    try:
        p5_diagnostic(channel, b"\x10\x03", b"\x50\x03", 6, 88)
        mode = 1
    except ExecutableJ2534Error as error:
        if error.driver_status not in (9, 16):
            raise
    except ExecutableCANResponseError as error:
        if error.response_size != 8 or error.response != b"\x7f\x10\x12":
            raise
        mode = 2
    if mode == 1:
        response = p5_diagnostic(channel, b"\x22\x20\x01", b"\x62\x20\x01", 5, 87)
        if response[3] & 0x40:
            p5_diagnostic(
                channel,
                b"\x2e\x20\x01" + bytes((response[3], response[4] | 0x40)),
                b"\x6e\x20\x01",
                3,
                78,
            )
    elif mode == 2:
        try:
            legacy_diagnostic(
                channel,
                b"\x10\x70",
                b"\x50",
                1,
                78,
                busy_retries=255,
                pending_reads=149,
            )
        except ExecutableCANResponseError as error:
            if error.response_size != 8 or error.response not in (
                b"\x7f\x10\x11",
                b"\x7f\x10\x12",
                b"\x7f\x10\x13",
            ):
                raise


def automatic_ig_off_cancel(context, io: ExecutableIO) -> None:
    """Original18 helper owns its fixed extended-address flow-control filter."""
    from scripts.cuw_legacy_channel import channel_state
    from scripts.cuw_legacy_engine import (
        executable_start_filter,
        executable_stop_filter,
    )

    if context.build != 18:
        raise ValueError("Automatic IG off cancellation is original18-only")
    state = channel_state(context)
    channel = CommonCAN.from_io(
        io, bytes.fromhex("00000750e9"), bytes.fromhex("00000758e9"), state=state
    )
    filter_id = executable_start_filter(
        io, channel.request, channel.response, padding=state.padding
    )
    try:
        cancel_automatic_ig_off(channel)
    finally:
        try:
            executable_stop_filter(io, filter_id)
        except ExecutableNativeError:
            pass


class OriginalSeedKey:
    """Original executable four-round codec and source-owned material producer."""

    def __init__(self, context):
        from scripts.cuw_legacy_engine import ExecutableImage

        source = ExecutableImage(context)
        start, table, constructor = {
            12: (0x451400, 0x59E85C, 0x40E310),
            18: (0x47F0C4, 0x5F6EE8, 0x419BDC),
        }[context.build]
        materials = []
        for index in range(4):
            address = start + index * 21
            code = source.read(address, 15)
            if (
                code[0] != 0x68
                or code[5] != 0x68
                or int.from_bytes(code[6:10], "little") != table + index * 0x10C
                or code[10] != 0xE8
                or address + 15 + int.from_bytes(code[11:15], "little", signed=True)
                != constructor
            ):
                raise ValueError("Original seed-key material producer mismatch")
            value = int.from_bytes(code[1:5], "little")
            if value > 0xFFFF:
                raise ValueError("Native conversion material must be WORD")
            # Native byte-array WORD constructor stores most-significant byte first.
            materials.append(value.to_bytes(2, "big"))
        self._materials = tuple(materials)
        self._cpu_count = len(context.cpus)

    def __call__(self, runtime_cpu_index: int, seed: bytes) -> bytes:
        if (
            type(runtime_cpu_index) is not int
            or not 0 <= runtime_cpu_index < self._cpu_count
        ):
            raise ValueError("Actual runtime CPU index required")
        return seed_key_four_round(seed, self._materials)


class CanController:
    """Original12/18 CCan and P5 Execute over imported RAM and raw primitives."""

    def __init__(self, context, io):
        from scripts.cuw_legacy_channel import channel_state
        from scripts.cuw_legacy_engine import ExecutableContext, ExecutableImage
        from scripts.cuw_legacy_recovery import LegacyRecoveryStore
        from scripts.cuw_legacy_sil import SilTables

        if (
            not isinstance(context, ExecutableContext)
            or context.controller not in ("CCanFlashWriter", "CP5CanFlashWriter")
            or not isinstance(io, ExecutableIO)
            or not isinstance(context.recovery_store, LegacyRecoveryStore)
            or context.recovery_store.build != context.build
            or context.recovery_store.container_sha256 != context.container_sha256
            or context.recovery_store.state is not context.state
        ):
            raise ValueError(
                "Imported CAN controller and source-associated recovery RAM required"
            )
        self.context, self.io = context, io
        self.key_provider = OriginalSeedKey(context)
        self.source = ExecutableImage(context)
        self.state = channel_state(context)
        if self.state.protocol != 6:
            raise ValueError(
                "Native CAN Execute requires its connected protocol6 channel"
            )
        self.p5 = context.controller == "CP5CanFlashWriter"
        indices = tuple(row.selected.index for row in context.cpus)
        if indices != tuple(range(len(indices))) or not 0 < len(indices) <= 4:
            raise ValueError("CAN Execute requires contiguous actual runtime CPU rows")
        if any(row.image is None for row in context.cpus):
            raise ValueError("Materialized native CPU images required")
        self.rows = context.cpus
        self.store = context.recovery_store
        self.images: list[bytes] = []
        self.locations: list[bytes] = []
        for row in self.rows:
            assert row.image is not None
            self.images.append(row.image.data)
            self.locations.append(
                original_location_id(row.selected.values.get("locationid", ""))
            )
        self.tables = SilTables(context)
        self.progress = CANProgress(io, tuple(map(len, self.images)))
        self.value_78 = self.value_80 = 0
        self.flag_68 = False
        self.completion_success = False
        self.status_70 = self.status(0)
        self.entry_timeout = self.state.read_timeout
        self.active_filter = None
        self.channel = CommonCAN.from_io(
            io,
            *location_headers(self.locations[context.state.write_cpu_index]),
            state=self.state,
        )

    def status(self, index):
        base = 0x5F1A48 if self.context.build == 18 else 0x59A7F0
        return int.from_bytes(self.source.read(base + index * 4, 4), "little")

    def cpu_type(self, index):
        from scripts.cuw_legacy_engine import executable_cpu_type

        return executable_cpu_type(self.context, index)

    def field(self, key, value):
        self.store.set_field(self.io, key, value)

    def begin_writing(self):
        self.store.begin_writing(self.io)

    def capture(self, error):
        self.value_78 = error.native_code & 0xFFFFFFFF
        if isinstance(error, ExecutableJ2534Error):
            self.value_80 = error.driver_status

    def stop_filter(self):
        from scripts.cuw_legacy_engine import executable_stop_filter

        if self.active_filter is not None:
            try:
                executable_stop_filter(self.io, self.active_filter)
            except ExecutableNativeError:
                # Native ALL stop handlers swallow native errors, retaining host ownership.
                pass
            self.active_filter = None

    def bind_cpu(self, index):
        from scripts.cuw_legacy_engine import executable_start_filter

        request, response = location_headers(self.locations[index])
        self.channel = CommonCAN.from_io(self.io, request, response, state=self.state)
        self.active_filter = executable_start_filter(
            self.io, request, response, padding=self.state.padding
        )

    def password(self, index, *, allow_new=True):
        from dataclasses import replace

        from scripts.cuw_legacy_engine import (
            executable_new_password,
            executable_selected_password,
        )

        if allow_new and self.context.state.use_new_software_password:
            return executable_new_password(
                replace(self.context, native=self.rows[index])
            )
        return executable_selected_password(self.context, index)

    def prepare(self):
        if self.p5:
            prepare_p5_imported(self.context, self.io, self.key_provider)
        else:
            prepare_ccan_imported(self.context, self.io, self.key_provider)

    def reconnect(self):
        from scripts.cuw_legacy_engine import executable_reconnect

        # 46e870 finishes the current session;46e450 rebuilds source-owned resources.
        executable_reconnect(self.context, self.io, 6)

    def m16c_recovery(self, physical: int) -> None:
        """46789c/441fec, including concrete raw-CAN reset467b9c/4422b8."""
        from scripts.cuw_legacy_engine import executable_reconnect

        attempt = 1
        while self.channel.m16c_status() is None:
            if attempt > 3:
                raise ExecutableCANError(20)
            if self.channel.m16c_query() is not None:
                break
            if self.cpu_type(physical) in ("15", "16"):
                self.channel.write(bytes(256))
            else:
                self.stop_filter()
                executable_reconnect(self.context, self.io, 5)
                self.channel.write(b"\x11" + bytes(7))
                self.channel.wait(1000)
                for index in range(36):
                    self.channel.write(bytes((0x20 + ((index + 1) & 15),)) + bytes(7))
                executable_reconnect(self.context, self.io, 6)
                self.bind_cpu(physical)
            self.channel.wait(3000)
            attempt += 1

    def retry_tail(self, logical: int, physical: int, saved_category: int) -> bool:
        """462d.../43e0... reconnect tail; return source skip-CPU exit predicate."""
        skip = self.cpu_type(logical) in ("86", "87", "89", "90", "216")
        if not skip:
            if self.context.build == 18:
                automatic_ig_off_cancel(self.context, self.io)
            from scripts.cuw_legacy_body import (
                central_gw_change_to_reprogramming,
                central_gw_exists,
            )

            if central_gw_exists(self.context):
                central_gw_change_to_reprogramming(self.context, self.io)
        self.bind_cpu(physical)
        try:
            if not skip:
                if logical != physical:
                    self.channel.set_timeout(3000)
                    self.m16c_recovery(physical)
                elif self.cpu_type(logical) == "22":
                    self.channel.wait(5000)
                else:
                    self.channel.prepare_reprogramming(saved_category)
                    self.field("PassThruErrorCode", 99)
        finally:
            self.stop_filter()
        return skip

    def show_error(
        self, end_block, *, reset_index=None, apply_password=True, publish_status=True
    ):
        from scripts.cuw_legacy_engine import (
            apply_recovery_password_state,
            executable_sync,
        )

        if publish_status:
            executable_sync(self.io, "value_70", value=self.status_70)
        if apply_password:
            apply_recovery_password_state(
                self.context, self.io, end_block, self.value_78
            )
        if (
            not self.p5
            and self.context.state.recovery_retry
            and not self.context.state.retry_input
        ):
            executable_sync(self.io, "flag_88", value=True)
            self.field("RetryInput", False)
            self.value_78 = self.value_80 = 0
            return True
        if self.p5 and reset_index is not None:
            self.progress.counts[reset_index] = 0
            self.progress.publish_counts()
            self.progress.percentages[reset_index] = 0
            self.progress.publish_percentages()
        executable_sync(
            self.io, "values_78_80", value_78=self.value_78, value_80=self.value_80
        )
        executable_sync(self.io, "flag_88", value=False)
        executable_sync(self.io, "error_handler")
        accepted = executable_sync(self.io, "read_flag_88")
        if not self.p5 and reset_index is not None:
            self.progress.counts[reset_index] = 0
            self.progress.publish_counts()
            self.progress.percentages[reset_index] = 0
            self.progress.publish_percentages()
        if not accepted:
            self.flag_68 = True
            return False
        self.value_78 = self.value_80 = 0
        return True

    def transfer_p5(self, logical, physical, transfer):
        channel = self.channel
        cpu_type = self.cpu_type(logical)
        extended = cpu_type in ("98", "216")
        channel.wait(1500 if cpu_type == "136" else 500)
        channel.check_id(
            self.locations[physical],
            self.password(physical, allow_new=cpu_type in ("136", "86", "87", "89")),
            swap_endian=extended,
        )
        if physical != logical:
            channel.set_timeout(10000)
            channel.m16c_password(cpu_type, self.password(logical, allow_new=False))
            m16c_flash_regions(
                channel,
                self.images[logical],
                ccan_m16c_extra_regions("90"),
                progress=lambda length: self.progress.account(logical, length),
            )
            channel.set_timeout(1000)
        else:
            try:
                if cpu_type in ("86", "87", "89"):
                    transfer_zv_imported(
                        self.context,
                        channel,
                        logical,
                        extended=True,
                        progress=self.progress,
                        begin_writing=True,
                    )
                elif cpu_type == "136":
                    flash_r32c_imported(
                        self.context,
                        channel,
                        logical,
                        logical,
                        transfer,
                        extended=True,
                        persist=self.context.state.recovery_persistence_active,
                        progress=self.progress,
                    )
            except ExecutableCANError as error:
                return error.native_code != 10
        return False

    def transfer_can(self, logical, physical, transfer):
        from scripts.cuw_legacy_engine import set_executable_cpu_type

        channel = self.channel
        native_failures: list[ExecutableNativeError] = []
        cpu_type = self.cpu_type(logical)
        if physical != logical:
            channel.set_timeout(10000)
            if not self.context.state.retry_mode or cpu_type == "90":
                channel.m16c_password(cpu_type, self.password(logical, allow_new=False))
            m16c_flash_regions(
                channel,
                self.images[logical],
                ccan_m16c_extra_regions(cpu_type),
                begin_writing=self.begin_writing,
                progress=lambda length: self.progress.account(logical, length),
                native_failures=native_failures,
            )
            channel.set_timeout(1000)
            return bool(native_failures)
        channel.wait(
            600 if self.context.native.base_metadata["kind_of_ecu"] == "47" else 500
        )
        password = self.password(
            physical, allow_new=cpu_type in ("22", "86", "87", "89", "216", "90")
        )
        channel.check_id(
            self.locations[physical],
            password,
            swap_endian=cpu_type in ("98", "216"),
            interframe_ms=2 if cpu_type in ("20", "85", "124", "26") else None,
        )
        if cpu_type in ("19", "73"):
            channel.command(b"\x05", error_code=40)
        memory = None
        extended = False
        if self.tables.dynamic_cpu(cpu_type):
            memory, extended = channel.memory_ordinary()
            if extended != self.tables.cpu_mode(cpu_type):
                mapped = self.tables.remap_cpu(cpu_type)
                if mapped is None:
                    raise ExecutableCANError(10)
                set_executable_cpu_type(self.context, logical, mapped)
                cpu_type = mapped
        else:
            extended = self.tables.cpu_mode(cpu_type)
        try:
            if cpu_type in ("86", "87", "89"):
                transfer_zv_imported(
                    self.context,
                    channel,
                    logical,
                    extended=extended,
                    progress=self.progress,
                    begin_writing=True,
                )
            elif extended:
                flash_shrink_imported(
                    self.context,
                    channel,
                    logical,
                    logical,
                    extended=extended,
                    persist=self.context.state.recovery_persistence_active,
                    memory=memory,
                    progress=self.progress,
                    transfer=transfer,
                    begin_writing=True,
                )
        except ExecutableCANError as error:
            return error.native_code != 10
        if cpu_type not in ("86", "87", "89") and not extended:
            if memory is None:
                memory, extended = channel.memory_ordinary()
            if not cpu_matches(
                cpu_type,
                memory.firmware_descriptor,
                extended,
                self.tables.descriptor_rows(),
            ):
                raise ExecutableCANError(10)
            ordinary_flash_blocks(
                channel,
                cpu_type,
                memory,
                self.images[logical],
                wide=extended,
                progress=lambda length: self.progress.account(logical, length),
                begin_writing=self.begin_writing,
                set_error=lambda code: self.field("PassThruErrorCode", code),
                native_failures=native_failures,
            )

        return bool(native_failures)

    def run(self):
        from scripts.cuw_legacy_engine import (
            executable_retry_requested,
            executable_sync,
        )

        initial_failed = program_failed = False
        cleanup_errors = []
        primary = None
        try:
            try:
                if self.p5 or not executable_retry_requested(self.context):
                    self.prepare()
            except ExecutableNativeError:
                initial_failed = True
            position = self.context.state.write_cpu_index
            if (
                not initial_failed
                and not self.p5
                and self.cpu_type(position) == "22"
                and not executable_retry_requested(self.context)
            ):
                CommonCAN.from_io(self.io, b"\0" * 4, b"\0" * 4, state=self.state).wait(
                    2000
                )
            while not initial_failed and position < len(self.rows):
                logical = position
                cpu_type = self.cpu_type(logical)
                aliases = ("90",) if self.p5 else ("17", "54", "90", "18")
                physical = logical
                if cpu_type in aliases:
                    supported = (
                        ("87", "86", "89")
                        if self.p5
                        else ("15", "86", "87", "89", "216", "16")
                    )
                    physical = next(
                        (
                            index
                            for index in range(len(self.rows))
                            if index != logical and self.cpu_type(index) in supported
                        ),
                        -1,
                    )
                    if physical < 0:
                        break
                transfer = CANTransferState(
                    self.context.state.native_flag_ed6
                    if self.p5
                    else self.context.state.writing_end_block
                    if executable_retry_requested(self.context)
                    else False,
                    self.context.state if self.p5 else None,
                )
                retry_phase = failed = False
                if not self.p5 and not executable_retry_requested(self.context):
                    self.field("WritingEndBlock", False)
                try:
                    self.bind_cpu(physical)
                    if self.p5:
                        retry_phase = self.transfer_p5(logical, physical, transfer)
                    else:
                        retry_phase = self.transfer_can(logical, physical, transfer)
                    if self.p5:
                        self.context.state.use_new_software_password = False
                    else:
                        self.field("UseNewSoftwarePassword", False)
                    original_position = position
                    if (
                        not self.p5
                        and self.context.native.base_metadata["kind_of_ecu"] == "51"
                        and position + 1 < len(self.rows)
                        and self.cpu_type(logical + 1) == "15"
                    ):
                        position = len(self.rows) - 1
                    if position + 1 < len(self.rows):
                        try:
                            self.channel.change_cpu()
                        except ExecutableNativeError:
                            failed = True
                    else:
                        acknowledge = (
                            self.context.build == 18
                            and not self.p5
                            and can_finish_ack(
                                self.context.native.base_metadata["kind_of_ecu"],
                                tuple(self.cpu_type(i) for i in range(len(self.rows))),
                            )
                        )
                        try:
                            header = (
                                b"\0\0"
                                + self.locations[
                                    int(
                                        self.cpu_type(0)
                                        in (
                                            ("90",)
                                            if self.p5
                                            else ("17", "54", "90", "18")
                                        )
                                    )
                                ][6:8]
                            )
                            self.channel.finish(
                                acknowledge=acknowledge, request_header=header
                            )
                        except ExecutableNativeError:
                            if not self.p5 and acknowledge:
                                retry_phase = True
                                raise
                        if not self.p5 and original_position + 1 == len(self.rows):
                            self.store.finish(self.io)
                        self.completion_success = True
                except (ExecutableJ2534Error, ExecutableCANError) as error:
                    self.capture(error)
                    failed = True
                    retry_phase = retry_phase or self.context.state.retry_mode
                finally:
                    self.stop_filter()
                if retry_phase:
                    saved_category = self.value_78
                    self.status_70 = self.status(2)
                    apply_password = True
                    repeat_connect = False
                    leave_controller = False
                    while True:
                        if not self.show_error(
                            self.context.state.native_flag_ed6
                            if self.p5
                            else transfer.end_block,
                            reset_index=None
                            if self.p5 and repeat_connect
                            else position,
                            apply_password=apply_password,
                            publish_status=not repeat_connect,
                        ):
                            leave_controller = True
                            break
                        apply_password = False
                        try:
                            self.reconnect()
                            if not self.p5:
                                leave_controller = self.retry_tail(
                                    logical, physical, saved_category
                                )
                        except (ExecutableJ2534Error, ExecutableCANError) as error:
                            if self.p5 and isinstance(error, ExecutableCANError):
                                raise
                            self.capture(error)
                            self.status_70 = self.status(3)
                            executable_sync(self.io, "value_70", value=self.status_70)
                            repeat_connect = True
                            continue
                        self.context.state.retry_mode = True
                        leave_controller = leave_controller or self.p5
                        break
                    if leave_controller:
                        break
                    continue
                if failed:
                    initial_failed = True
                    program_failed = True
                    break
                self.context.state.retry_mode = False
                if self.p5:
                    self.context.state.native_flag_ed6 = False
                else:
                    self.field("Writing", False)
                    self.field("WriteCpuIndex", position + 1)
                position += 1
            if initial_failed:
                self.status_70 = self.status(2 if program_failed else 1)
                apply_password = True
                while self.show_error(
                    self.context.state.native_flag_ed6 if self.p5 else False,
                    apply_password=apply_password,
                ):
                    apply_password = False
                    try:
                        self.reconnect()
                    except (ExecutableJ2534Error, ExecutableCANError) as error:
                        self.capture(error)
                        self.status_70 = self.status(3)
                        continue
                    break
            executable_sync(self.io, "flag_68", value=self.flag_68)
            executable_sync(
                self.io, "values_78_80", value_78=self.value_78, value_80=self.value_80
            )
            executable_sync(self.io, "owner_clear")
            executable_sync(
                self.io,
                "completion",
                outcome="success" if self.completion_success else "failure",
            )
        except BaseException as error:
            primary = error
            if isinstance(error, (InterruptedError, TimeoutError)):
                try:
                    if self.channel is not None:
                        self.channel.set_timeout(self.entry_timeout, cleanup=True)
                except Exception as cleanup:  # noqa: BLE001 - retain original host boundary
                    error.add_note(
                        "CAN abort timeout restoration failed: "
                        + type(cleanup).__name__
                    )
            raise
        finally:
            cleanup_errors = self.io.close()
            if primary is not None:
                for detail in cleanup_errors:
                    primary.add_note("CAN host cleanup failed: " + detail)
        self.io.check()
        return {
            "controller": self.context.controller,
            "build": self.context.build,
            "native_success": self.completion_success,
            "success": self.completion_success
            and not self.flag_68
            and not cleanup_errors,
            "native_flag_68": self.flag_68,
            "native_value_78": self.value_78,
            "native_value_80": self.value_80,
            "host_cleanup_errors": cleanup_errors,
        }


def execute(context, io):
    return CanController(context, io).run()
