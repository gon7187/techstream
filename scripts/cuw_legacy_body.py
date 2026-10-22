"""Original CUW12/18 body and chassis controllers.

These are executable-internal algorithms. No DLL implementation or device is
selected here; callers supply raw communication and imported native context.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Protocol

from scripts.cuw_legacy_can import ExecutableCANError


@dataclass(frozen=True)
class CPUDescriptor:
    """Fields +4/+5/+6/+8/+c of a selected native utility table row."""

    identifier: int
    wide_identifier: bool
    big_endian: bool
    external_flag_offset: int
    external: bool

    def __post_init__(self) -> None:
        if (
            type(self.identifier) is not int
            or not 0 <= self.identifier <= 0x7F
            or type(self.external_flag_offset) is not int
            or not 0 <= self.external_flag_offset < 64 * 1024 * 1024
            or any(
                type(value) is not bool
                for value in (self.wide_identifier, self.big_endian, self.external)
            )
        ):
            raise ValueError("Invalid native CPU descriptor")


def cpu_matches(descriptor: CPUDescriptor, firmware_id: int, wide: bool) -> bool:
    """Cuw18 569e10/57547c: compare both identification mode and CPU value."""
    if (
        not isinstance(descriptor, CPUDescriptor)
        or type(firmware_id) is not int
        or not 0 <= firmware_id <= 255
        or type(wide) is not bool
    ):
        raise ValueError("Native descriptor, identification byte and BOOL required")
    identifier = firmware_id & 0x7F if wide else (firmware_id >> 4) & 7
    return descriptor.wide_identifier == wide and descriptor.identifier == identifier


def memory_mode(descriptor: CPUDescriptor, image: bytes) -> int:
    """Cuw18 56a2c8/575380: image flag 0/1, otherwise native unknown mode 2."""
    if (
        not isinstance(descriptor, CPUDescriptor)
        or type(image) is not bytes
        or not 0 < len(image) <= 64 * 1024 * 1024
        or descriptor.external_flag_offset >= len(image)
    ):
        raise ValueError("Native external-memory flag lies outside supplied image")
    value = image[descriptor.external_flag_offset]
    return value if value in (0, 1) else 2


def sequential_ranges(count: int) -> tuple[tuple[int, int], ...]:
    """Cuw18 5677c4: one-based singleton ranges for every calculated block."""
    if type(count) is not int or not 0 <= count <= 65536:
        raise ValueError("Bounded native block count required")
    return tuple((number, number) for number in range(1, count + 1))


def s0_block_ranges(header: bytes) -> tuple[tuple[int, int], ...]:
    """Cuw18 56a130/569ec0: AA55AA55 records expand BE16 inclusive ranges.

    Native code reads beyond malformed buffers. Reject those buffers at the host
    boundary while retaining record skipping and reversed-range behavior.
    """
    if type(header) is not bytes or len(header) > 1024 * 1024:
        raise ValueError("Bounded decoded S0 header required")
    result: list[tuple[int, int]] = []
    index = 0
    while index < len(header):
        if header[index : index + 4] != b"\xaa\x55\xaa\x55":
            index += 1
            continue
        if index + 8 > len(header):
            raise ValueError("Truncated native S0 range record")
        count = header[index + 7]
        end = index + 8 + count * 4
        if end > len(header):
            raise ValueError("Truncated native S0 range entries")
        for offset in range(index + 8, end, 4):
            first = int.from_bytes(header[offset : offset + 2], "big")
            last = int.from_bytes(header[offset + 2 : offset + 4], "big")
            if last == 65535:
                # Native WORD increment wraps here and cannot terminate.
                raise ValueError("Native S0 range would wrap its WORD iterator")
            if len(result) + max(0, last - first + 1) > 65536:
                raise ValueError("Native S0 range expansion exceeds host budget")
            result.extend((number + 1, number + 1) for number in range(first, last + 1))
        index = end
    return tuple(result)


def validate_external_ranges(
    sizes: Sequence[int], ranges: Sequence[tuple[int, int]], flash_size: int
) -> None:
    """Cuw18 56c2fc: selected first blocks increase and sum to FlashSize."""
    if (
        not isinstance(sizes, (tuple, list))
        or not isinstance(ranges, (tuple, list))
        or len(sizes) > 65536
        or len(ranges) > 65536
        or type(flash_size) is not int
        or not 0 <= flash_size <= 64 * 1024 * 1024
        or any(type(size) is not int or not 0 <= size <= 0xFFFFFFFF for size in sizes)
    ):
        raise ValueError("Bounded native block geometry required")
    previous = 0
    total = 0
    for pair in ranges:
        if (
            not isinstance(pair, tuple)
            or len(pair) != 2
            or any(type(value) is not int for value in pair)
            or not previous < pair[0] <= len(sizes)
            or not 1 <= pair[1] <= 65536
        ):
            raise ValueError("Native selected blocks must strictly increase")
        previous = pair[0]
        total = (total + sizes[pair[0] - 1]) & 0xFFFFFFFF
    if total != flash_size:
        raise ValueError("Native selected block sizes differ from FlashSize")


class EPBChannel(Protocol):
    """Concrete shared-CAN primitives; no operation-level success callback."""

    def write(self, payload: bytes) -> None: ...
    def ack(self) -> bool: ...
    def status(self, *, retry: bool = True) -> int: ...
    def wait(self, milliseconds: int) -> None: ...


class BodyOperationError(ExecutableCANError):
    def __init__(
        self,
        code: int,
        operation: str,
        *,
        response: bytes | None = None,
        response_size: int | None = None,
    ):
        if response is not None and (
            type(response) is not bytes
            or len(response) > 4095
            or type(response_size) is not int
            or not len(response) <= response_size <= 4100
        ):
            raise ValueError("Bounded native diagnostic response required")
        self.response = response
        self.response_size = response_size
        super().__init__(code)
        self.native_code = code
        self.operation = operation
        self.args = (f"Native body controller {operation} failed ({code})",)


def _epb_erase_native(channel: EPBChannel, block: int) -> None:
    """Cuw18 57a3a4: narrow erase and 10 ms pending-80 polling."""
    if type(block) is not int or not 1 <= block <= 256:
        raise ValueError("EPB block number must fit the native byte")
    channel.write(bytes((0x25, block - 1)))
    if not channel.ack():
        raise BodyOperationError(12, "erase ACK")
    while True:
        channel.wait(10)
        status = channel.status(retry=True)
        if type(status) is not int or not 0 <= status <= 255:
            raise ValueError("Native status must be a byte")
        if status != 0x80:
            break
    if status:
        raise BodyOperationError(12, "erase")


def epb_erase(channel: EPBChannel, block: int) -> None:
    """57a3a4: annotate only the native driver exception category12."""
    with _transfer_phase(12, pass_thru=False):
        _epb_erase_native(channel, block)


def _epb_verify(
    channel: EPBChannel,
    image: bytes,
    sizes: Sequence[int],
    block: int,
    cpu_index: int,
    progress: Callable[[int, int], None],
) -> None:
    """Cuw18 57a7c0: 256-byte raw verify chunks and pending-20 polling.

    Caller supplies shared primitive deadline/cancellation checks. Native copies
    exactly 256 bytes even on the final chunk; reject an out-of-image read.
    """
    if (
        type(image) is not bytes
        or not 0 < len(image) <= 64 * 1024 * 1024
        or not isinstance(sizes, (tuple, list))
        or not 1 <= len(sizes) <= 256
        or any(
            type(size) is not int or not 0 <= size <= 64 * 1024 * 1024 for size in sizes
        )
        or type(block) is not int
        or not 1 <= block <= len(sizes)
        or type(cpu_index) is not int
        or not 0 <= cpu_index < 128
        or not callable(progress)
    ):
        raise ValueError("Invalid bounded EPB verification geometry")
    start = sum(sizes[: block - 1])
    size = sizes[block - 1]
    copied_size = ((size + 255) // 256) * 256
    if start + copied_size > len(image):
        raise ValueError("Native EPB verification would read beyond image")
    channel.write(bytes((0x15, block - 1)))
    if not channel.ack():
        raise BodyOperationError(15, "verify ACK")
    for offset in range(0, size, 256):
        channel.write(image[start + offset : start + offset + 256])
        progress(cpu_index, 256)
        if not channel.ack():
            raise BodyOperationError(15, "verify data ACK")
        status = 0
        while True:
            channel.wait(5)
            try:
                status = channel.status(retry=offset + 256 == size)
            except ExecutableCANError:
                if offset + 256 == size:
                    raise
                break
            if type(status) is not int or not 0 <= status <= 255:
                raise ValueError("Native status must be a byte")
            if status != 0x20:
                break
        if status:
            raise BodyOperationError(15, "verify")


@contextmanager
def _transfer_phase(code: int, *, pass_thru: bool = True) -> Iterator[None]:
    """57abd2/57b167/58dab9: driver category mutation and CPass replacement."""
    from scripts.cuw_legacy_engine import ExecutableJ2534Error

    try:
        yield
    except ExecutableJ2534Error as error:
        error.native_code = code
        raise
    except ExecutableCANError as error:
        if pass_thru:
            raise BodyOperationError(code, "transfer") from error
        raise


def epb_verify(channel, image, sizes, block, cpu_index, progress) -> None:
    """57a7c0: typed CPassThru/CJ2534 handlers preserve native domains."""
    with _transfer_phase(15):
        _epb_verify(channel, image, sizes, block, cpu_index, progress)


def _epb_memory_native(channel):
    """Cuw18 57a54c/58d284: 75 only, exactly eight memory bytes, two ACKs."""
    from scripts.cuw_legacy_can import CANMemory

    channel.write(b"\x75")
    if not channel.ack():
        raise BodyOperationError(10, "memory ACK")
    response = channel.read(mode=1)
    if type(response) is not bytes or len(response) != 12:
        raise BodyOperationError(10, "memory length")
    result = CANMemory(
        int.from_bytes(response[4:7], "big"),
        int.from_bytes(response[7:10], "big"),
        response[10],
        response[11],
    )
    if not channel.ack():
        raise BodyOperationError(10, "memory final ACK")
    return result


def epb_memory(channel):
    """57a54c/58d284: memory10 mutates only typed native driver failures."""
    with _transfer_phase(10, pass_thru=False):
        return _epb_memory_native(channel)


def _block_write_native(
    channel: EPBChannel,
    image: bytes,
    sizes: Sequence[int],
    block: int,
    address: int,
    cpu_index: int,
    progress: Callable[[int, int], None],
    *,
    first_wait: int,
    status_retry: bool,
) -> None:
    if (
        type(image) is not bytes
        or not 0 < len(image) <= 64 * 1024 * 1024
        or not isinstance(sizes, (tuple, list))
        or not 1 <= len(sizes) <= 256
        or any(
            type(size) is not int or not 0 <= size <= 64 * 1024 * 1024 for size in sizes
        )
        or type(block) is not int
        or not 1 <= block <= len(sizes)
        or type(cpu_index) is not int
        or not 0 <= cpu_index < 128
        or not callable(progress)
        or type(address) is not int
        or not 0 <= address <= 0xFFFFFF
    ):
        raise ValueError("Invalid bounded native body write geometry")
    start = sum(sizes[: block - 1])
    size = sizes[block - 1]
    copied_size = max(1024, ((size + 1023) // 1024) * 1024)
    if start + copied_size > len(image) or address + start > 0xFFFFFF:
        raise ValueError("Native body writer would read outside image/address")
    channel.write(b"\x41")
    if not channel.ack():
        raise BodyOperationError(13, "write initial ACK")
    channel.write((address + start).to_bytes(3, "big") + b"\xff")
    if first_wait:
        channel.wait(first_wait)
    for offset in range(0, copied_size, 1024):
        if offset:
            channel.write(b"\x45")
            if not channel.ack():
                raise BodyOperationError(13, "write continuation ACK")
        channel.write(image[start + offset : start + offset + 1024])
        progress(cpu_index, 1024)
        if not channel.ack():
            raise BodyOperationError(13, "write data ACK")
        while True:
            channel.wait(5)
            status = channel.status(retry=status_retry)
            if type(status) is not int or not 0 <= status <= 255:
                raise ValueError("Native status must be a byte")
            if status != 0x40:
                break
        if status:
            raise BodyOperationError(13, "write status")


def epb_write(channel, image, sizes, block, address, cpu_index, progress) -> None:
    """Cuw18 57ac50: 1024-byte writes, 5 ms pending40, no status retries."""
    with _transfer_phase(13):
        _block_write_native(
            channel,
            image,
            sizes,
            block,
            address,
            cpu_index,
            progress,
            first_wait=0,
            status_retry=False,
        )


def epc_write(channel, image, sizes, block, address, cpu_index, progress) -> None:
    """Cuw18 58d644: wait3 before first chunk and retrying status polling."""
    with _transfer_phase(13):
        _block_write_native(
            channel,
            image,
            sizes,
            block,
            address,
            cpu_index,
            progress,
            first_wait=3,
            status_retry=True,
        )


def epc_erase(channel: EPBChannel, block: int) -> None:
    """Cuw18 58d4f8/58e0c8: erase uses operation error12, pending80."""
    with _transfer_phase(12, pass_thru=False):
        _epc_block_operation(channel, block, b"\x25", 0x80, 12)


def epc_inverify(channel: EPBChannel, block: int) -> None:
    """Cuw18 58db3c/58e0c8: internal verify47, pending40, error14."""
    with _transfer_phase(14, pass_thru=False):
        _epc_block_operation(channel, block, b"\x47", 0x40, 14)


def _epc_block_operation(channel, block, command, busy, code):
    if type(block) is not int or not 1 <= block <= 256:
        raise ValueError("EPC block number must fit the native byte")
    channel.write(command + bytes((block - 1,)))
    if not channel.ack():
        raise BodyOperationError(code, "block ACK")
    while True:
        channel.wait(10)
        status = channel.status(retry=True)
        if type(status) is not int or not 0 <= status <= 255:
            raise ValueError("Native status must be a byte")
        if status != busy:
            break
    if status:
        raise BodyOperationError(code, "block status")


def epc_verify(channel, image, sizes, block, cpu_index, progress) -> None:
    """58dc88 has the same wire/state/copy/ACK/poll flow as EPB57a7c0."""
    epb_verify(channel, image, sizes, block, cpu_index, progress)


class BodyTables:
    """Read selected CPU geometry from the supplied, hash-admitted executable.

    Native Delphi initializers assign string pointers into otherwise static rows.
    Read those assignments; do not execute the original image or ship its tables.
    """

    def __init__(self, context):
        import re

        from scripts.cuw_legacy_engine import ExecutableImage

        self.build = context.build
        self.image = ExecutableImage(context)
        self.names: dict[int, int] = {}
        for pattern in (
            rb"\xa1(.{4})\xa3(.{4})",
            rb"\x8b\x15(.{4})\x89\x15(.{4})",
            rb"\x8b\x0d(.{4})\x89\x0d(.{4})",
        ):
            for match in re.finditer(pattern, self.image.data, re.DOTALL):
                source, destination = (
                    int.from_bytes(value, "little") for value in match.groups()
                )
                lower, upper = (
                    (0x610000, 0x630000) if self.build == 18 else (0x5B0000, 0x5D0000)
                )
                fc_lower, fc_upper = (
                    (0x5F731C, 0x5F7470) if self.build == 18 else (0x59EC90, 0x59EDE4)
                )
                if lower <= destination < upper or fc_lower <= destination < fc_upper:
                    self.names[destination] = self.number(source)
        initializers = (
            ((0x56E510, 0x360, 0x616FB0, 3), (0x47F098, 0x400, 0x5F731C, 6))
            if self.build == 18
            else ((0x5262C0, 0x360, 0x5BAF60, 3), (0x4513D4, 0x400, 0x59EC90, 6))
        )
        for address, size, table, base_register in initializers:
            self._relative_names(address, size, table, base_register)

    def _relative_names(
        self, address: int, size: int, table: int, base_register: int
    ) -> None:
        """Unit initializers also store string pointers relative to EBX/ESI."""
        import re

        code = self.image.read(address, size)
        for source_register, pattern in (
            (0, rb"\xa1(.{4})"),
            (1, rb"\x8b\x0d(.{4})"),
            (2, rb"\x8b\x15(.{4})"),
        ):
            for match in re.finditer(pattern, code, re.DOTALL):
                store = code[match.end() : match.end() + 6]
                if (
                    len(store) < 2
                    or store[0] != 0x89
                    or (store[1] >> 3) & 7 != source_register
                    or store[1] & 7 != base_register
                ):
                    continue
                mode = store[1] >> 6
                if mode == 0:
                    offset = 0
                elif mode in (1, 2):
                    width = 1 if mode == 1 else 4
                    if len(store) < width + 2:
                        raise ValueError("Truncated native table string assignment")
                    offset = int.from_bytes(store[2 : 2 + width], "little", signed=True)
                else:
                    continue
                if 0 <= offset < 128 * 8 and offset % 8 == 0:
                    source = int.from_bytes(match.group(1), "little")
                    self.names[table + offset] = self.number(source)

    def number(self, address: int) -> int:
        return int.from_bytes(self.image.read(address, 4), "little")

    def _constructed_word(self, address: int) -> bytes:
        """Read a CBytes2 WORD initializer; its file-backed object is still zeroed."""
        import re

        constructor = 0x419BDC if self.build == 18 else 0x40E310
        pattern = rb"\x68(.{4})\x68" + re.escape(address.to_bytes(4, "little"))
        pattern += rb"\xe8(.{4})"
        values = []
        for match in re.finditer(pattern, self.image.data, re.DOTALL):
            call_offset = match.start() + 10
            for rva, size, raw in self.image.sections:
                if raw <= call_offset < raw + size:
                    call_address = self.image.image_base + rva + call_offset - raw
                    relative = int.from_bytes(match.group(2), "little", signed=True)
                    if call_address + 5 + relative == constructor:
                        value = int.from_bytes(match.group(1), "little")
                        if value > 0xFFFF:
                            raise ValueError("Native private constructor is not a WORD")
                        values.append(value.to_bytes(2, "big"))
        if len(values) != 1:
            raise ValueError("Native private WORD constructor is not uniquely sourced")
        return values[0]

    def _name(self, row: int) -> str:
        address = self.names.get(row, self.number(row))
        value = bytearray()
        for offset in range(32):
            byte = self.image.read(address + offset, 1)[0]
            if byte == 0:
                return bytes(value).decode("ascii")
            value.append(byte)
        raise ValueError("Unbounded native CPU type string")

    def _row(self, table: int, count: int, stride: int, cpu_type: str) -> int:
        if type(cpu_type) is not str or len(cpu_type) > 31:
            raise ValueError("Bounded original CPU type required")
        for index in range(count):
            row = table + index * stride
            if self._name(row) == cpu_type:
                return row
        raise BodyOperationError(99, "unknown CPU utility table")

    def descriptor(self, kind: str, cpu_type: str) -> CPUDescriptor:
        if kind not in ("body", "dss1"):
            raise ValueError("Body or DSS1 descriptor required")
        table, count, stride = (
            ((0x614244 if self.build == 18 else 0x5B8214), 27, 16)
            if kind == "body"
            else ((0x619644 if self.build == 18 else 0x5BD5E0), 6, 12)
        )
        row = self._row(table, count, stride, cpu_type)
        values = self.image.read(row + 4, 8)
        external = bool(self.number(row + 12)) if kind == "body" else False
        return CPUDescriptor(
            values[0],
            bool(values[1]),
            bool(values[2]),
            int.from_bytes(values[4:8], "little"),
            external,
        )

    def epc_cpu_matches(self, cpu_type: str, firmware_id: int) -> bool:
        """58c52f: source EPC row, common46cb1c with narrow mode0."""
        return self.identified("epc", cpu_type, firmware_id, False)

    def identified(
        self, kind: str, cpu_type: str, firmware_id: int, wide: bool
    ) -> bool:
        """46cb1c/444f38: source family row, sentinel and both ID modes."""
        if (
            type(cpu_type) is not str
            or len(cpu_type) > 31
            or type(firmware_id) is not int
            or not 0 <= firmware_id <= 255
            or type(wide) is not bool
        ):
            raise ValueError(
                "Bounded original CPU type and identification byte required"
            )
        layouts = {
            "airbag": 0x6135EC if self.build == 18 else 0x5B75C0,
            "chassis": 0x616FB0 if self.build == 18 else 0x5BAF60,
            "epb": 0x616FB0 if self.build == 18 else 0x5BAF60,
            "old_ecb": 0x616FB0 if self.build == 18 else 0x5BAF60,
            "fc": 0x5F731C if self.build == 18 else 0x59EC90,
            "epc": 0x628EC0 if self.build == 18 else 0x5CCA40,
        }
        if kind not in layouts:
            raise ValueError("Unknown native CPU identification table")
        table = layouts[kind]
        for index in range(128):
            row = table + index * 8
            name = self._name(row)
            if not name:
                return False
            if name == cpu_type:
                values = self.image.read(row + 4, 2)
                return cpu_matches(
                    CPUDescriptor(values[0], bool(values[1]), False, 0, False),
                    firmware_id,
                    wide,
                )
        raise ValueError("Native CPU identification table has no bounded sentinel")

    def sonar_cpu(self, cpu_type: str) -> tuple[int, bool] | None:
        """56fda8/56fe1c: four source rows, identifier and swap-endian flag."""
        if type(cpu_type) is not str or len(cpu_type) > 31:
            raise ValueError("Bounded original sonar CPU type required")
        table = 0x617C00 if self.build == 18 else 0x5BBBE4
        for index in range(4):
            row = table + index * 8
            if self._name(row) == cpu_type:
                values = self.image.read(row + 4, 2)
                return values[0], bool(values[1])
        return None

    def sizes(self, kind: str, cpu_type: str) -> tuple[int, ...]:
        """567? byte sizes versus Body/DSS1/EPC run-length KiB rows."""
        if kind == "airbag":
            try:
                row = self._row(
                    0x6139D8 if self.build == 18 else 0x5B79A8, 4, 24, cpu_type
                )
            except BodyOperationError:
                return ()
            count = self.image.read(row + 4, 1)[0]
            if count > 19:
                raise ValueError("Native Airbag size row exceeds table width")
            return tuple(value * 1024 for value in self.image.read(row + 5, count))
        layouts = {
            "body": (0x614770 if self.build == 18 else 0x5B8734, 26),
            "dss1": (0x618BEC if self.build == 18 else 0x5BCB88, 5),
            "epc": (0x628ED4 if self.build == 18 else 0x5CCA54, 1),
        }
        if kind not in layouts:
            raise ValueError("Unknown native CPU block-size table")
        table, count = layouts[kind]
        row = self._row(table, count, 136, cpu_type)
        count = self.number(row + 4)
        result = []
        for index in range(16):
            if len(result) >= count:
                return tuple(result)
            size = self.number(row + 8 + index * 8) * 1024
            repetitions = self.number(row + 12 + index * 8)
            if repetitions > 65536 or len(result) + repetitions > 65536:
                raise ValueError("Native block size expansion exceeds host budget")
            result.extend([size] * repetitions)
        raise ValueError("Native size row does not cover declared block count")

    def body_shift_operands(self) -> bytes:
        """522814/56a30c read six private operands from the admitted original."""
        return self.image.read(0x614004 if self.build == 18 else 0x5B7FD4, 6)

    def two_byte_passwords(
        self, kind: str, kind_of_ecu: str, index: int = 0
    ) -> tuple[bytes, bytes]:
        """568080/5752a8: KindOfECU-selected WORDs, CBytes2 BE order."""
        if type(index) is not int or not 0 <= index < 4:
            raise ValueError("Native two-byte password index must be 0..3")
        if kind == "airbag":
            table, count = (0x61361C if self.build == 18 else 0x5B75F0), 1
        elif kind == "dss1":
            table, count = (0x619690 if self.build == 18 else 0x5BD62C), 3
        else:
            raise ValueError("Airbag or DSS1 two-byte password table required")
        row = self._row(table, count, 20, kind_of_ecu)
        return (
            self.image.read(row + 4 + index * 2, 2)[::-1],
            self.image.read(row + 12 + index * 2, 2)[::-1],
        )

    def sonar_passwords(self) -> tuple[bytes, bytes]:
        """5266f4/56e944 construct private CBytes2 globals from WORD immediates."""
        operands = (0x56E964, 0x56E989) if self.build == 18 else (0x526714, 0x526739)
        values = tuple(self.number(address) for address in operands)
        if any(value > 0xFFFF for value in values):
            raise ValueError("Native sonar initializer is not a WORD constructor")
        return values[0].to_bytes(2, "big"), values[1].to_bytes(2, "big")

    def preparation_cpu_selectors(
        self, kind: str, kind_of_ecu: str, address_count: int
    ) -> tuple[int, ...]:
        """56d828/582884: two-address preparation CPU ordering, independent of IDs."""
        if (
            kind not in ("chassis", "old_ecb")
            or type(kind_of_ecu) is not str
            or len(kind_of_ecu) > 128
            or type(address_count) is not int
            or not 0 <= address_count <= 2
        ):
            raise ValueError("Bounded native two-address preparation required")
        if kind == "old_ecb":
            address = 0x61F490 if self.build == 18 else 0x5C3078
            return tuple(self.image.read(address, 2)[:address_count])
        comparison = self._name(0x5D51B0 if self.build == 18 else 0x585494)
        selectors = (
            (1, 0) if address_count == 2 and kind_of_ecu == comparison else (0, 2)
        )
        return selectors[:address_count]

    def four_round_operands(self, kind: str, cpu_type: str = "") -> tuple[bytes, ...]:
        """Selected source-specific round operands; values remain in private PE."""
        if kind == "epb":
            table = 0x616748 if self.build == 18 else 0x5BA6F8
        elif kind == "fc":
            table = 0x5F6EE8 if self.build == 18 else 0x59E85C
        elif kind == "old_ecb":
            table = 0x616314 if self.build == 18 else 0x5BA2C4
        elif kind == "chassis":
            globals_ = (
                (0x5D4FD0, 0x5D5000, 0x5D4FF0)
                if self.build == 18
                else (0x5852B4, 0x5852E4, 0x5852D4)
            )
            special = tuple(self._name(address) for address in globals_)
            table = (
                (0x616B7C if cpu_type in special else 0x616314)
                if self.build == 18
                else (0x5BAB2C if cpu_type in special else 0x5BA2C4)
            )
        else:
            raise ValueError("Unknown native four-round security family")
        return tuple(self._constructed_word(table + index * 268) for index in range(4))

    def ranges(
        self, kind: str, cpu_type: str, block_count: int
    ) -> tuple[tuple[int, int], ...]:
        """46c050/444d60: source CPU row or empty fallback, up to five ranges."""
        if (
            kind not in ("chassis", "old_ecb", "sonar", "fc")
            or type(cpu_type) is not str
            or len(cpu_type) > 31
            or type(block_count) is not int
            or not 1 <= block_count <= 65536
        ):
            raise ValueError(
                "Native grouped controller, CPU type and block count required"
            )
        table = (
            (0x617C24 if self.build == 18 else 0x5BBC08)
            if kind == "sonar"
            else (0x6170C4 if self.build == 18 else 0x5BB074)
        )
        for index in range(1024):
            row = table + index * 44
            if self._name(row) in (cpu_type, ""):
                result = []
                for pair in range(5):
                    first, last = (
                        self.number(row + 4 + pair * 8),
                        self.number(row + 8 + pair * 8),
                    )
                    if first == 0:
                        break
                    result.append((first, last))
                if not result:
                    raise ValueError(
                        "Native grouping would index an empty range vector"
                    )
                if result[-1][1] == 0:
                    result[-1] = (result[-1][0], block_count)
                if any(not 1 <= first <= last <= block_count for first, last in result):
                    raise ValueError("Native grouped range lies outside block geometry")
                return tuple(result)
        raise ValueError("Native CPU grouping table has no bounded fallback")


def diagnostic(
    channel,
    request: bytes,
    expected: bytes,
    minimum_response: int,
    error_code: int,
    *,
    padding: bool,
    busy_retries: int = 255,
    pending_responses: int = 149,
    wait_ms: int = 0,
    native_cancel: Callable[[], bool] | None = None,
) -> bytes:
    """Cuw18 45d458: mode2 diagnostics, NRC21 resend and NRC78 bounded read.

    The existing channel timeout is required native context. Deadline/cancellation
    and restoration after provider faults are explicit host safety policy.
    """
    from scripts.cuw_legacy_engine import ExecutableJ2534Error

    if (
        type(request) is not bytes
        or not 1 <= len(request) <= 4095
        or type(expected) is not bytes
        or len(expected) > 4095
        or type(minimum_response) is not int
        or not len(expected) <= minimum_response <= 4095
        or type(error_code) is not int
        or not 0 <= error_code <= 255
        or type(padding) is not bool
        or (native_cancel is not None and not callable(native_cancel))
        or any(
            type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (busy_retries, pending_responses, wait_ms)
        )
        or type(channel.timeout_ms) is not int
        or not 0 <= channel.timeout_ms <= 0xFFFFFFFF
    ):
        raise ValueError(
            "Bounded native diagnostic request and observed channel timeout required"
        )
    saved_timeout = channel.timeout_ms
    native_error_code = error_code if error_code < 128 else error_code - 256
    busy = 0
    last_payload = b""
    try:
        while True:
            channel._write(request, channel.request)
            channel.wait(wait_ms)
            pending = 0
            while True:
                if native_cancel is not None:
                    cancelled = native_cancel()
                    if type(cancelled) is not bool:
                        raise ValueError(
                            "Native diagnostic cancellation must return BOOL"
                        )
                    if cancelled:
                        # The native callback runs before clearing the response DTO.
                        return last_payload
                frame = channel.read(mode=2, padding=padding)
                payload = frame[len(channel.request) :]
                last_payload = payload
                if len(frame) >= 7 and payload[:2] == b"\x7f" + request[:1]:
                    if len(payload) < 3:
                        raise BodyOperationError(
                            native_error_code,
                            "short diagnostic negative",
                            response=payload,
                            response_size=len(frame),
                        )
                    if payload[2] == 0x78:
                        busy = 0
                        pending += 1
                        if pending > pending_responses:
                            channel._write(b"\x3e", channel.request)
                            raise BodyOperationError(
                                native_error_code,
                                "diagnostic pending limit",
                                response=payload,
                                response_size=len(frame),
                            )
                        if saved_timeout < 5000:
                            channel.set_timeout(5000)
                        continue
                    if payload[2] == 0x21:
                        busy += 1
                        if busy > busy_retries:
                            raise BodyOperationError(
                                native_error_code,
                                "diagnostic busy limit",
                                response=payload,
                                response_size=len(frame),
                            )
                        channel.set_timeout(saved_timeout)
                        break
                channel.set_timeout(saved_timeout)
                if len(frame) < len(channel.request) + minimum_response:
                    raise BodyOperationError(
                        native_error_code,
                        "short diagnostic response",
                        response=payload,
                        response_size=len(frame),
                    )
                if expected and not payload.startswith(expected):
                    raise BodyOperationError(
                        native_error_code,
                        "diagnostic response prefix",
                        response=payload,
                        response_size=len(frame),
                    )
                return payload
    except ExecutableJ2534Error as error:
        # Typed handler45d828 mutates +0c and retains the original driver DWORD.
        error.native_code = native_error_code
        raise
    finally:
        primary = sys.exception()
        cleanup_failure: Exception | None = None
        try:
            channel.set_timeout(saved_timeout, cleanup=True)
        except Exception as cleanup_error:  # noqa: BLE001 - preserve primary failure.
            cleanup_failure = cleanup_error
            if primary is not None:
                primary.add_note(
                    "Native diagnostic timeout restoration failed: "
                    + type(cleanup_error).__name__
                )
        try:
            channel.io.check()
        except (InterruptedError, TimeoutError) as boundary:
            raise boundary from (primary or cleanup_failure)
        if primary is None and cleanup_failure is not None:
            raise cleanup_failure


def convert_seed(seed: bytes, rounds: Sequence[bytes]) -> bytes:
    """45a1b0/45a388: four rotate-half/XOR rounds over the native four-byte seed."""
    if (
        type(seed) is not bytes
        or len(seed) != 4
        or not isinstance(rounds, (tuple, list))
        or len(rounds) != 4
        or any(type(value) is not bytes or len(value) != 2 for value in rounds)
    ):
        raise ValueError(
            "Four-byte seed and four explicit private round operands required"
        )
    for operand in rounds:
        seed = seed[2:] + bytes((seed[0] ^ operand[0], seed[1] ^ operand[1]))
    return seed


def epc_security(channel, *, padding: bool) -> None:
    """58ca64: one-byte seed minus one, with the native 100 ms key delay."""
    response = diagnostic(channel, b"\x27\x01", b"\x67\x01", 3, 16, padding=padding)
    key = bytes(((response[2] - 1) & 0xFF,))
    channel.wait(100)
    diagnostic(channel, b"\x27\x02" + key, b"\x67\x02", 2, 17, padding=padding)


def _original_cpu_location(native) -> bytes:
    from scripts.cuw_legacy_can import original_location_id

    return original_location_id(native.selected.values["locationid"])


def functional_header(context) -> bytes:
    """41448c param4: CPU0 LocationID fourth WORD, CBytes2 then SetNum(4)."""
    from scripts.cuw_legacy_engine import ExecutableContext

    if not isinstance(context, ExecutableContext) or not context.cpus:
        raise ValueError("Imported CPU0 required for native functional header")
    return b"\0\0" + _original_cpu_location(context.cpus[0])[6:8]


def _diagnostic_mask(channel, header: bytes | None) -> None:
    if header is None:
        channel.diagnostic_mask()
        return
    if type(header) is not bytes or len(header) != 4:
        raise ValueError("Native functional mask header must contain four bytes")
    for _ in range(3):
        channel._write(b"\xa0\x27", header)
        channel.wait(100)


def epc_prepare(channel, *, padding: bool, mask_header: bytes | None = None) -> None:
    """58cd28: security, delay100, diagnostic-mask triplet, session1002, delay300.

    Connection/filter acquisition remains in the executable's shared controller
    lifecycle. This function never substitutes a successful provider for an ECU
    response or a recovered algorithm.
    """
    epc_security(channel, padding=padding)
    channel.wait(100)
    _diagnostic_mask(channel, mask_header)
    diagnostic(channel, b"\x10\x02", b"\x50", 1, 18, padding=padding)
    channel.wait(300)


def airbag_seed_key(seed: bytes, password: bytes) -> bytes:
    """567f28/419de8: BE16 password plus complemented BE16 seed, modulo WORD."""
    if any(type(value) is not bytes or len(value) != 2 for value in (seed, password)):
        raise ValueError("Explicit two-byte native seed and private password required")
    value = int.from_bytes(password, "big") + ~int.from_bytes(seed, "big")
    return (value & 0xFFFF).to_bytes(2, "big")


def body_seed_key(seed: bytes, shifts: bytes) -> bytes:
    """56a30c: six sequential rotate/add steps with in-place indexed additions."""
    if (
        type(seed) is not bytes
        or len(seed) != 6
        or type(shifts) is not bytes
        or len(shifts) != 6
    ):
        raise ValueError("Six-byte native seed and six private shift operands required")
    result = bytearray(seed)
    for index, value in enumerate(seed):
        shift = ((value >> (shifts[index] & 31)) & 3) + 1
        source_index = value & 7
        if source_index > 5:
            source_index -= 6
        rotated = ((value >> (8 - shift)) | (value << shift)) & 0xFF
        result[index] = (rotated + result[source_index]) & 0xFF
    return bytes(result)


def airbag_security(
    channel, access_password: bytes, conversion_password: bytes, *, padding: bool
) -> None:
    """567bb8:2703/password2 → seed2/34 → wait100 →2704/key2,670434."""
    if type(access_password) is not bytes or len(access_password) != 2:
        raise ValueError("Explicit two-byte security access password required")
    # Validate both private inputs before making any communication attempt.
    airbag_seed_key(b"\0\0", conversion_password)
    response = diagnostic(
        channel, b"\x27\x03" + access_password, b"\x67\x03", 5, 16, padding=padding
    )
    if response[4] != 0x34:
        raise BodyOperationError(16, "security seed marker")
    key = airbag_seed_key(response[2:4], conversion_password)
    channel.wait(100)
    diagnostic(channel, b"\x27\x04" + key, b"\x67\x04\x34", 3, 17, padding=padding)


def body_security(channel, shifts: bytes, *, padding: bool) -> None:
    """56a404:2761 → six-byte seed → wait100 →2762/key6,676234."""
    body_seed_key(b"\0" * 6, shifts)
    response = diagnostic(channel, b"\x27\x61", b"\x67\x61", 8, 16, padding=padding)
    key = body_seed_key(response[2:8], shifts)
    channel.wait(100)
    diagnostic(channel, b"\x27\x62" + key, b"\x67\x62\x34", 3, 17, padding=padding)


def four_byte_security(
    channel, rounds: Sequence[bytes], *, padding: bool, cpu: int | None = None
) -> None:
    """2701[/CPU] → seed4 → four rounds → wait100 →2702/key4.

    EPB579f28 supplies CPU0; Chassis56dd58 and OldECB582d34 supply
    their selected CPU. FC57c3a8 has no CPU request suffix.
    """
    convert_seed(b"\0" * 4, rounds)
    if cpu is not None and (type(cpu) is not int or not 0 <= cpu <= 255):
        raise ValueError("Native preparation CPU selector must be a byte")
    request = b"\x27\x01" + (b"" if cpu is None else bytes((cpu,)))
    response = diagnostic(channel, request, b"\x67\x01", 6, 16, padding=padding)
    key = convert_seed(response[2:6], rounds)
    channel.wait(100)
    diagnostic(channel, b"\x27\x02" + key, b"\x67\x02", 2, 17, padding=padding)


def sonar_security(
    channel, access_password: bytes, conversion_password: bytes, *, padding: bool
) -> None:
    """56f590 typed catch: retry seed error16 once with reversed access WORD."""
    try:
        airbag_security(channel, access_password, conversion_password, padding=padding)
    except ExecutableCANError as error:
        if error.code != 16:
            raise
        channel.wait(100)
        airbag_security(
            channel, access_password[::-1], conversion_password, padding=padding
        )


def epb_prepare(
    channel, rounds: Sequence[bytes], *, padding: bool, mask_header: bytes | None = None
) -> None:
    """579ad0: selected CPU0 security, wait100, mask triplet, diagnostic session."""
    four_byte_security(channel, rounds, padding=padding, cpu=0)
    channel.wait(100)
    _diagnostic_mask(channel, mask_header)
    diagnostic(channel, b"\x10\x02", b"\x50", 1, 18, padding=padding)


def chassis_prepare_cpu(
    channel,
    rounds: Sequence[bytes],
    cpu: int,
    *,
    padding: bool,
    mask_header: bytes | None = None,
) -> None:
    """56d828: one selected native address/CPU, security100/mask/session."""
    four_byte_security(channel, rounds, padding=padding, cpu=cpu)
    channel.wait(100)
    _diagnostic_mask(channel, mask_header)
    diagnostic(channel, b"\x10\x02", b"\x50", 1, 18, padding=padding)


def old_ecb_prepare_cpu(
    channel,
    rounds: Sequence[bytes],
    cpu: int,
    *,
    first: bool,
    padding: bool,
    mask_header: bytes | None = None,
) -> None:
    """582884: security for each address, mask only for its first CPU, session."""
    if type(first) is not bool:
        raise ValueError("Explicit native first-CPU BOOL required")
    four_byte_security(channel, rounds, padding=padding, cpu=cpu)
    if first:
        _diagnostic_mask(channel, mask_header)
    diagnostic(channel, b"\x10\x02", b"\x50", 1, 18, padding=padding)


def fc_prepare(
    channel,
    rounds: Sequence[bytes],
    *,
    repeat_session: bool,
    padding: bool,
    mask_header: bytes | None = None,
) -> None:
    """57c674: security100/mask/session; 41aa30-selected second session at110ms."""
    if type(repeat_session) is not bool:
        raise ValueError("Source-derived native repeated-session BOOL required")
    four_byte_security(channel, rounds, padding=padding)
    channel.wait(100)
    _diagnostic_mask(channel, mask_header)
    diagnostic(channel, b"\x10\x02", b"\x50", 1, 18, padding=padding)
    if repeat_session:
        channel.wait(110)
        diagnostic(channel, b"\x10\x02", b"\x50", 1, 18, padding=padding)


def body_change_mode(channel, secondary: bool, *, padding: bool) -> None:
    """56bff0/574f28: normal1002/error18 or secondary1060/error49."""
    if type(secondary) is not bool:
        raise ValueError("Explicit native secondary-mode BOOL required")
    diagnostic(
        channel,
        b"\x10\x60" if secondary else b"\x10\x02",
        b"\x50",
        1,
        49 if secondary else 18,
        padding=padding,
    )


def body_mode_switch(io, value: bool) -> None:
    """56c46c/575030: SET_CONFIG, one parameter30 and explicit byte BOOL."""
    from scripts.cuw_legacy_engine import executable_j2534_call

    if type(value) is not bool:
        raise ValueError("Explicit native external-memory switch BOOL required")
    result = executable_j2534_call(
        io,
        "ioctl",
        ioctl_id=2,
        input={"num_params": 1, "config": ((0x1E, int(value)),)},
        output=None,
    )
    if result is not None:
        raise ValueError("Native external-memory SET_CONFIG must return None")


def airbag_prepare(
    channel,
    access_password: bytes,
    conversion_password: bytes,
    *,
    padding: bool,
    mask_header: bytes | None = None,
) -> None:
    """5691d0: security,100ms,mask,session1002,1500ms before filter release."""
    airbag_security(channel, access_password, conversion_password, padding=padding)
    channel.wait(100)
    _diagnostic_mask(channel, mask_header)
    diagnostic(channel, b"\x10\x02", b"\x50", 1, 18, padding=padding)
    channel.wait(1500)


def sonar_prepare(
    channel,
    access_password: bytes,
    conversion_password: bytes,
    *,
    padding: bool,
    mask_header: bytes | None = None,
) -> None:
    """56f590: typed security retry,100ms,mask,session1002,500ms."""
    sonar_security(channel, access_password, conversion_password, padding=padding)
    channel.wait(100)
    _diagnostic_mask(channel, mask_header)
    diagnostic(channel, b"\x10\x02", b"\x50", 1, 18, padding=padding)
    channel.wait(500)


def body_security_session(
    channel, shifts: bytes, secondary: bool, *, padding: bool
) -> None:
    """56bc0c/574638: six-byte security; secondary omits mask and selects1060.

    The native controller orders external-memory switching and the1500ms wait
    differently for Body and DSS1; their callers must perform those outer steps.
    """
    if type(secondary) is not bool:
        raise ValueError("Explicit native secondary-mode BOOL required")
    body_security(channel, shifts, padding=padding)
    channel.wait(100)
    if not secondary:
        channel.diagnostic_mask()
    body_change_mode(channel, secondary, padding=padding)


def dss_primary_security_session(
    channel, access_password: bytes, conversion_password: bytes, *, padding: bool
) -> None:
    """574638: primary two-byte security,100ms,mask,normal mode1002."""
    airbag_security(channel, access_password, conversion_password, padding=padding)
    channel.wait(100)
    channel.diagnostic_mask()
    body_change_mode(channel, False, padding=padding)


def epc_write_cpu(context, channel, progress) -> None:
    """58c144/540b78 transfer body after native preparation/filter acquisition.

    The caller establishes timeout5000 before acquiring the native filter and
    retains ownership and outer exception/reconnect/completion callbacks. This
    is not the complete Execute entry.
    """
    from scripts.cuw_legacy_can import CANProgress, CommonCAN, location_headers
    from scripts.cuw_legacy_engine import (
        ExecutableContext,
        executable_cpu_type,
        executable_new_password,
        executable_selected_password,
        executable_sync,
    )

    if (
        not isinstance(context, ExecutableContext)
        or context.controller != "CCanElectricPowerControlFlashWriter"
        or not isinstance(channel, CommonCAN)
        or not isinstance(progress, CANProgress)
        or context.native.image is None
        or channel.timeout_ms != 5000
    ):
        raise ValueError("Imported EPC context, image and concrete native CAN required")
    if (channel.request, channel.response) != location_headers(
        _original_cpu_location(context.native)
    ):
        raise ValueError("EPC channel headers differ from imported LocationID")
    cpu_type = executable_cpu_type(context)
    tables = BodyTables(context)
    sizes = tables.sizes("epc", cpu_type)
    image = context.native.image.data
    if not sizes or sum(sizes) > len(image):
        raise ValueError("Native EPC block geometry exceeds imported image")
    cpu_index = context.native.selected.index
    if (
        progress.io is not channel.io
        or cpu_index >= len(progress.image_sizes)
        or progress.image_sizes[cpu_index] != len(image)
    ):
        raise ValueError("EPC CPU, runtime and progress image binding must agree")
    start = 0
    for size in sizes:
        if start + max(1024, ((size + 1023) // 1024) * 1024) > len(image):
            raise ValueError("Native EPC transfer would read beyond imported image")
        start += size
    if context.state.use_new_software_password:
        password = executable_new_password(context.native)
    else:
        password = executable_selected_password(context)
    channel.check_id(
        _original_cpu_location(context.native),
        password,
        swap_endian=False,
        first_timeout_ms=0,
        interframe_ms=3,
    )
    channel.wait(3)
    memory = epb_memory(channel)
    if not tables.epc_cpu_matches(cpu_type, memory.firmware_descriptor):
        raise BodyOperationError(10, "EPC CPU identification")
    if memory.address + sum(sizes[:-1]) > 0xFFFFFF:
        raise ValueError("Native EPC final block address exceeds three bytes")
    for block in range(1, len(sizes) + 1):
        if block == len(sizes):
            context.state.native_flag_ed6 = True
        context.state.native_flag_ed8 = True
        epc_erase(channel, block)
        epc_write(
            channel, image, sizes, block, memory.address, cpu_index, progress.account
        )
        epc_inverify(channel, block)
        epc_verify(channel, image, sizes, block, cpu_index, progress.account)
    channel.finish(acknowledge=True, request_header=functional_header(context))
    channel.wait(1000)
    context.state.native_flag_ed8 = False
    context.state.native_flag_ed6 = False
    executable_sync(channel.io, "flag_88", value=False)


def epc_reset_progress(progress, cpu_index: int) -> None:
    """58d228: clear one CPU count, publish, clear its percentage, publish."""
    from scripts.cuw_legacy_can import CANProgress

    if (
        not isinstance(progress, CANProgress)
        or type(cpu_index) is not int
        or not 0 <= cpu_index < len(progress.counts)
    ):
        raise ValueError("Native EPC progress and selected CPU index required")
    progress.counts[cpu_index] = 0
    progress.publish_counts()
    progress.percentages[cpu_index] = 0
    progress.publish_percentages()


class EPCController:
    """Original18 58c144 /12 540b78, including both typed native phase scopes."""

    controller_name = "CCanElectricPowerControlFlashWriter"

    def __init__(self, context, io):
        from scripts.cuw_legacy_addresses import (
            legacy_address_inputs,
        )
        from scripts.cuw_legacy_can import CANProgress, CommonCAN, location_headers
        from scripts.cuw_legacy_channel import channel_state
        from scripts.cuw_legacy_engine import (
            ExecutableContext,
            ExecutableImage,
            ExecutableIO,
            executable_constructor_timeout,
        )

        if (
            not isinstance(context, ExecutableContext)
            or context.controller != self.controller_name
            or not isinstance(io, ExecutableIO)
            or context.native.image is None
        ):
            raise ValueError(
                "Imported native body controller, selected image and runtime required"
            )
        self.context, self.io = context, io
        self.mask_header = functional_header(context)
        self.source = ExecutableImage(context)
        self.saved_timeout = executable_constructor_timeout(context)
        kind, config, mode, factory = legacy_address_inputs(context)
        addresses = self.select_prepare_addresses(context, kind, config, mode, factory)
        if not addresses:
            raise ValueError("Native EPC preparation requires its first address row")
        self.prepare_addresses = addresses
        address = addresses[0]
        state = channel_state(context)
        self.prepare_channel = CommonCAN.from_io(
            io, address.request_header, address.response_header, state=state
        )
        tx, rx = location_headers(_original_cpu_location(context.native))
        self.channel = CommonCAN(
            io,
            tx,
            rx,
            padding=self.prepare_channel.padding,
            read_timeout_ms=self.prepare_channel.timeout_ms,
            send_timeout_ms=self.prepare_channel.send_timeout_ms,
            state=state,
        )
        entry_timeout = self.channel.timeout_ms
        if type(entry_timeout) is not int:
            raise ValueError("Native EPC entry timeout DWORD required")
        self.entry_timeout: int = entry_timeout
        sizes = tuple(
            len(cpu.image.data) if cpu.image is not None else 0 for cpu in context.cpus
        )
        self.progress = CANProgress(io, sizes)
        self.value_78 = self.value_80 = 0
        self.flag_68 = False
        self.status_70 = self.status(0)

    def select_prepare_addresses(self, context, kind, config, mode, factory):
        from scripts.cuw_legacy_addresses import select_legacy_addresses

        return select_legacy_addresses(
            context, kind, config, reprog_mode=mode, factory_state=factory
        )

    def status(self, index):
        base = 0x5F1A48 if self.context.build == 18 else 0x59A7F0
        return int.from_bytes(self.source.read(base + index * 4, 4), "little")

    def capture(self, error):
        from scripts.cuw_legacy_engine import ExecutableJ2534Error

        self.value_78 = error.native_code & 0xFFFFFFFF
        if isinstance(error, ExecutableJ2534Error):
            self.value_80 = error.driver_status

    def stop_filter(self, handle):
        from scripts.cuw_legacy_engine import (
            ExecutableNativeError,
            executable_stop_filter,
        )

        if handle is not None:
            try:
                executable_stop_filter(self.io, handle)
            except (ExecutableNativeError, ExecutableCANError):
                # 58d02d/58c926 ignore native stop faults, retaining host ownership.
                pass

    def prepare(self):
        from scripts.cuw_legacy_engine import (
            ExecutableJ2534Error,
            executable_start_filter,
        )

        handle = None
        caught = False
        try:
            handle = executable_start_filter(
                self.io,
                self.prepare_channel.request,
                self.prepare_channel.response,
                padding=self.prepare_channel.padding,
            )
            epc_prepare(
                self.prepare_channel,
                padding=self.prepare_channel.padding,
                mask_header=self.mask_header,
            )
        except (ExecutableJ2534Error, ExecutableCANError) as error:
            self.capture(error)
            caught = True
        self.stop_filter(handle)
        return caught

    def error_handler(self):
        from scripts.cuw_legacy_engine import (
            ExecutableJ2534Error,
            executable_reconnect,
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
                executable_reconnect(self.context, self.io, 6)
            except ExecutableJ2534Error as error:
                # 58d1d7 native reconnect catch selects the connection status.
                self.capture(error)
                self.status_70 = self.status(3)
                continue
            return

    def run(self):
        from scripts.cuw_legacy_engine import (
            ExecutableJ2534Error,
            apply_recovery_password_state,
            executable_start_filter,
            executable_sync,
        )

        native_success = False
        aborted = None
        cleanup_errors = []
        try:
            caught = self.prepare()
            if not caught or self.context.state.native_flag_ed8:
                caught = False
                handle = None
                try:
                    self.channel.set_timeout(5000)
                    handle = executable_start_filter(
                        self.io,
                        self.channel.request,
                        self.channel.response,
                        padding=self.channel.padding,
                    )
                    epc_write_cpu(self.context, self.channel, self.progress)
                    native_success = True
                except (ExecutableJ2534Error, ExecutableCANError) as error:
                    self.capture(error)
                    epc_reset_progress(
                        self.progress, self.context.native.selected.index
                    )
                    caught = True
                self.stop_filter(handle)
            if caught:
                self.status_70 = self.status(
                    2 if self.context.state.native_flag_ed8 else 1
                )
                apply_recovery_password_state(
                    self.context,
                    self.io,
                    self.context.state.native_flag_ed6,
                    self.value_78,
                    persist=self.context.state.recovery_persistence_active,
                )
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
                self.channel.set_timeout(self.entry_timeout, cleanup=True)
            except Exception as cleanup_error:  # noqa: BLE001 - retain host abort
                error.add_note(
                    "EPC abort timeout restoration failed: "
                    + type(cleanup_error).__name__
                )
            raise
        finally:
            cleanup_errors = self.io.close()
            if aborted is not None:
                for error in cleanup_errors:
                    aborted.add_note("EPC host cleanup failed: " + error)
        return {
            "controller": self.context.controller,
            "build": self.context.build,
            "source_entry": "0x58c144" if self.context.build == 18 else "0x540b78",
            "success": native_success and not cleanup_errors,
            "native_success": native_success,
            "native_flag_68": self.flag_68,
            "native_value_78": self.value_78,
            "native_value_80": self.value_80,
            "host_cleanup_errors": cleanup_errors,
        }


def epb_write_cpu(context, channel, progress):
    """579418..57981b/52fac0: narrow EPB ID/memory, erase/write/verify, finish80."""
    from scripts.cuw_legacy_can import (
        CANProgress,
        CommonCAN,
        calc_block_sizes,
        location_headers,
    )
    from scripts.cuw_legacy_engine import (
        ExecutableContext,
        executable_cpu_type,
        executable_selected_password,
        executable_sync,
    )

    if (
        not isinstance(context, ExecutableContext)
        or context.controller != "CCanEPBFlashWriter"
        or not isinstance(channel, CommonCAN)
        or not isinstance(progress, CANProgress)
        or context.native.image is None
        or channel.timeout_ms not in (10000, 120000)
        or (channel.request, channel.response)
        != location_headers(_original_cpu_location(context.native))
        or progress.io is not channel.io
    ):
        raise ValueError("Imported EPB image, CPU index and concrete channel required")
    cpu_index = context.native.selected.index
    image = context.native.image.data
    if cpu_index >= len(progress.image_sizes) or progress.image_sizes[cpu_index] != len(
        image
    ):
        raise ValueError("EPB progress image binding differs from selected CPU")
    password = executable_selected_password(context)
    channel.wait(500)
    channel.check_id(
        _original_cpu_location(context.native),
        password,
        swap_endian=False,
        first_timeout_ms=0,
    )
    memory = epb_memory(channel)
    cpu_type = executable_cpu_type(context)
    if not BodyTables(context).identified(
        "epb", cpu_type, memory.firmware_descriptor, False
    ):
        raise BodyOperationError(10, "EPB CPU identification")
    sizes = calc_block_sizes(cpu_type, memory)
    start = 0
    if not sizes or len(sizes) > 256:
        raise ValueError("Native EPB geometry must fit the block byte")
    for size in sizes:
        if (
            start + max(1024, ((size + 1023) // 1024) * 1024) > len(image)
            or memory.address + start > 0xFFFFFF
        ):
            raise ValueError("Native EPB transfer would read beyond selected image")
        start += size
    for block in range(1, len(sizes) + 1):
        epb_erase(channel, block)
        epb_write(
            channel, image, sizes, block, memory.address, cpu_index, progress.account
        )
        epb_verify(channel, image, sizes, block, cpu_index, progress.account)
    channel.finish(acknowledge=False, request_header=functional_header(context))
    executable_sync(channel.io, "flag_88", value=False)


class EPBController(EPCController):
    """Original18 5792b4 /12 52fac0; EPB never sets the EPC writing latches."""

    controller_name = "CCanEPBFlashWriter"

    def prepare(self):
        from scripts.cuw_legacy_engine import (
            ExecutableJ2534Error,
            executable_start_filter,
        )

        rounds = BodyTables(self.context).four_round_operands("epb")
        handle = None
        caught = False
        try:
            handle = executable_start_filter(
                self.io,
                self.prepare_channel.request,
                self.prepare_channel.response,
                padding=self.prepare_channel.padding,
            )
            epb_prepare(
                self.prepare_channel,
                rounds,
                padding=self.prepare_channel.padding,
                mask_header=self.mask_header,
            )
        except (ExecutableJ2534Error, ExecutableCANError) as error:
            self.capture(error)
            self.status_70 = self.status(1)
            caught = True
        self.stop_filter(handle)
        return caught

    def run(self):
        from scripts.cuw_legacy_engine import (
            ExecutableJ2534Error,
            executable_start_filter,
            executable_sync,
        )

        native_success = False
        aborted = None
        cleanup_errors = []
        try:
            caught = self.prepare()
            if not caught:
                # 579318 snapshots after preparation; constructor snapshot covers its failure.
                current_timeout = self.channel.timeout_ms
                if (
                    type(current_timeout) is not int
                    or not 0 <= current_timeout <= 0xFFFFFFFF
                ):
                    raise ValueError("EPB post-preparation timeout DWORD required")
                self.saved_timeout = current_timeout
                mode = self.context.observations.get("legacy_reprog_mode", False)
                if type(mode) is not bool:
                    raise ValueError("Native process-global reprog-mode BOOL required")
                self.channel.set_timeout(10000 if mode else 120000)
                handle = None
                try:
                    handle = executable_start_filter(
                        self.io,
                        self.channel.request,
                        self.channel.response,
                        padding=self.channel.padding,
                    )
                    epb_write_cpu(self.context, self.channel, self.progress)
                    native_success = True
                except (ExecutableJ2534Error, ExecutableCANError) as error:
                    self.capture(error)
                    self.status_70 = self.status(2)
                    index = self.context.native.selected.index
                    # 5798ac/579913 clear cached arrays without the EPC notifications.
                    self.progress.counts[index] = self.progress.percentages[index] = 0
                    caught = True
                self.stop_filter(handle)
            if caught:
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
                self.channel.set_timeout(self.entry_timeout, cleanup=True)
            except Exception as cleanup_error:  # noqa: BLE001 - retain host abort
                error.add_note(
                    "EPB abort timeout restoration failed: "
                    + type(cleanup_error).__name__
                )
            raise
        finally:
            cleanup_errors = self.io.close()
            if aborted is not None:
                for error in cleanup_errors:
                    aborted.add_note("EPB host cleanup failed: " + error)
        return {
            "controller": self.context.controller,
            "build": self.context.build,
            "source_entry": "0x5792b4" if self.context.build == 18 else "0x52fac0",
            "success": native_success and not cleanup_errors,
            "native_success": native_success,
            "native_flag_68": self.flag_68,
            "native_value_78": self.value_78,
            "native_value_80": self.value_80,
            "host_cleanup_errors": cleanup_errors,
        }


class ChassisController(EPCController):
    """56c748/524994: complete multi-CPU grouped chassis Execute."""

    controller_name = "CCanChassisShrinkFlashWriter"

    def prepare(self):
        from scripts.cuw_legacy_engine import (
            ExecutableJ2534Error,
            executable_cpu_type,
            executable_start_filter,
        )

        tables = BodyTables(self.context)
        kind = self.context.native.base_metadata["kind_of_ecu"]
        selectors = tables.preparation_cpu_selectors(
            "chassis", kind, len(self.prepare_addresses)
        )
        rounds = tables.four_round_operands(
            "chassis", executable_cpu_type(self.context, 0)
        )
        handle = None
        caught = False
        try:
            handle = executable_start_filter(
                self.io,
                self.prepare_channel.request,
                self.prepare_channel.response,
                padding=self.prepare_channel.padding,
            )
            for cpu in selectors:
                chassis_prepare_cpu(
                    self.prepare_channel,
                    rounds,
                    cpu,
                    padding=self.prepare_channel.padding,
                    mask_header=self.mask_header,
                )
        except (ExecutableJ2534Error, ExecutableCANError) as error:
            self.capture(error)
            self.status_70 = self.status(1)
            caught = True
        self.stop_filter(handle)
        return caught

    def channel_for_cpu(self, native):
        from scripts.cuw_legacy_can import CommonCAN, location_headers
        from scripts.cuw_legacy_channel import channel_state

        if native.image is None:
            raise ValueError("Imported chassis CPU image and LocationID required")
        state = channel_state(self.context)
        request, response = location_headers(_original_cpu_location(native))
        return CommonCAN(self.io, request, response, padding=state.padding, state=state)

    def transfer_cpu(self, native):
        from dataclasses import replace

        from scripts.cuw_legacy_can import calc_block_sizes
        from scripts.cuw_legacy_engine import (
            executable_cpu_type,
            executable_new_password,
            executable_selected_password,
        )

        context = self.context
        cpu_index = native.selected.index
        cpu_type = executable_cpu_type(context, cpu_index)
        tables = BodyTables(context)
        channel = self.channel
        image = native.image.data
        if context.state.use_new_software_password:
            password = executable_new_password(replace(context, native=native))
        else:
            password = executable_selected_password(context, native.selected.index)
        # 56cc67..56cfab compare the original ten native CPU string pointers.
        globals_ = (
            0x5D4FB4,
            0x5D4FB8,
            0x5D4FBC,
            0x5D4FD0,
            0x5D4FE4,
            0x5D4FE8,
            0x5D4FEC,
            0x5D4FF0,
            0x5D5000,
            0x5D5004,
        )
        atomic = cpu_type in tuple(
            tables._name(value if context.build == 18 else value - 0x4FD1C)
            for value in globals_
        )
        mode = context.observations.get("legacy_reprog_mode", False)
        if type(mode) is not bool:
            raise ValueError("Native process-global reprog-mode BOOL required")
        channel.wait(500)
        channel.check_id(
            _original_cpu_location(native),
            password,
            first_timeout_ms=10000 if mode else 80000,
            interframe_ms=None if atomic else 3,
        )
        channel.wait(3)
        memory = channel.memory(wide=False)
        if not tables.identified(
            "chassis", cpu_type, memory.firmware_descriptor, False
        ):
            raise BodyOperationError(10, "chassis CPU identification")
        sizes = calc_block_sizes(cpu_type, memory)
        ranges = tables.ranges("chassis", cpu_type, len(sizes))
        if ranges[0][0] != 1:
            sizes = (0,) * (ranges[0][0] - 1) + sizes
        plans = []
        for first, last in ranges:
            offset = sum(sizes[: first - 1])
            length = sum(sizes[first - 1 : last])
            if (
                not 0 < length <= len(image) - offset
                or length % 1024
                or memory.address + offset > 0xFFFFFF
            ):
                raise ValueError("Native chassis grouped copy exceeds imported image")
            plans.append((first, last, offset, length))
        for index, (first, last, offset, length) in enumerate(plans):
            self.end_block = index + 1 == len(plans)
            part = image[offset : offset + length]
            channel.erase(first, last)
            channel.write_block(
                memory.address + offset,
                part,
                initial_wait_ms=3,
                progress=lambda size: self.progress.account(cpu_index, size),
            )
            channel.inverify(first, last)
            channel.verify(
                first,
                last,
                part,
                progress=lambda size: self.progress.account(cpu_index, size),
            )
        context.state.use_new_software_password = False

    def run(self):
        from scripts.cuw_legacy_engine import (
            ExecutableJ2534Error,
            apply_recovery_password_state,
            executable_start_filter,
            executable_sync,
        )

        success = False
        completed = []
        aborted = None
        cleanup_errors = []
        self.end_block = False
        try:
            caught = self.prepare()
            if not caught:
                current_timeout = self.channel.timeout_ms
                if type(current_timeout) is not int:
                    raise ValueError("Native chassis channel timeout DWORD required")
                self.saved_timeout = current_timeout
                cpus = tuple(
                    cpu
                    for cpu in self.context.cpus
                    if cpu.selected.index >= self.context.native.selected.index
                )
                for position, native in enumerate(cpus):
                    self.channel = self.channel_for_cpu(native)
                    self.channel.set_timeout(3000)
                    handle = None
                    try:
                        handle = executable_start_filter(
                            self.io,
                            self.channel.request,
                            self.channel.response,
                            padding=self.channel.padding,
                        )
                        self.transfer_cpu(native)
                        if position + 1 < len(cpus):
                            self.channel.change_cpu()
                            executable_sync(self.io, "completion", outcome="success")
                        else:
                            self.channel.finish(
                                acknowledge=False, request_header=self.mask_header
                            )
                            executable_sync(self.io, "flag_88", value=False)
                        completed.append(native.selected.index)
                    except (ExecutableJ2534Error, ExecutableCANError) as error:
                        self.capture(error)
                        self.status_70 = self.status(2)
                        index = native.selected.index
                        self.progress.counts[index] = self.progress.percentages[
                            index
                        ] = 0
                        caught = True
                    self.stop_filter(handle)
                    if caught:
                        break
                success = not caught
            if caught:
                apply_recovery_password_state(
                    self.context,
                    self.io,
                    self.end_block,
                    self.value_78,
                    persist=self.context.state.recovery_persistence_active,
                )
                self.error_handler()
            self.channel.set_timeout(self.saved_timeout)
            executable_sync(self.io, "flag_68", value=self.flag_68)
            executable_sync(
                self.io, "values_78_80", value_78=self.value_78, value_80=self.value_80
            )
            executable_sync(self.io, "owner_clear")
            executable_sync(
                self.io, "completion", outcome="success" if success else "failure"
            )
        except (InterruptedError, TimeoutError) as error:
            aborted = error
            try:
                self.channel.set_timeout(self.entry_timeout, cleanup=True)
            except Exception as cleanup_error:  # noqa: BLE001 - preserve host boundary
                error.add_note(
                    "Chassis abort timeout restoration failed: "
                    + type(cleanup_error).__name__
                )
            raise
        finally:
            cleanup_errors = self.io.close()
            if aborted is not None:
                for error in cleanup_errors:
                    aborted.add_note("Chassis host cleanup failed: " + error)
        return {
            "controller": self.context.controller,
            "build": self.context.build,
            "source_entry": "0x56c748" if self.context.build == 18 else "0x524994",
            "success": success and not cleanup_errors,
            "native_success": success,
            "completed_cpu_indices": completed,
            "native_flag_68": self.flag_68,
            "native_value_78": self.value_78,
            "native_value_80": self.value_80,
            "host_cleanup_errors": cleanup_errors,
        }


class OldECBController(ChassisController):
    """581aac/5374c4: local range retry survives native reconnect, never a saved cursor."""

    controller_name = "CCanOldSpecECBFlashWriter"

    def prepare(self):
        from scripts.cuw_legacy_engine import (
            ExecutableJ2534Error,
            executable_start_filter,
        )

        tables = BodyTables(self.context)
        kind = self.context.native.base_metadata["kind_of_ecu"]
        selectors = tables.preparation_cpu_selectors(
            "old_ecb", kind, len(self.prepare_addresses)
        )
        rounds = tables.four_round_operands("old_ecb")
        handle = None
        caught = False
        try:
            handle = executable_start_filter(
                self.io,
                self.prepare_channel.request,
                self.prepare_channel.response,
                padding=self.prepare_channel.padding,
            )
            for index, cpu in enumerate(selectors):
                old_ecb_prepare_cpu(
                    self.prepare_channel,
                    rounds,
                    cpu,
                    first=index == 0,
                    padding=self.prepare_channel.padding,
                    mask_header=self.mask_header,
                )
        except (ExecutableJ2534Error, ExecutableCANError) as error:
            self.capture(error)
            self.status_70 = self.status(1)
            caught = True
        self.stop_filter(handle)
        return caught

    def transfer_cpu(self, native):
        from dataclasses import replace

        from scripts.cuw_legacy_can import calc_block_sizes
        from scripts.cuw_legacy_engine import (
            executable_cpu_type,
            executable_new_password,
            executable_selected_password,
        )

        context = self.context
        cpu_index = native.selected.index
        cpu_type = executable_cpu_type(context, cpu_index)
        channel = self.channel
        image = native.image.data
        if context.state.use_new_software_password:
            password = executable_new_password(replace(context, native=native))
        else:
            password = executable_selected_password(context, native.selected.index)
        channel.wait(500)
        channel.check_id(_original_cpu_location(native), password)
        memory = channel.memory(wide=False)
        tables = BodyTables(context)
        if not tables.identified(
            "old_ecb", cpu_type, memory.firmware_descriptor, False
        ):
            raise BodyOperationError(10, "old ECB CPU identification")
        self.block_sizes = calc_block_sizes(cpu_type, memory)
        self.block_ranges = tables.ranges("old_ecb", cpu_type, len(self.block_sizes))
        plans = []
        for first, last in self.block_ranges:
            offset = sum(self.block_sizes[: first - 1])
            length = sum(self.block_sizes[first - 1 : last])
            if (
                not 0 < length <= len(image) - offset
                or length % 1024
                or memory.address + offset > 0xFFFFFF
            ):
                raise ValueError("Native old ECB grouped copy exceeds imported image")
            plans.append((first, last, offset, length))
        for range_index in range(self.range_start, len(plans)):
            self.range_index = range_index
            first, last, offset, length = plans[range_index]
            self.end_block = self.range_index + 1 == len(plans)
            part = image[offset : offset + length]
            channel.erase(first, last)
            channel.write_block(
                memory.address + offset,
                part,
                progress=lambda size: self.progress.account(cpu_index, size),
            )
            channel.inverify(first, last)
            channel.verify(
                first,
                last,
                part,
                progress=lambda size: self.progress.account(cpu_index, size),
            )
        self.range_index = len(plans)
        self.range_start = 0
        context.state.use_new_software_password = False

    def restore_progress(self, native):
        """5831dc: previous range only, doubled count and literal x87 *2*100."""
        index = native.selected.index
        count = 0
        if self.range_index:
            if self.range_index > len(self.block_ranges) or not self.block_sizes:
                raise ValueError("Native old ECB range progress inputs are absent")
            first, last = self.block_ranges[self.range_index - 1]
            count = ((last - first + 1) * self.block_sizes[0] * 2) & 0xFFFFFFFF
        self.progress.counts[index] = count
        self.progress.publish_counts()
        # The original multiplication is surprising but is not division by two.
        self.progress.percentages[index] = (
            int(count / len(native.image.data) * 2 * 100) & 0xFFFFFFFF
        )
        self.progress.publish_percentages()

    def restart_write(self):
        from scripts.cuw_legacy_engine import (
            executable_start_filter,
            executable_stop_filter,
        )

        self.channel.set_timeout(120000)
        handle = executable_start_filter(
            self.io,
            self.channel.request,
            self.channel.response,
            padding=self.channel.padding,
        )
        try:
            self.channel.command(b"\x05", error_code=20)
            self.channel.command(b"\x65", error_code=20)
        finally:
            executable_stop_filter(self.io, handle)

    def run(self):
        from scripts.cuw_legacy_engine import (
            ExecutableJ2534Error,
            ExecutableNativeError,
            apply_recovery_password_state,
            executable_start_filter,
            executable_sync,
        )

        success = False
        completed = []
        aborted = None
        cleanup_errors = []
        self.end_block = False
        self.range_start = self.range_index = 0
        self.block_sizes = self.block_ranges = ()
        try:
            self.channel.wait(2000)
            caught = self.prepare()
            if caught:
                self.error_handler()
            else:
                current_timeout = self.channel.timeout_ms
                if type(current_timeout) is not int:
                    raise ValueError("Native old ECB channel timeout DWORD required")
                self.saved_timeout = current_timeout
                cpus = tuple(
                    cpu
                    for cpu in self.context.cpus
                    if cpu.selected.index >= self.context.native.selected.index
                )
                for position, native in enumerate(cpus):
                    while True:
                        caught = False
                        self.channel = self.channel_for_cpu(native)
                        self.channel.set_timeout(120000)
                        handle = None
                        try:
                            handle = executable_start_filter(
                                self.io,
                                self.channel.request,
                                self.channel.response,
                                padding=self.channel.padding,
                            )
                            self.transfer_cpu(native)
                            if position + 1 < len(cpus):
                                self.channel.change_cpu()
                                executable_sync(
                                    self.io, "completion", outcome="success"
                                )
                            else:
                                self.channel.finish(
                                    acknowledge=False, request_header=self.mask_header
                                )
                                executable_sync(self.io, "flag_88", value=False)
                            completed.append(native.selected.index)
                        except (ExecutableJ2534Error, ExecutableCANError) as error:
                            self.capture(error)
                            self.status_70 = self.status(2)
                            self.restore_progress(native)
                            caught = True
                        self.stop_filter(handle)
                        if not caught:
                            break
                        while True:
                            apply_recovery_password_state(
                                self.context,
                                self.io,
                                self.end_block,
                                self.value_78,
                                persist=self.context.state.recovery_persistence_active,
                            )
                            self.error_handler()
                            if self.flag_68:
                                break
                            try:
                                self.restart_write()
                            except ExecutableNativeError:
                                # 58248e changes status only; the previous error fields stay.
                                self.status_70 = self.status(3)
                                continue
                            break
                        if self.flag_68:
                            break
                        self.range_start = self.range_index
                    if caught:
                        break
                success = not caught
            self.channel.set_timeout(self.saved_timeout)
            executable_sync(self.io, "flag_68", value=self.flag_68)
            executable_sync(
                self.io, "values_78_80", value_78=self.value_78, value_80=self.value_80
            )
            executable_sync(self.io, "owner_clear")
            executable_sync(
                self.io, "completion", outcome="success" if success else "failure"
            )
        except (InterruptedError, TimeoutError) as error:
            aborted = error
            try:
                self.channel.set_timeout(self.entry_timeout, cleanup=True)
            except Exception as cleanup_error:  # noqa: BLE001 - preserve host boundary
                error.add_note(
                    "Old ECB abort timeout restoration failed: "
                    + type(cleanup_error).__name__
                )
            raise
        finally:
            cleanup_errors = self.io.close()
            if aborted is not None:
                for error in cleanup_errors:
                    aborted.add_note("Old ECB host cleanup failed: " + error)
        return {
            "controller": self.context.controller,
            "build": self.context.build,
            "source_entry": "0x581aac" if self.context.build == 18 else "0x5374c4",
            "success": success and not cleanup_errors,
            "native_success": success,
            "completed_cpu_indices": completed,
            "native_flag_68": self.flag_68,
            "native_value_78": self.value_78,
            "native_value_80": self.value_80,
            "host_cleanup_errors": cleanup_errors,
        }


class SonarController(ChassisController):
    """56eb48/52690c: CPU0, ten-ms frames, manager end latch and both timeouts."""

    controller_name = "CCanClearanceSonarFlashWriter"

    def __init__(self, context, io):
        from scripts.cuw_legacy_engine import executable_constructor_send_timeout

        super().__init__(context, io)
        self.saved_send_timeout = executable_constructor_send_timeout(context)
        entry_send_timeout = self.channel.send_timeout_ms
        if type(entry_send_timeout) is not int:
            raise ValueError("Native sonar entry send-timeout DWORD required")
        self.entry_send_timeout: int = entry_send_timeout

    def prepare(self):
        from scripts.cuw_legacy_engine import (
            ExecutableJ2534Error,
            executable_start_filter,
        )

        access, conversion = BodyTables(self.context).sonar_passwords()
        handle = None
        caught = False
        try:
            handle = executable_start_filter(
                self.io,
                self.prepare_channel.request,
                self.prepare_channel.response,
                padding=self.prepare_channel.padding,
            )
            sonar_prepare(
                self.prepare_channel,
                access,
                conversion,
                padding=self.prepare_channel.padding,
                mask_header=self.mask_header,
            )
        except (ExecutableJ2534Error, ExecutableCANError) as error:
            self.capture(error)
            self.status_70 = self.status(1)
            caught = True
        self.stop_filter(handle)
        return caught

    def transfer_cpu(self, native):
        from dataclasses import replace

        from scripts.cuw_legacy_can import calc_block_sizes
        from scripts.cuw_legacy_engine import (
            executable_cpu_type,
            executable_new_password,
            executable_selected_password,
        )

        context = self.context
        cpu_type = executable_cpu_type(context, 0)
        channel = self.channel
        image = native.image.data
        if context.state.use_new_software_password:
            password = executable_new_password(replace(context, native=native))
        else:
            password = executable_selected_password(context, native.selected.index)
        tables = BodyTables(context)
        descriptor = tables.sonar_cpu(cpu_type)
        swap = False if descriptor is None else descriptor[1]
        mode = context.observations.get("legacy_reprog_mode", False)
        if type(mode) is not bool:
            raise ValueError("Native process-global reprog-mode BOOL required")
        channel.wait(500)
        channel.check_id(
            _original_cpu_location(native),
            password,
            swap_endian=swap,
            first_timeout_ms=10000 if mode else 80000,
            interframe_ms=10,
        )
        channel.wait(10)
        memory = channel.memory(wide=False)
        if descriptor is None or descriptor[0] != memory.firmware_descriptor & 0x7F:
            raise BodyOperationError(10, "sonar CPU identification")
        sizes = calc_block_sizes(cpu_type, memory)
        ranges = tables.ranges("sonar", cpu_type, len(sizes))
        plans = []
        for first, last in ranges:
            offset = sum(sizes[: first - 1])
            length = sum(sizes[first - 1 : last])
            if (
                not 0 < length <= len(image) - offset
                or length % 1024
                or memory.address + offset > 0xFFFFFF
            ):
                raise ValueError("Native sonar grouped copy exceeds imported image")
            plans.append((first, last, offset, length))
        for index, (first, last, offset, length) in enumerate(plans):
            if index:
                context.state.native_flag_ed5 = True
            part = image[offset : offset + length]
            channel.erase(first, last)
            channel.write_block(
                memory.address + offset,
                part,
                initial_wait_ms=10,
                progress=lambda size: self.progress.account(0, size),
            )
            channel.inverify(first, last)
            channel.verify(
                first, last, part, progress=lambda size: self.progress.account(0, size)
            )
        context.state.use_new_software_password = False

    def run(self):
        from scripts.cuw_legacy_engine import (
            ExecutableJ2534Error,
            apply_recovery_password_state,
            executable_start_filter,
            executable_sync,
        )

        success = False
        aborted = None
        cleanup_errors = []
        try:
            caught = self.prepare()
            if not caught:
                native = self.context.cpus[0]
                self.channel = self.channel_for_cpu(native)
                self.channel.set_timeout(3000)
                self.channel.set_send_timeout(10000)
                handle = None
                try:
                    handle = executable_start_filter(
                        self.io,
                        self.channel.request,
                        self.channel.response,
                        padding=self.channel.padding,
                    )
                    self.transfer_cpu(native)
                    self.channel.finish(
                        acknowledge=True, request_header=self.mask_header
                    )
                    executable_sync(self.io, "flag_88", value=False)
                    success = True
                except (ExecutableJ2534Error, ExecutableCANError) as error:
                    self.capture(error)
                    self.status_70 = self.status(2)
                    self.progress.counts[0] = self.progress.percentages[0] = 0
                    caught = True
                self.stop_filter(handle)
            if caught:
                apply_recovery_password_state(
                    self.context,
                    self.io,
                    self.context.state.native_flag_ed5,
                    self.value_78,
                    persist=self.context.state.recovery_persistence_active,
                )
                self.error_handler()
            self.channel.set_timeout(self.saved_timeout)
            self.channel.set_send_timeout(self.saved_send_timeout)
            executable_sync(self.io, "flag_68", value=self.flag_68)
            executable_sync(
                self.io, "values_78_80", value_78=self.value_78, value_80=self.value_80
            )
            executable_sync(self.io, "owner_clear")
            executable_sync(
                self.io, "completion", outcome="success" if success else "failure"
            )
        except (InterruptedError, TimeoutError) as error:
            aborted = error
            try:
                self.channel.set_timeout(self.entry_timeout, cleanup=True)
                self.channel.set_send_timeout(self.entry_send_timeout, cleanup=True)
            except Exception as cleanup_error:  # noqa: BLE001 - preserve host boundary
                error.add_note(
                    "Sonar abort timeout restoration failed: "
                    + type(cleanup_error).__name__
                )
            raise
        finally:
            cleanup_errors = self.io.close()
            if aborted is not None:
                for error in cleanup_errors:
                    aborted.add_note("Sonar host cleanup failed: " + error)
        return {
            "controller": self.context.controller,
            "build": self.context.build,
            "source_entry": "0x56eb48" if self.context.build == 18 else "0x52690c",
            "success": success and not cleanup_errors,
            "native_success": success,
            "native_flag_68": self.flag_68,
            "native_value_78": self.value_78,
            "native_value_80": self.value_80,
            "host_cleanup_errors": cleanup_errors,
        }


def _source_header(source, address):
    """Construct a native four-byte CBytes value from its admitted ASCII literal."""
    raw = source.read(address, 32).split(b"\0", 1)[0]
    if len(raw) != 8 or any(value not in b"0123456789abcdefABCDEF" for value in raw):
        raise ValueError("Native header literal must contain exactly eight hex digits")
    return bytes.fromhex(raw.decode("ascii"))


class BodyController(ChassisController):
    """56ad68/523044: native per-CPU preparation, external ranges and latches."""

    controller_name = "CCanBodyFlashWriter"
    family = "body"

    def prepare_mode(self, secondary):
        from scripts.cuw_legacy_addresses import (
            legacy_address_inputs,
            legacy_kind_override,
            select_legacy_addresses,
        )
        from scripts.cuw_legacy_can import CommonCAN
        from scripts.cuw_legacy_channel import channel_state
        from scripts.cuw_legacy_engine import (
            ExecutableJ2534Error,
            executable_start_filter,
        )

        kind, config, mode, factory = legacy_address_inputs(self.context)
        if secondary:
            kind = legacy_kind_override(self.context)
        addresses = select_legacy_addresses(
            self.context, kind, config, reprog_mode=mode, factory_state=factory
        )
        if not addresses:
            raise LookupError("Body/DSS preparation has no native address row")
        address = addresses[0]
        channel = CommonCAN.from_io(
            self.io,
            address.request_header,
            address.response_header,
            state=channel_state(self.context),
        )
        switched = address.extended
        if self.family == "dss1" and not secondary:
            switched = self.external_mode == 1
        handle = None
        caught = False
        try:
            if switched:
                body_mode_switch(self.io, True)
            handle = executable_start_filter(
                self.io, channel.request, channel.response, padding=channel.padding
            )
            tables = BodyTables(self.context)
            if self.family == "dss1" and not secondary:
                access, conversion = tables.two_byte_passwords(
                    "dss1", self.context.native.base_metadata["kind_of_ecu"]
                )
                airbag_security(channel, access, conversion, padding=channel.padding)
            else:
                body_security(
                    channel, tables.body_shift_operands(), padding=channel.padding
                )
            channel.wait(100)
            if not secondary:
                header = (
                    _source_header(
                        self.source, 0x618A62 if self.context.build == 18 else 0x5BC9FE
                    )
                    if self.family == "dss1"
                    else self.mask_header
                )
                _diagnostic_mask(channel, header)
            body_change_mode(channel, secondary, padding=channel.padding)
            # Body disables SET_CONFIG before the wait; DSS1 disables it after.
            if switched and self.family == "body":
                from scripts.cuw_legacy_engine import ExecutableNativeError

                try:
                    body_mode_switch(self.io, False)
                except ExecutableNativeError:
                    # 56c4c0 suppresses only native failures while disabling.
                    pass
            channel.wait(1500)
            if switched and self.family == "dss1":
                body_mode_switch(self.io, False)
        except (ExecutableJ2534Error, ExecutableCANError) as error:
            self.capture(error)
            caught = True
        self.stop_filter(handle)
        return caught

    def transfer_cpu(self, native):
        from dataclasses import replace

        from scripts.cuw_legacy_engine import (
            executable_cpu_type,
            executable_new_password,
            executable_original_cpu_type,
            executable_selected_password,
        )

        cpu_index = native.selected.index
        cpu_type = executable_cpu_type(self.context, cpu_index)
        tables = BodyTables(self.context)
        descriptor = tables.descriptor(self.family, cpu_type)
        wide = descriptor.external if self.family == "body" else False
        image = native.image.data
        sizes = tables.sizes(self.family, cpu_type)
        if not sizes:
            raise ValueError("Native Body/DSS CPU block geometry is empty")
        ranges = sequential_ranges(len(sizes))
        if (
            self.family == "body"
            and wide
            and cpu_type
            not in tuple(
                tables._name(value if self.context.build == 18 else value - 0x4FD1C)
                for value in (0x5D5150, 0x5D5154)
            )
        ):
            if not native.image.s0_header:
                raise ValueError(
                    "Native external CPU requires the actual decoded S0 header"
                )
            ranges = s0_block_ranges(native.image.s0_header)
            validate_external_ranges(sizes, ranges, len(image))
        if not ranges:
            raise ValueError("Native Body/DSS transfer has no selected block ranges")
        password = (
            executable_new_password(replace(self.context, native=native))
            if (not wide and self.context.state.use_new_software_password)
            else executable_selected_password(self.context, cpu_index)
        )
        from scripts.cuw_legacy_engine import ExecutableNativeError

        check_id_swap = (
            tables.descriptor(
                "body", executable_original_cpu_type(self.context)
            ).big_endian
            if self.family == "body"
            else True
        )
        attempts = (
            11 if self.family == "body" and self.context.state.native_flag_ed8 else 1
        )
        for attempt in range(attempts):
            try:
                self.channel.check_id(
                    _original_cpu_location(native),
                    password,
                    swap_endian=check_id_swap,
                    interframe_ms=3,
                )
                break
            except ExecutableNativeError:
                # 56b4aa catch-all retries the paced CheckID only, without a delay.
                if attempt + 1 == attempts:
                    raise
        self.channel.wait(3)
        memory = self.channel.memory(wide=wide)
        if not cpu_matches(descriptor, memory.firmware_descriptor, True):
            raise BodyOperationError(10, "Body/DSS CPU identification")
        plans = []
        for first, last in ranges:
            offset = sum(sizes[: first - 1])
            length = sum(sizes[first - 1 : last])
            if (
                not 1 <= first <= last <= len(sizes)
                or not 0 < length <= len(image) - offset
                or length % 1024
                or memory.address + offset >= (1 << (32 if wide else 24))
            ):
                raise ValueError(
                    "Native Body/DSS block copy exceeds selected imported image"
                )
            plans.append((first, last, offset, length))
        for position, (first, last, offset, length) in enumerate(plans):
            if position + 1 == len(plans):
                self.context.state.native_flag_ed6 = True
            self.context.state.native_flag_ed8 = True
            part = image[offset : offset + length]
            self.channel.erase(first, last)
            self.channel.write_block(
                memory.address + offset,
                part,
                wide=wide,
                initial_wait_ms=3,
                progress=lambda size: self.progress.account(cpu_index, size),
            )
            self.channel.inverify(first, last)
            if not self.half_progress:
                self.channel.verify(
                    first,
                    last,
                    part,
                    progress=lambda size: self.progress.account(cpu_index, size),
                )

    def run(self):
        from scripts.cuw_legacy_engine import (
            ExecutableJ2534Error,
            apply_recovery_password_state,
            executable_cpu_type,
            executable_start_filter,
            executable_sync,
        )

        context = self.context
        tables = BodyTables(context)
        first = context.cpus[0]
        descriptor = tables.descriptor(self.family, executable_cpu_type(context, 0))
        if first.image is None:
            raise ValueError("Imported first Body/DSS CPU image required")
        self.external_mode = (
            0
            if self.family == "body" and descriptor.external
            else memory_mode(descriptor, first.image.data)
        )
        self.half_progress = self.family == "body" and first.base_metadata[
            "kind_of_ecu"
        ] == tables._name(0x5D524C if context.build == 18 else 0x585530)
        if self.half_progress:
            self.progress.image_sizes = tuple(
                size // 2 for size in self.progress.image_sizes
            )
        success = False
        completed = []
        aborted = None
        cleanup_errors = []
        finish_started = False
        try:
            caught = False
            if self.family == "dss1":
                caught = self.prepare_mode(False)
                if not caught or context.state.native_flag_ed8:
                    caught = (
                        self.prepare_mode(True) if self.external_mode == 1 else False
                    )
            if not caught:
                cpus = tuple(
                    cpu
                    for cpu in context.cpus
                    if cpu.selected.index >= context.native.selected.index
                )
                for position, native in enumerate(cpus):
                    if self.family == "body":
                        caught = self.prepare_mode(False)
                        if not caught or context.state.native_flag_ed8:
                            caught = (
                                self.prepare_mode(True)
                                if self.external_mode == 1
                                else False
                            )
                    if caught:
                        break
                    self.channel = self.channel_for_cpu(native)
                    self.channel.set_timeout(5000)
                    handle = None
                    try:
                        handle = executable_start_filter(
                            self.io,
                            self.channel.request,
                            self.channel.response,
                            padding=self.channel.padding,
                        )
                        self.transfer_cpu(native)
                        if self.family == "dss1" and position + 1 < len(cpus):
                            self.channel.change_cpu()
                            executable_sync(self.io, "completion", outcome="success")
                        else:
                            finish_started = True
                            self.channel.finish(
                                acknowledge=True, request_header=self.mask_header
                            )
                            if position + 1 < len(cpus):
                                executable_sync(
                                    self.io, "completion", outcome="success"
                                )
                            self.channel.wait(1000)
                            context.state.native_flag_ed8 = False
                        context.state.native_flag_ed6 = False
                        if self.family == "body":
                            context.state.use_new_software_password = False
                        executable_sync(self.io, "flag_88", value=False)
                        completed.append(native.selected.index)
                    except (ExecutableJ2534Error, ExecutableCANError) as error:
                        self.capture(error)
                        # 56ba0d/57435c clear both current-CPU arrays silently.
                        self.progress.counts[native.selected.index] = 0
                        self.progress.percentages[native.selected.index] = 0
                        caught = True
                    self.stop_filter(handle)
                    if caught:
                        break
                success = not caught
            if caught:
                self.status_70 = self.status(2 if context.state.native_flag_ed8 else 1)
                apply_recovery_password_state(
                    context,
                    self.io,
                    context.state.native_flag_ed6,
                    self.value_78,
                    persist=context.state.recovery_persistence_active,
                )
                self.error_handler()
                if self.family == "dss1" and not self.flag_68 and finish_started:
                    self.channel.wait(5000)
                    if self.finish_probe():
                        context.state.native_flag_ed6 = (
                            context.state.native_flag_ed8
                        ) = False
                        executable_sync(self.io, "flag_88", value=False)
                        success = True
            self.channel.set_timeout(self.saved_timeout)
            executable_sync(self.io, "flag_68", value=self.flag_68)
            executable_sync(
                self.io, "values_78_80", value_78=self.value_78, value_80=self.value_80
            )
            executable_sync(self.io, "owner_clear")
            executable_sync(
                self.io, "completion", outcome="success" if success else "failure"
            )
        except (InterruptedError, TimeoutError) as error:
            aborted = error
            try:
                self.channel.set_timeout(self.entry_timeout, cleanup=True)
            except Exception as cleanup_error:  # noqa: BLE001 - preserve host abort
                error.add_note(
                    "Body/DSS abort timeout restoration failed: "
                    + type(cleanup_error).__name__
                )
            raise
        finally:
            cleanup_errors = self.io.close()
            if aborted is not None:
                for error in cleanup_errors:
                    aborted.add_note("Body/DSS host cleanup failed: " + error)
        return {
            "controller": context.controller,
            "build": context.build,
            "source_entry": ("0x56ad68" if context.build == 18 else "0x5230e4")
            if self.family == "body"
            else ("0x573a28" if context.build == 18 else "0x52ad10"),
            "success": success and not cleanup_errors,
            "native_success": success,
            "completed_cpu_indices": completed,
            "native_flag_68": self.flag_68,
            "native_value_78": self.value_78,
            "native_value_80": self.value_80,
            "host_cleanup_errors": cleanup_errors,
        }

    def finish_probe(self):
        from scripts.cuw_legacy_engine import (
            ExecutableNativeError,
            executable_start_filter,
        )

        handle = None
        result = False
        try:
            handle = executable_start_filter(
                self.io,
                self.prepare_channel.request,
                self.prepare_channel.response,
                padding=self.prepare_channel.padding,
            )
            self.prepare_channel.is_finished()
            result = True
        except ExecutableNativeError:
            pass
        self.stop_filter(handle)
        return result


class DSS1Controller(BodyController):
    """573a28/52ad10: one preparation then multi-CPU DSS1 singleton writes."""

    controller_name = "CCanDSS1FlashWriter"
    family = "dss1"


_CGW_ISSUER = object()


@dataclass
class OriginalCGWState:
    """Original process globals, issued only by startup or actual recovery restore."""

    _issuer: object
    build: int
    source_sha256: str
    channel: object
    exists: bool = False
    variant: int = 0
    double_driver_fault: bool = False
    phase: str = "startup"

    def validate(self, context, *, completed=True):
        import hashlib

        from scripts.cuw_legacy_channel import channel_state
        from scripts.cuw_legacy_engine import ExecutableImage

        if (
            self._issuer is not _CGW_ISSUER
            or self.build != context.build
            or self.source_sha256
            != hashlib.sha256(ExecutableImage(context).data).hexdigest()
            or self.channel is not channel_state(context)
            or type(self.exists) is not bool
            or type(self.double_driver_fault) is not bool
            or type(self.variant) is not int
            or self.variant not in (0, 1, 2)
            or self.phase not in ("startup", "complete", "restored")
            or (completed and self.phase == "startup")
        ):
            raise ValueError(
                "Actual original CGW startup/recovery process state required"
            )


def _cgw_bound_state(context, *, completed=True):
    state = context.observations.get("legacy_cgw_state")
    if not isinstance(state, OriginalCGWState):
        raise TypeError("Actual original CGW startup or recovery producer is missing")
    state.validate(context, completed=completed)
    return state


def central_gw_exists(context):
    """58f5cc/543e4c: read the actual shared process global, never a caller BOOL."""
    return _cgw_bound_state(context).exists


def _cgw_new_context(context):
    import hashlib
    from dataclasses import replace

    from scripts.cuw_legacy_channel import channel_state
    from scripts.cuw_legacy_engine import ExecutableImage

    if "legacy_cgw_state" in context.observations:
        state = _cgw_bound_state(context)
        return context, state
    state = OriginalCGWState(
        _CGW_ISSUER,
        context.build,
        hashlib.sha256(ExecutableImage(context).data).hexdigest(),
        channel_state(context),
        variant=2 if context.build == 12 else 0,
    )
    return replace(
        context, observations={**context.observations, "legacy_cgw_state": state}
    ), state


def restore_central_gw_state(context):
    """58fef4/5447ac: copy only the actual loaded RecoveryInfo flag to process RAM."""
    from scripts.cuw_legacy_recovery import LegacyRecoveryStore

    store = context.recovery_store
    if (
        not isinstance(store, LegacyRecoveryStore)
        or store.original_data is None
        or store.build != context.build
        or store.state is not context.state
        or store.container_sha256 != context.container_sha256
        or store.fields.get("IsCentralGWExist") not in ("0", "1")
    ):
        raise ValueError("Actual source-associated loaded CGW recovery flag required")
    context, state = _cgw_new_context(context)
    state.exists = store.fields["IsCentralGWExist"] == "1"
    state.phase = "restored"
    return context


def _cgw_channel(context, io):
    from scripts.cuw_legacy_addresses import select_legacy_addresses
    from scripts.cuw_legacy_can import CommonCAN
    from scripts.cuw_legacy_channel import channel_state

    # 58f07a/543907 pass the native dedicated KindOfECU string, config=NULL.
    kind = BodyTables(context)._name(0x5D525C if context.build == 18 else 0x585540)
    addresses = select_legacy_addresses(context, kind)
    if not addresses:
        raise LookupError("Original CGW preparation address vector is empty")
    address = addresses[0]
    return CommonCAN.from_io(
        io,
        address.diagnostic_request_header,
        address.diagnostic_response_header,
        state=channel_state(context),
    )


def central_gw_seed_key(context, seed, *, reprogramming):
    """58f940/5441c8→566dd8/51fa4c: admitted nibble text→hex AES128 ECB key."""
    from scripts.calibration import decode_cuw_text
    from scripts.cuw_legacy_engine import ExecutableImage
    from scripts.programming_2026_common import native_aes128_ecb_block

    if type(seed) is not bytes or len(seed) != 16 or type(reprogramming) is not bool:
        raise ValueError("Native CGW sixteen-byte seed and direction required")
    source = ExecutableImage(context)
    address = (
        (0x629C40 if reprogramming else 0x629C84)
        if context.build == 18
        else (0x5CD718 if reprogramming else 0x5CD75C)
    )
    encoded = source.read(address, 68).split(b"\0", 1)[0]
    decoded = decode_cuw_text(encoded)
    if len(decoded) != 32 or any(
        value not in b"0123456789ABCDEFabcdef" for value in decoded
    ):
        raise ValueError("Native CGW private AES text has an invalid source layout")
    key = bytes.fromhex(decoded.decode("ascii"))
    return native_aes128_ecb_block(key, seed)


def _cgw_detect_variant(channel, state):
    """58ff7c: normal3e→2; swallowed CJ9/16 or CP except pending→3e00→1."""
    from scripts.cuw_legacy_can import (
        ExecutableCANResponseError,
        legacy_diagnostic,
        p5_diagnostic,
    )
    from scripts.cuw_legacy_engine import ExecutableJ2534Error

    first_driver_fault = False
    try:
        legacy_diagnostic(
            channel, b"\x3e", b"\x7e", 1, 80, busy_retries=255, pending_reads=149
        )
        return 2
    except ExecutableJ2534Error as error:
        if error.driver_status not in (9, 16):
            raise
        first_driver_fault = True
    except ExecutableCANResponseError as error:
        if error.response_size == 8 and error.response == b"\x7f\x3e\x78":
            raise
    try:
        p5_diagnostic(channel, b"\x3e\0", b"\x7e\0", 2, 79)
    except ExecutableJ2534Error as error:
        if first_driver_fault and error.driver_status in (9, 16):
            state.double_driver_fault = True
        raise
    return 1


def _cgw_legacy_security(context, channel):
    from scripts.cuw_legacy_can import legacy_diagnostic

    response = legacy_diagnostic(
        channel, b"\x27\x51", b"\x67\x51", 18, 16, busy_retries=255, pending_reads=149
    )
    key = central_gw_seed_key(context, response[2:18], reprogramming=True)
    channel.wait(100)
    legacy_diagnostic(
        channel,
        b"\x27\x52" + key,
        b"\x67\x52\x34",
        3,
        17,
        busy_retries=255,
        pending_reads=149,
    )


def _central_gw_change_to_reprogramming(context, io, state):
    from scripts.cuw_legacy_can import legacy_diagnostic, p5_diagnostic
    from scripts.cuw_legacy_engine import (
        ExecutableNativeError,
        executable_start_filter,
        executable_stop_filter,
    )

    state.validate(context, completed=False)
    channel = _cgw_channel(context, io)
    handle = None
    try:
        body_mode_switch(io, True)
        handle = executable_start_filter(
            io, channel.request, channel.response, padding=channel.padding
        )
        if not state.variant:
            state.variant = _cgw_detect_variant(channel, state)
        if state.variant == 1:
            p5_diagnostic(channel, b"\x10\x03", b"\x50\x03", 2, 88)
            p5_diagnostic(channel, b"\x27\x21", b"\x67\x21", 18, 16)
            # 5907ec/590858 invokes MainFrm49bcf8, registered by493006→47a338→
            # 478bd2→58ff44. No synthetic key calculation replaces that sender.
            raise NotImplementedError(
                "Original modern CGW requires the actual registered MainFrm49bcf8 online-key sender"
            )
        _cgw_legacy_security(context, channel)
        channel.wait(100)
        legacy_diagnostic(
            channel, b"\x10\x60", b"\x50", 1, 50, busy_retries=255, pending_reads=149
        )
        if context.build == 18:
            channel.wait(1500)
    finally:
        import sys

        primary = sys.exception()
        cleanup_error = None
        try:
            # 58fefc/5447b4 are native catch-all cleanup wrappers.
            body_mode_switch(io, False)
        except ExecutableNativeError:
            pass
        except Exception as error:  # noqa: BLE001 - retain primary and release filter
            if primary is None:
                cleanup_error = error
            else:
                primary.add_note("CGW mode restoration failed: " + type(error).__name__)
        if handle is not None:
            try:
                executable_stop_filter(io, handle)
            except ExecutableNativeError:
                pass
            except Exception as error:  # noqa: BLE001 - retain primary and cleanup identity
                if primary is None and cleanup_error is None:
                    cleanup_error = error
                else:
                    retained = primary or cleanup_error
                    assert retained is not None
                    retained.add_note(
                        "CGW filter release failed: " + type(error).__name__
                    )
        if cleanup_error is not None:
            raise cleanup_error
    if context.build == 12:
        channel.wait(1500)


def central_gw_change_to_reprogramming(context, io):
    """58f028/5438b8: unconditional actual helper over the shared issued process RAM."""
    _central_gw_change_to_reprogramming(context, io, _cgw_bound_state(context))


def central_gw_startup(context, io):
    """58eea4/5436ec: run the real startup producer; success alone publishes True."""
    from scripts.cuw_legacy_engine import (
        ExecutableJ2534Error,
        executable_reconnect,
        executable_sync,
    )
    from scripts.cuw_legacy_recovery import LegacyRecoveryStore

    store = context.recovery_store
    if (
        not isinstance(store, LegacyRecoveryStore)
        or store.state is not context.state
        or store.build != context.build
        or store.container_sha256 != context.container_sha256
    ):
        raise ValueError("Actual CGW RecoveryInfo RAM setter/store required")
    if context.build == 12:
        import re

        from scripts.cuw_legacy_engine import executable_parameters

        text = executable_parameters(context, 0).get("WaitTimeAfterIGOn", "0")
        if (
            not re.fullmatch(r"[ \t]*[+-]?[0-9]{1,10}", text)
            or not -(2**31) <= int(text) < 2**31
        ):
            raise ValueError("Native WaitTimeAfterIGOn signed LONG required")
        if io.call("wait", milliseconds=int(text) & 0xFFFFFFFF) is not None:
            raise ValueError("Native CGW pre-start wait must return None")
    context, state = _cgw_new_context(context)
    state.phase = "startup"
    state.exists = state.double_driver_fault = False
    # 42eca0/417fd4 are RAM-only setters; later full Save sees this field.
    store.fields["IsCentralGWExist"] = "0"
    category = driver = 0
    outcome = True
    try:
        _central_gw_change_to_reprogramming(context, io, state)
        state.exists = True
        store.fields["IsCentralGWExist"] = "1"
    except (ExecutableJ2534Error, ExecutableCANError) as error:
        absent_driver = isinstance(error, ExecutableJ2534Error) and (
            state.double_driver_fault
            if context.build == 18
            else error.native_code == 16 and error.driver_status in (9, 16)
        )
        if not absent_driver:
            category = error.native_code & 0xFFFFFFFF
            driver = (
                error.driver_status if isinstance(error, ExecutableJ2534Error) else 0
            )
            status = int.from_bytes(
                BodyTables(context).image.read(
                    0x5F1A4C if context.build == 18 else 0x59A7F4, 4
                ),
                "little",
            )
            while True:
                executable_sync(io, "value_70", value=status)
                executable_sync(io, "values_78_80", value_78=category, value_80=driver)
                executable_sync(io, "flag_88", value=False)
                executable_sync(io, "error_handler")
                if not executable_sync(io, "read_flag_88"):
                    outcome = False
                    break
                category = driver = 0
                try:
                    executable_reconnect(context, io, 6)
                except ExecutableJ2534Error as reconnect_error:
                    category, driver = (
                        reconnect_error.native_code & 0xFFFFFFFF,
                        reconnect_error.driver_status,
                    )
                    status = int.from_bytes(
                        BodyTables(context).image.read(
                            0x5F1A54 if context.build == 18 else 0x59A7FC, 4
                        ),
                        "little",
                    )
                    continue
                break
        else:
            outcome = True
    state.phase = "complete"
    executable_sync(io, "flag_68", value=not outcome)
    executable_sync(io, "values_78_80", value_78=category, value_80=driver)
    executable_sync(io, "owner_clear")
    executable_sync(io, "completion", outcome="success" if outcome else "failure")
    return context


class AirbagController(BodyController):
    """5685e4/520d74: CPU0 singleton writes and source-local transfer retries."""

    controller_name = "CCanAirbagFlashWriter"

    def prepare(self):
        from scripts.cuw_legacy_engine import (
            ExecutableJ2534Error,
            executable_start_filter,
        )

        caught = False
        handle = None
        try:
            handle = executable_start_filter(
                self.io,
                self.prepare_channel.request,
                self.prepare_channel.response,
                padding=self.prepare_channel.padding,
            )
            access, conversion = BodyTables(self.context).two_byte_passwords(
                "airbag", self.context.native.base_metadata["kind_of_ecu"]
            )
            airbag_prepare(
                self.prepare_channel,
                access,
                conversion,
                padding=self.prepare_channel.padding,
                mask_header=self.mask_header,
            )
        except (ExecutableJ2534Error, ExecutableCANError) as error:
            self.capture(error)
            caught = True
        self.stop_filter(handle)
        return caught

    def error_handler(self):
        transfer_error = self.status_70 == self.status(2)
        super().error_handler()
        if transfer_error and not self.flag_68:
            if self.context.build == 18:
                from scripts.cuw_legacy_can import automatic_ig_off_cancel

                automatic_ig_off_cancel(self.context, self.io)
            if "legacy_cgw_state" not in self.context.observations:
                raise NotImplementedError(
                    "Airbag accepted retry requires the actual CGW startup/recovery producer"
                )
            if central_gw_exists(self.context):
                central_gw_change_to_reprogramming(self.context, self.io)

    def transfer_cpu(self, native):
        from dataclasses import replace

        from scripts.cuw_legacy_engine import (
            executable_cpu_type,
            executable_new_password,
            executable_selected_password,
        )

        tables = BodyTables(self.context)
        cpu_type = executable_cpu_type(self.context, 0)
        sizes = tables.sizes("airbag", cpu_type)
        image = native.image.data
        if (
            not sizes
            or sum(sizes) > len(image)
            or any(size <= 0 or size % 1024 for size in sizes)
        ):
            raise ValueError("Native Airbag singleton copy exceeds imported image")
        from scripts.cuw_legacy_engine import apply_recovery_password_state

        attempts = 11 if self.started else 1
        for attempt in range(attempts):
            # 568868 reloads this selection on each attempt after the CPass7
            # handler may reset the native new-password flag.
            password = (
                executable_new_password(replace(self.context, native=native))
                if self.context.state.use_new_software_password
                else executable_selected_password(self.context, 0)
            )
            try:
                self.channel.check_id(
                    _original_cpu_location(native), password, swap_endian=True
                )
                break
            except ExecutableCANError as error:
                self.value_78 = error.native_code & 0xFFFFFFFF
                if attempt + 1 == attempts or self.value_78 != 7:
                    raise
                self.channel.wait(2000)
                apply_recovery_password_state(
                    self.context,
                    self.io,
                    False,
                    self.value_78,
                    persist=self.context.state.recovery_persistence_active,
                )
        memory = self.channel.memory(wide=False)
        if not tables.identified("airbag", cpu_type, memory.firmware_descriptor, True):
            raise BodyOperationError(10, "Airbag CPU identification")
        offset = 0
        for block, size in enumerate(sizes, 1):
            self.started = True
            part = image[offset : offset + size]
            self.channel.erase(block, block)
            self.channel.write_block(
                memory.address + offset,
                part,
                progress=lambda count: self.progress.account(0, count),
            )
            self.channel.inverify(block, block)
            self.channel.verify(
                block,
                block,
                part,
                progress=lambda count: self.progress.account(0, count),
            )
            offset += size

    def run(self):
        from scripts.cuw_legacy_engine import (
            ExecutableJ2534Error,
            apply_recovery_password_state,
            executable_start_filter,
            executable_sync,
        )

        success = False
        self.started = False
        finish_started = False
        aborted = None
        cleanup_errors = []
        try:
            preparation_failed = self.prepare()
            if not preparation_failed:
                self.channel = self.channel_for_cpu(self.context.cpus[0])
                while True:
                    self.channel.set_timeout(5000)
                    handle = None
                    caught = False
                    finish_started = False
                    try:
                        handle = executable_start_filter(
                            self.io,
                            self.channel.request,
                            self.channel.response,
                            padding=self.channel.padding,
                        )
                        self.transfer_cpu(self.context.cpus[0])
                        finish_started = True
                        self.channel.finish(
                            acknowledge=True, request_header=self.mask_header
                        )
                        self.channel.wait(1000)
                        executable_sync(self.io, "flag_88", value=False)
                        success = True
                    except (ExecutableJ2534Error, ExecutableCANError) as error:
                        self.capture(error)
                        epc_reset_progress(self.progress, 0)
                        caught = True
                    self.stop_filter(handle)
                    if not caught:
                        break
                    self.status_70 = self.status(2)
                    apply_recovery_password_state(
                        self.context,
                        self.io,
                        self.started,
                        self.value_78,
                        persist=self.context.state.recovery_persistence_active,
                    )
                    self.error_handler()
                    if self.flag_68:
                        break
                    self.channel.wait(5000)
                    if finish_started and self.finish_probe():
                        executable_sync(self.io, "flag_88", value=False)
                        success = True
                        break
            if preparation_failed:
                apply_recovery_password_state(
                    self.context,
                    self.io,
                    False,
                    self.value_78,
                    persist=self.context.state.recovery_persistence_active,
                )
                self.status_70 = self.status(1)
                self.error_handler()
            self.channel.set_timeout(self.saved_timeout)
            executable_sync(self.io, "flag_68", value=self.flag_68)
            executable_sync(
                self.io, "values_78_80", value_78=self.value_78, value_80=self.value_80
            )
            executable_sync(self.io, "owner_clear")
            executable_sync(
                self.io, "completion", outcome="success" if success else "failure"
            )
        except (InterruptedError, TimeoutError) as error:
            aborted = error
            try:
                self.channel.set_timeout(self.entry_timeout, cleanup=True)
            except Exception as cleanup_error:  # noqa: BLE001 - retain host abort
                error.add_note(
                    "Airbag abort timeout restoration failed: "
                    + type(cleanup_error).__name__
                )
            raise
        finally:
            cleanup_errors = self.io.close()
            if aborted is not None:
                for error in cleanup_errors:
                    aborted.add_note("Airbag host cleanup failed: " + error)
        return {
            "controller": self.context.controller,
            "build": self.context.build,
            "source_entry": "0x5685e4" if self.context.build == 18 else "0x520d74",
            "success": success and not cleanup_errors,
            "native_success": success,
            "native_flag_68": self.flag_68,
            "native_value_78": self.value_78,
            "native_value_80": self.value_80,
            "host_cleanup_errors": cleanup_errors,
        }


class FCController(ChassisController):
    """57b3c0/531d60: selected-target FC address and full block retry scope."""

    controller_name = "CCanFCFlashWriter"

    def select_prepare_addresses(self, context, kind, config, mode, factory):
        from scripts.cuw_legacy_addresses import CAddress, select_fuel_cell_address
        from scripts.cuw_legacy_engine import executable_selected_target_calibration

        key = executable_selected_target_calibration(context)
        # 424d1c preserves an uninitialized caller record on a missing key. A
        # bounded reconstruction rejects that native undefined-address branch.
        if not any(candidate == key for candidate, _ in factory.fuel_cell_rows):
            raise LookupError("Selected FC target has no actual discovered address")
        return (select_fuel_cell_address(context, key, factory, CAddress(bytes(8))),)

    def prepare(self):
        from scripts.cuw_legacy_engine import (
            ExecutableJ2534Error,
            ExecutableNativeError,
            executable_start_filter,
        )

        handle = None
        caught = False
        try:
            handle = executable_start_filter(
                self.io,
                self.prepare_channel.request,
                self.prepare_channel.response,
                padding=self.prepare_channel.padding,
            )
            pairs = self.source.read(
                0x5D6054 if self.context.build == 18 else 0x585FDC, 4
            )
            fc_prepare(
                self.prepare_channel,
                BodyTables(self.context).four_round_operands("fc"),
                repeat_session=self.prepare_channel.request[2:4]
                in (pairs[:2], pairs[2:]),
                padding=self.prepare_channel.padding,
                mask_header=self.mask_header,
            )
        except (ExecutableJ2534Error, ExecutableCANError) as error:
            self.capture(error)
            caught = True
        except ExecutableNativeError:
            # Execute's initial scope is catch-all; no invented CJ/CPass fields.
            caught = True
        self.stop_filter(handle)
        return caught

    def transfer_cpu(self, native):
        from scripts.cuw_legacy_can import calc_block_sizes
        from scripts.cuw_legacy_engine import (
            ExecutableNativeError,
            executable_cpu_type,
            executable_selected_password,
        )

        channel = self.channel
        cpu_index = native.selected.index
        if not self.retrying:
            channel.wait(500)
            channel.check_id(
                _original_cpu_location(native),
                executable_selected_password(self.context),
            )
        memory = channel.memory(wide=False)
        tables = BodyTables(self.context)
        cpu_type = executable_cpu_type(self.context)
        if not tables.identified("fc", cpu_type, memory.firmware_descriptor, False):
            raise BodyOperationError(10, "FC CPU identification")
        sizes = calc_block_sizes(cpu_type, memory)
        ranges = tables.ranges("fc", cpu_type, len(sizes))
        image = native.image.data
        plans = []
        for first, last in ranges:
            offset = sum(sizes[: first - 1])
            length = sum(sizes[first - 1 : last])
            if (
                not 0 < length <= len(image) - offset
                or length % 1024
                or memory.address + offset > 0xFFFFFF
            ):
                raise ValueError(
                    "Native FC grouped copy exceeds selected imported image"
                )
            plans.append((first, last, offset, length))
        # 57b946 catches native exceptions only around this block loop, before
        # the outer typed CJ2534/CPassThru handlers choose the retry branch.
        try:
            for first, last, offset, length in plans:
                part = image[offset : offset + length]
                if not channel.check_block(first, last):
                    channel.erase(first, last)
                channel.write_block(
                    memory.address + offset,
                    part,
                    initial_wait_ms=0,
                    progress=lambda size: self.progress.account(cpu_index, size),
                )
                channel.inverify(first, last)
                channel.verify(
                    first,
                    last,
                    part,
                    progress=lambda size: self.progress.account(cpu_index, size),
                )
        except ExecutableNativeError:
            self.block_failed = True
            raise

    def retry_block(self):
        from scripts.cuw_legacy_engine import (
            ExecutableJ2534Error,
            executable_reconnect,
            executable_start_filter,
            executable_sync,
        )

        saved_category = self.value_78
        self.status_70 = self.status(2)
        while True:
            executable_sync(self.io, "value_70", value=self.status_70)
            executable_sync(
                self.io, "values_78_80", value_78=self.value_78, value_80=self.value_80
            )
            executable_sync(self.io, "flag_88", value=False)
            executable_sync(self.io, "error_handler")
            vote = executable_sync(self.io, "read_flag_88")
            # Source resets both arrays after the GUI, even on declined retry.
            epc_reset_progress(self.progress, self.context.native.selected.index)
            if not vote:
                self.flag_68 = True
                return False
            self.value_78 = self.value_80 = 0
            handle = None
            caught = False
            try:
                executable_reconnect(self.context, self.io, 6)
                handle = executable_start_filter(
                    self.io,
                    self.channel.request,
                    self.channel.response,
                    padding=self.channel.padding,
                )
                # Native vtable30 receives the original exception category,
                # not KindOfECU; 13/15 enable the source zero-fill fallback.
                self.channel.prepare_reprogramming(saved_category)
            except (ExecutableJ2534Error, ExecutableCANError) as error:
                self.capture(error)
                caught = True
            self.stop_filter(handle)
            if not caught:
                return True
            self.status_70 = self.status(3)

    def run(self):
        from scripts.cuw_legacy_engine import (
            ExecutableJ2534Error,
            executable_start_filter,
            executable_sync,
        )

        success = False
        cleanup_errors = []
        aborted = None
        self.retrying = self.block_failed = False
        try:
            self.channel.wait(1000)
            preparation_failed = self.prepare()
            if not preparation_failed:
                while True:
                    handle = None
                    caught = False
                    self.block_failed = False
                    try:
                        handle = executable_start_filter(
                            self.io,
                            self.channel.request,
                            self.channel.response,
                            padding=self.channel.padding,
                        )
                        self.transfer_cpu(self.context.native)
                        self.channel.finish(
                            acknowledge=False, request_header=self.mask_header
                        )
                        success = True
                    except (ExecutableJ2534Error, ExecutableCANError) as error:
                        self.capture(error)
                        caught = True
                    self.stop_filter(handle)
                    if not caught:
                        break
                    if not self.block_failed:
                        preparation_failed = True
                        break
                    if not self.retry_block():
                        break
                    self.retrying = True
            if preparation_failed:
                self.status_70 = self.status(1)
                self.error_handler()
            executable_sync(self.io, "flag_68", value=self.flag_68)
            executable_sync(
                self.io, "values_78_80", value_78=self.value_78, value_80=self.value_80
            )
            executable_sync(self.io, "owner_clear")
            executable_sync(
                self.io, "completion", outcome="success" if success else "failure"
            )
        except (InterruptedError, TimeoutError) as error:
            aborted = error
            raise
        finally:
            cleanup_errors = self.io.close()
            if aborted is not None:
                for error in cleanup_errors:
                    aborted.add_note("FC host cleanup failed: " + error)
        return {
            "controller": self.context.controller,
            "build": self.context.build,
            "source_entry": "0x57b3c0" if self.context.build == 18 else "0x531d60",
            "success": success and not cleanup_errors,
            "native_success": success,
            "native_flag_68": self.flag_68,
            "native_value_78": self.value_78,
            "native_value_80": self.value_80,
            "host_cleanup_errors": cleanup_errors,
        }


def execute(context, io):
    """Run the nine source-selected body entries; guarded gaps fail explicitly."""
    from scripts.cuw_legacy_engine import ExecutableContext

    if not isinstance(context, ExecutableContext):
        raise TypeError("Imported native controller context required")
    if context.controller == "CCanAirbagFlashWriter":
        return AirbagController(context, io).run()
    if context.controller == "CCanBodyFlashWriter":
        return BodyController(context, io).run()
    if context.controller == "CCanDSS1FlashWriter":
        return DSS1Controller(context, io).run()
    if context.controller == "CCanFCFlashWriter":
        return FCController(context, io).run()
    if context.controller == "CCanClearanceSonarFlashWriter":
        return SonarController(context, io).run()
    if context.controller == "CCanOldSpecECBFlashWriter":
        return OldECBController(context, io).run()
    if context.controller == "CCanChassisShrinkFlashWriter":
        return ChassisController(context, io).run()
    if context.controller == "CCanEPBFlashWriter":
        return EPBController(context, io).run()
    return EPCController(context, io).run()
