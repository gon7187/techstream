"""Native MongoosePro JLR USB identity/version probe and offline SLP codec.

Derived from monpj432.dll 2710726fdd174f32b5e703e310cfce047a663451edbb3e35ca0c8eeff6929413
and dtmonpro.sys. See docs/jlr-native.md. The probe sends no ECU requests.
"""

from __future__ import annotations

import ctypes as C
import ctypes.util
import math
import struct
import threading
import time
from collections import deque
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from scripts.mongoose_protocol import MAGIC, MAX_PAYLOAD, encode_frame


class StreamDecoder:
    def __init__(self):
        self.pending = b""

    def feed(self, data: bytes) -> list[bytes]:
        if len(data) > 65536:
            raise ValueError("USB chunk exceeds 64 KiB")
        buffer = self.pending + data
        frames, cursor = [], 0
        while len(buffer) - cursor >= 4:
            size, check = struct.unpack_from("<HH", buffer, cursor)
            if not 1 <= size <= MAX_PAYLOAD or size ^ check != MAGIC:
                cursor += 1
                continue
            if len(buffer) - cursor < size + 4:
                break
            frames.append(buffer[cursor + 4 : cursor + 4 + size])
            cursor += size + 4
        self.pending = buffer[cursor:]
        return frames


def request(
    target: int, opcode: int, sequence: int, body: bytes = b"", *, count: int = 0
) -> bytes:
    if (
        not 0 <= target <= 65535
        or not 0 <= opcode < 0x8000
        or not 1 <= sequence <= 255
        or not 0 <= count <= 65535
    ):
        raise ValueError("Invalid JLR target, opcode or sequence")
    # Native stack alignment slot is unwritten; deterministic zero avoids leaking it.
    return encode_frame(
        struct.pack("<6H", target, 0, opcode, sequence, count, 0) + body
    )


def response(payload: bytes, target: int, opcode: int, sequence: int) -> int:
    if len(payload) < 20:
        raise ValueError("Truncated JLR reply")
    destination, source, reply_opcode, reply_sequence = struct.unpack_from(
        "<4H", payload
    )
    if (destination, source, reply_opcode, reply_sequence) != (
        0,
        target,
        opcode | 0x8000,
        sequence,
    ):
        raise ValueError("JLR reply does not match target, opcode and sequence")
    return struct.unpack_from("<I", payload, 12)[0]


class JLRClient:
    def __init__(self, transport, cancel: threading.Event | None = None):
        self.transport = transport
        self.decoder = StreamDecoder()
        self.sequence = 0
        self.events: deque[bytes] = deque()
        self.cancel = cancel
        self.io_lock = threading.RLock()
        self.channel_owner: object | None = None

    def transact(
        self,
        target: int,
        opcode: int,
        body: bytes = b"",
        timeout: float = 10,
        *,
        count: int = 0,
        accepted_statuses: tuple[int, ...] = (0,),
        cleanup: bool = False,
    ) -> bytes:
        with self.io_lock:
            return self._transact(
                target,
                opcode,
                body,
                timeout,
                count=count,
                accepted_statuses=accepted_statuses,
                cleanup=cleanup,
            )

    def _transact(
        self,
        target: int,
        opcode: int,
        body: bytes,
        timeout: float,
        *,
        count: int,
        accepted_statuses: tuple[int, ...],
        cleanup: bool,
    ) -> bytes:
        if not math.isfinite(timeout) or not 0 <= timeout <= 10:
            raise ValueError("JLR timeout must be finite and in [0, 10] seconds")
        if not cleanup and self.cancel is not None and self.cancel.is_set():
            raise InterruptedError("JLR operation cancelled")
        if timeout == 0:
            raise TimeoutError(f"JLR opcode {opcode:#x}: reply timeout")
        self.sequence = self.sequence % 255 + 1
        sequence = self.sequence
        self.transport.write(request(target, opcode, sequence, body, count=count))
        deadline = time.monotonic() + timeout
        answer = None
        while answer is None:
            if not cleanup and self.cancel is not None and self.cancel.is_set():
                raise InterruptedError("JLR operation cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"JLR opcode {opcode:#x}: reply timeout")
            for packet in self.decoder.feed(
                self.transport.read(min(50, max(1, int(remaining * 1000))))
            ):
                if len(packet) >= 8 and struct.unpack_from("<4H", packet) == (
                    0,
                    target,
                    opcode | 0x8000,
                    sequence,
                ):
                    if opcode == 0x100:
                        if len(packet) < 12:
                            raise ValueError("Truncated JLR echo reply")
                    else:
                        response(packet, target, opcode, sequence)
                    if answer is not None:
                        raise ValueError("Duplicate JLR reply")
                    answer = packet
                else:
                    if len(self.events) >= 1024:
                        raise BufferError("JLR unsolicited event queue is full")
                    self.events.append(packet)
        status = 0 if opcode == 0x100 else response(answer, target, opcode, sequence)
        if status not in accepted_statuses:
            raise OSError(f"JLR opcode {opcode:#x}: device status {status:#x}")
        return answer

    def poll_events(self, timeout_ms: int = 50) -> list[bytes]:
        """Single transport reader shared with transact; bounded cooperative polling."""
        if not 1 <= timeout_ms <= 50:
            raise ValueError("Event polling timeout must be 1..50 ms")
        with self.io_lock:
            if self.cancel is not None and self.cancel.is_set():
                raise InterruptedError("JLR operation cancelled")
            if not self.events:
                packets = self.decoder.feed(self.transport.read(timeout_ms))
                if len(packets) > 1024:
                    raise BufferError("JLR unsolicited event queue is full")
                self.events.extend(packets)
            packets = list(self.events)
            self.events.clear()
            return packets

    def get_value(self, parameter: int) -> int:
        payload = self.transact(1, 0x0C, struct.pack("<I", parameter))
        if len(payload) < 28:
            raise ValueError("JLR GetValue reply has no value at byte 24")
        return struct.unpack_from("<I", payload, 24)[0]

    def probe(self) -> dict:
        try:
            self.transact(1, 0x100, timeout=0.25)
        except TimeoutError:
            pass  # Original USB3 warmup tolerates a lost first echo.
        board_reply = self.transact(1, 0x109)
        if len(board_reply) != 180:
            raise ValueError("JLR board reply must contain eight 20-byte records")
        firmware, bootloader = self.get_value(0x2B), self.get_value(0x2A)
        serial_reply = self.transact(1, 0x13, struct.pack("<I", 0))
        end = serial_reply.find(b"\0", 24)
        if end == -1:
            raise ValueError("JLR serial string is not NUL terminated")
        serial = serial_reply[24:end]
        return {
            "firmware_raw": firmware,
            "bootloader_raw": bootloader,
            "serial_hex": serial.hex(),
            "serial_text": serial.decode("ascii", errors="backslashreplace"),
            "boards": [
                {
                    "slot": i + 1,
                    "type": board_reply[20 + i * 20],
                    "raw_hex": board_reply[20 + i * 20 : 40 + i * 20].hex(),
                }
                for i in range(8)
            ],
        }


@dataclass(frozen=True)
class USBLocation:
    port: str
    bus: int
    address: int
    input_endpoint: int
    output_endpoint: int


def discover_jlr(root: Path = Path("/sys/bus/usb/devices")) -> list[USBLocation]:
    devices = []
    for entry in sorted(root.iterdir()):
        try:
            if (
                (entry / "idVendor").read_text().strip().lower(),
                (entry / "idProduct").read_text().strip().lower(),
            ) != ("18e1", "0104"):
                continue
        except (OSError, UnicodeError):
            continue
        interfaces, inputs, outputs = set(), [], []
        for interface in root.glob(entry.name + ":*"):
            number = int((interface / "bInterfaceNumber").read_text().strip(), 16)
            alternate = int((interface / "bAlternateSetting").read_text().strip())
            if number not in (0, 1) or alternate:
                raise ValueError(
                    "JLR interface layout differs from the recovered driver"
                )
            interfaces.add(number)
            for endpoint in interface.glob("ep_*"):
                attributes = int((endpoint / "bmAttributes").read_text().strip(), 16)
                if attributes & 3 == 2:
                    address = int(
                        (endpoint / "bEndpointAddress").read_text().strip(), 16
                    )
                    if not 1 <= address & 15 <= 15 or address & 0x70:
                        raise ValueError("Invalid USB bulk endpoint address")
                    (inputs if address & 0x80 else outputs).append(address)
        if interfaces != {0, 1} or len(inputs) != 1 or len(outputs) != 1:
            raise ValueError(
                "JLR requires interfaces 0/1 and an unambiguous bulk endpoint pair"
            )
        devices.append(
            USBLocation(
                entry.name,
                int((entry / "busnum").read_text()),
                int((entry / "devnum").read_text()),
                inputs[0],
                outputs[0],
            )
        )
    return devices


class USBTransport:
    """libusb with exclusive interface claims; never detach an existing driver."""

    def __init__(self, location: USBLocation):
        library = ctypes.util.find_library("usb-1.0")
        if library is None:
            raise OSError("libusb-1.0 is not installed")
        self.lib = C.CDLL(library)
        pointer = C.c_void_p
        declarations = {
            "init": (C.c_int, [C.POINTER(pointer)]),
            "exit": (None, [pointer]),
            "get_device_list": (C.c_ssize_t, [pointer, C.POINTER(C.POINTER(pointer))]),
            "free_device_list": (None, [C.POINTER(pointer), C.c_int]),
            "get_bus_number": (C.c_uint8, [pointer]),
            "get_device_address": (C.c_uint8, [pointer]),
            "get_device_descriptor": (C.c_int, [pointer, pointer]),
            "open": (C.c_int, [pointer, C.POINTER(pointer)]),
            "close": (None, [pointer]),
            "claim_interface": (C.c_int, [pointer, C.c_int]),
            "release_interface": (C.c_int, [pointer, C.c_int]),
            "set_interface_alt_setting": (C.c_int, [pointer, C.c_int, C.c_int]),
            "control_transfer": (
                C.c_int,
                [
                    pointer,
                    C.c_uint8,
                    C.c_uint8,
                    C.c_uint16,
                    C.c_uint16,
                    pointer,
                    C.c_uint16,
                    C.c_uint,
                ],
            ),
            "bulk_transfer": (
                C.c_int,
                [pointer, C.c_uint8, pointer, C.c_int, C.POINTER(C.c_int), C.c_uint],
            ),
            "error_name": (C.c_char_p, [C.c_int]),
        }
        for name, (restype, argtypes) in declarations.items():
            function = getattr(self.lib, "libusb_" + name)
            function.restype, function.argtypes = restype, argtypes
        self.location = location
        self.context, self.handle = pointer(), pointer()
        self.claimed: list[int] = []
        self.vendor_open = False
        self.check(self.lib.libusb_init(C.byref(self.context)))
        try:
            devices = C.POINTER(pointer)()
            count = self.lib.libusb_get_device_list(self.context, C.byref(devices))
            self.check(count)
            try:
                for i in range(count):
                    device = devices[i]
                    if (
                        self.lib.libusb_get_bus_number(device),
                        self.lib.libusb_get_device_address(device),
                    ) != (location.bus, location.address):
                        continue
                    descriptor = C.create_string_buffer(18)
                    self.check(
                        self.lib.libusb_get_device_descriptor(device, descriptor)
                    )
                    if struct.unpack_from("<HH", descriptor.raw, 8) != (0x18E1, 0x0104):
                        raise OSError("USB device identity changed before open")
                    self.check(self.lib.libusb_open(device, C.byref(self.handle)))
                    break
            finally:
                self.lib.libusb_free_device_list(devices, 1)
            if not self.handle:
                raise OSError("Selected JLR device is no longer present")
            for interface in (0, 1):
                self.check(self.lib.libusb_claim_interface(self.handle, interface))
                self.claimed.append(interface)
                self.check(
                    self.lib.libusb_set_interface_alt_setting(self.handle, interface, 0)
                )
            self.vendor_open = True
            self.check(
                self.lib.libusb_control_transfer(
                    self.handle, 0x40, 0xDB, 1, 0, None, 0, 1000
                )
            )
        except BaseException:
            with suppress(OSError):
                self.close()
            raise

    def check(self, result: int) -> int:
        if result < 0:
            raise OSError(self.lib.libusb_error_name(result).decode("ascii"))
        return result

    def write(self, data: bytes) -> None:
        if not self.handle or not 1 <= len(data) <= 65536:
            raise ValueError("USB write requires an open device and 1..65536 bytes")
        buffer = C.create_string_buffer(data)
        transferred = C.c_int()
        self.check(
            self.lib.libusb_bulk_transfer(
                self.handle,
                self.location.output_endpoint,
                buffer,
                len(data),
                C.byref(transferred),
                1000,
            )
        )
        if transferred.value != len(data):
            raise OSError("Short JLR USB write; session must be closed")

    def read(self, timeout_ms: int) -> bytes:
        if not self.handle or not 1 <= timeout_ms <= 10000:
            raise ValueError("USB read requires an open device and bounded timeout")
        buffer, transferred = C.create_string_buffer(65536), C.c_int()
        result = self.lib.libusb_bulk_transfer(
            self.handle,
            self.location.input_endpoint,
            buffer,
            len(buffer),
            C.byref(transferred),
            timeout_ms,
        )
        if result != -7:  # libusb timeout may still deliver a partial transfer.
            self.check(result)
        return buffer.raw[: transferred.value]

    def close(self) -> None:
        cleanup_error = None
        try:
            if self.handle:
                if self.vendor_open:
                    result = self.lib.libusb_control_transfer(
                        self.handle, 0x40, 0xDB, 0, 0, None, 0, 1000
                    )
                    if result < 0:
                        cleanup_error = result
                for interface in reversed(self.claimed):
                    result = self.lib.libusb_release_interface(self.handle, interface)
                    if result < 0 and cleanup_error is None:
                        cleanup_error = result
                self.lib.libusb_close(self.handle)
        finally:
            if self.context:
                self.lib.libusb_exit(self.context)
            self.handle, self.context = C.c_void_p(), C.c_void_p()
            self.claimed.clear()
            self.vendor_open = False
        if cleanup_error is not None:
            self.check(cleanup_error)


def probe_adapter(location: USBLocation, cancel: threading.Event | None = None) -> dict:
    transport = USBTransport(location)
    try:
        result = JLRClient(transport, cancel).probe()
    except BaseException:
        with suppress(OSError):
            transport.close()
        raise
    else:
        transport.close()
        return result
