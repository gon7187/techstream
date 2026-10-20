"""Statically recovered CUW vendor primitives with explicit bounded replay I/O.

No device discovery, native DLL execution or authorization calculation occurs here.
The raw-CAN seam carries payload bytes after the identifier; providers bind the
identifier/filter explicitly. A successful fragment is not a programmed vehicle.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from typing import Literal


def _uint(value: int, bits: int, name: str) -> int:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError(f"{name} must be uint{bits}")
    return value


def _error_chain(error: BaseException | None) -> list[str]:
    result = []
    seen = set()
    while error is not None and id(error) not in seen and len(result) < 8:
        seen.add(id(error))
        result.append(str(error))
        error = error.__cause__ or error.__context__
    return result


def _native_error_info(error: BaseException) -> dict:
    seen = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen and len(seen) < 8:
        seen.add(id(current))
        if isinstance(
            current,
            (VendorOperationError, VendorInitialCommandError, VendorStatusAckError),
        ):
            info = {
                "native_error_domain": "CPassThruException",
                "native_error_code": current.code,
            }
            if isinstance(current, VendorOperationError) and isinstance(
                current.response, bytes
            ):
                info["diagnostic_response_hex"] = current.response.hex()
            return info
        if isinstance(current, (NativeTransportError, NativeP5TransportError)):
            return {
                "native_error_domain": "CJ2534Exception",
                "native_error_code": current.code,
            }
        if isinstance(current, (NativeNegativeResponse, NativeDiagnosticError)):
            return {
                "native_error_domain": "diagnostic_response",
                "diagnostic_response_hex": current.response.hex(),
            }
        current = current.__cause__ or current.__context__
    return {"native_error_domain": None, "native_error_code": None}


def common_block_request(
    operation: str, first: int, last: int, *, wide: bool = False
) -> bytes:
    """Native one-based common-CAN block indices (CUW18 2920/2af0/32c0/34b0)."""
    commands = {"blank": 0x35, "erase": 0x25, "inverify": 0x47, "verify": 0x15}
    if operation not in commands or type(wide) is not bool:
        raise ValueError("Unknown common block operation or width")
    if (
        type(first) is not int
        or type(last) is not int
        or not 1 <= first <= last <= (65536 if wide else 256)
    ):
        raise ValueError("Invalid one-based block range")
    if not wide and first != last:
        raise ValueError("Narrow command addresses exactly one block")
    if wide:
        return (
            bytes((commands[operation] + 1,))
            + (first - 1).to_bytes(2, "big")
            + (last - 1).to_bytes(2, "big")
        )
    return bytes((commands[operation], first - 1))


def common_auth_frames(value: bytes, *, key: bool = False) -> tuple[bytes, ...]:
    """Native nonce/key16-byte slices; caller supplies authorized material."""
    if not isinstance(value, bytes) or len(value) != 16 or type(key) is not bool:
        raise ValueError("Explicit16-byte nonce or authorized key required")
    base = 0x3A if key else 0x37
    return (
        bytes((base,)) + value[:6],
        bytes((base + 1,)) + value[6:12],
        bytes((base + 2,)) + value[12:],
    )


class VendorCAN:
    """Raw common-CAN stream, separate from UDS request/positive-response exchange.

    write returns the actual number of complete messages accepted (exactly one).
    read returns one identifier-filtered payload; unrelated frames are not ACKs.
    Both callbacks must obey their remaining deadline. Late or partial writes
    retain uncertainty and are never resent. wait is an explicit replay seam.
    """

    def __init__(
        self,
        write: Callable[[bytes, float], int],
        read: Callable[[float], bytes],
        *,
        timeout: float = 30,
        cancelled: Callable[[], bool] = lambda: False,
        clock: Callable[[], float] = time.monotonic,
        wait: Callable[[int, float], None] | None = None,
    ):
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("Finite positive deadline required")
        self.write_callback, self.read_callback = write, read
        self.cancelled, self.clock, self.wait_callback = cancelled, clock, wait
        self.deadline = clock() + timeout
        self.attempted = False
        self.history: list[dict] = []
        self.received = 0
        self.retained = 0
        self.transferred = 0

    def remaining(self) -> float:
        if self.cancelled():
            raise InterruptedError("Vendor operation cancelled")
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise TimeoutError("Vendor operation deadline expired")
        return remaining

    def wait(self, milliseconds: int) -> None:
        _uint(milliseconds, 32, "Wait milliseconds")
        if milliseconds:
            if self.wait_callback is None:
                raise ValueError("Nonzero native wait requires explicit wait provider")
            try:
                self.wait_callback(milliseconds, self.remaining())
            except (Exception, KeyboardInterrupt):
                self.remaining()
                raise
        self.remaining()

    def write(self, payload: bytes) -> None:
        if not isinstance(payload, bytes) or not 1 <= len(payload) <= 4095:
            raise ValueError("Bounded immutable CAN payload required")
        remaining = self.remaining()
        if len(self.history) >= 65536:
            raise ValueError("Host operation budget exceeded")
        self.attempted = True
        try:
            count = self.write_callback(payload, remaining)
        except (Exception, KeyboardInterrupt):
            self.remaining()
            raise
        self.remaining()
        if type(count) is not int or count != 1:
            raise OSError("Partial or unproven CAN message write")
        self.history.append({"write_prefix": payload[:2].hex(), "length": len(payload)})

    def read(self) -> bytes:
        if self.received >= 65536:
            raise ValueError("Host receive budget exceeded")
        remaining = self.remaining()
        try:
            response = self.read_callback(remaining)
        except (Exception, KeyboardInterrupt):
            self.remaining()
            raise
        self.received += 1
        self.remaining()
        if not isinstance(response, bytes) or not 1 <= len(response) <= 4095:
            raise ValueError("Malformed CAN response")
        self.retained += len(response)
        if self.retained > 1024 * 1024:
            raise ValueError("Host receive byte budget exceeded")
        return response

    def ack(self) -> None:
        # Native ignores non-ACK frames until single byte3c; deadline bounds it.
        while self.read() != b"\x3c":
            pass

    def command(self, payload: bytes, *, ack: bool = True) -> None:
        self.write(payload)
        if ack:
            self.ack()

    def status(self, *, retries: int = 3) -> int:
        _uint(retries, 8, "Status retry count")
        # Native2310 catches CPassThru4 from ACK(false), not raw driver errors.
        for attempt in range(retries + 1):
            self.write(b"\x50")
            try:
                self._status_ack()
                response = self.read()
                if not response:
                    raise ValueError(
                        "Common status must contain its native status byte"
                    )
                self._status_ack()
                return response[0]
            except VendorStatusAckError:
                if attempt == retries:
                    raise
        raise AssertionError("Unreachable status loop")

    def _status_ack(self) -> None:
        try:
            self.ack()
        except (NativeTransportError, NativeP5TransportError) as error:
            if error.code not in (9, 16):
                raise
            raise VendorStatusAckError("Native GetStatus ACK failed") from error

    def poll(
        self, *, wait_ms: int = 0, busy: int | None = None, retries: int = 3
    ) -> int:
        for _ in range(4096):
            self.wait(wait_ms)
            status = self.status(retries=retries)
            if (
                (status == busy)
                if busy is not None
                else (status != 0 and status & 15 == 0)
            ):
                continue
            return status
        raise TimeoutError("Host status poll limit exceeded")

    def _operation_ack(self, code: int) -> None:
        try:
            self.ack()
        except (NativeTransportError, NativeP5TransportError) as error:
            if error.code not in (9, 16):
                raise
            raise VendorOperationError(code, "Native operation ACK failed") from error

    def _operation_status(
        self, code: int, *, wait_ms: int = 0, busy: int | None = None
    ) -> int:
        try:
            return self.poll(wait_ms=wait_ms, busy=busy)
        except VendorStatusAckError as error:
            raise VendorOperationError(
                code, "Native operation status ACK failed"
            ) from error

    def common_block(
        self,
        operation: str,
        first: int,
        last: int,
        *,
        wide: bool = False,
        wait_ms: int = 0,
    ) -> bool:
        request = common_block_request(operation, first, last, wide=wide)
        code = {"blank": 11, "erase": 12, "inverify": 14}[operation]
        self.write(request)
        self._operation_ack(code)
        status = self._operation_status(
            code, wait_ms=wait_ms, busy={"blank": 0x10, "inverify": 0x40}.get(operation)
        )
        if operation == "blank":
            return status == 0
        if status:
            raise VendorOperationError(
                code, f"Native {operation} failed with status{status:02x}"
            )
        return True

    def check_id(
        self,
        location_id: bytes,
        password: int,
        *,
        swap_endian: bool = False,
        wait_ms: int = 0,
        first_timeout_ms: int = 0,
        set_timeout: Callable[[int, float], None] | None = None,
    ) -> bytes:
        frames = common_check_id_frames(location_id, password, swap_endian=swap_endian)
        _uint(first_timeout_ms, 32, "Initial timeout")
        if first_timeout_ms and set_timeout is None:
            raise ValueError(
                "Initial timeout requires explicit transport configuration"
            )
        for frame in frames[:-1]:
            self.write(frame)
            self.wait(wait_ms)
        self.write(frames[-1])
        try:
            self.ack()
        except (NativeTransportError, NativeP5TransportError) as error:
            if error.code not in (9, 16):
                raise
            raise VendorInitialCommandError("Native CheckID ACK failed") from error
        if first_timeout_ms:
            assert set_timeout is not None
            set_timeout(first_timeout_ms, self.remaining())
        response = self.read()
        self.write(b"\x3c")
        return response

    def memory_info(self, *, wide: bool = False) -> dict:
        if type(wide) is not bool:
            raise ValueError("Boolean wide-address flag required")
        self.write(b"\x76")
        extended = True
        try:
            self.ack()
        except (NativeTransportError, NativeP5TransportError) as exc:
            if exc.code not in (9, 16):
                raise
            extended = False
            self.write(b"\x75")
            self._operation_ack(10)
        data = self.read()
        expected = 11 if extended and wide else 9 if extended else 8
        if len(data) != expected:
            raise VendorOperationError(
                10, "Native memory response has incorrect length"
            )
        meaningful = data[:-1] if extended else data
        info = common_memory_info(meaningful)
        self._operation_ack(10)
        return dict(info, extended=extended)

    def common_write(
        self,
        address: int,
        data: bytes,
        *,
        send_type: int = 0,
        wide: bool = False,
        wait_ms: int = 0,
        first_wait_ms: int = 0,
        progress: Callable[[int], None] | None = None,
    ) -> None:
        """CUW18 WriteBlock41→address/count→data→45 continuation→status."""
        _uint(address, 32 if wide else 24, "Address")
        if type(send_type) is not int or send_type not in (0, 1, 2):
            raise ValueError("Native send type must be0,1,2")
        width = (1024, 512, 128)[send_type]
        if (
            not isinstance(data, bytes)
            or not 0 < len(data) <= 64 * 1024 * 1024
            or len(data) % width
            or address + len(data) > 1 << (32 if wide else 24)
        ):
            raise ValueError("Native common writer requires complete aligned chunks")
        self.write(b"\x41")
        self._operation_ack(13)
        self.write(address.to_bytes(4 if wide else 3, "big") + bytes((width // 4 - 1,)))
        self.wait(first_wait_ms)
        for offset in range(0, len(data), width):
            if offset:
                self.write(b"\x45")
                self._operation_ack(13)
            self.write(data[offset : offset + width])
            if progress is not None:
                progress(width)
                self.remaining()
            self._operation_ack(13)
            status = self._operation_status(13, wait_ms=wait_ms)
            if status:
                raise VendorOperationError(
                    13, f"Native write failed with status{status:02x}"
                )
            self.transferred += width

    def common_verify(
        self,
        first: int,
        last: int,
        data: bytes,
        *,
        wide: bool = False,
        wait_ms: int = 0,
        variant2: bool = False,
        progress: Callable[[int], None] | None = None,
    ) -> None:
        request = common_block_request("verify", first, last, wide=wide or variant2)
        if type(variant2) is not bool:
            raise ValueError("Boolean verify variant required")
        width = 128 if variant2 else 256
        if variant2:
            request = b"\x18" + request[1:]
        if (
            not isinstance(data, bytes)
            or not 0 < len(data) <= 64 * 1024 * 1024
            or len(data) % width
        ):
            raise ValueError(
                "Native common verify requires complete native-size chunks"
            )
        self.write(request)
        self._operation_ack(15)
        for offset in range(0, len(data), width):
            self.write(data[offset : offset + width])
            if progress is not None:
                progress(width)
                self.remaining()
            self._operation_ack(15)
            last_chunk = offset + width == len(data)
            try:
                status = self.poll(wait_ms=wait_ms, retries=3 if last_chunk else 0)
            except VendorStatusAckError as error:
                if last_chunk:
                    raise VendorOperationError(
                        15, "Native verify status ACK failed"
                    ) from error
                continue  # Native VerifyBlock catches only CPassThru on nonfinal status.
            if status:
                raise VendorOperationError(15, "Native verify failed")

    def common_verify2(
        self,
        first: int,
        last: int,
        data: bytes,
        *,
        wait_ms: int = 0,
        progress: Callable[[int], None] | None = None,
    ) -> None:
        self.common_verify(
            first,
            last,
            data,
            wide=True,
            wait_ms=wait_ms,
            variant2=True,
            progress=progress,
        )

    def auth(self, value: bytes, *, key: bool = False, wait_ms: int = 0) -> None:
        frames = common_auth_frames(value, key=key)
        for frame in frames[:-1]:
            self.write(frame)
            self.wait(wait_ms)
        self.write(frames[-1])
        self._operation_ack(72 if key else 71)

    def auth_combined(self, nonce: bytes, key: bytes, *, wait_ms: int = 0) -> None:
        frames = common_auth_frames(nonce) + common_auth_frames(key, key=True)
        for frame in frames[:-1]:
            self.write(frame)
            self.wait(wait_ms)
        self.write(frames[-1])
        self._operation_ack(72)

    def detect_falsify(self) -> None:
        self.write(b"\x47")
        self._operation_ack(73)
        if self._operation_status(73, busy=0x50):
            raise VendorOperationError(73, "Native falsification check failed")

    def finish(self, *, acknowledge: bool = True) -> None:
        if type(acknowledge) is not bool:
            raise ValueError("Boolean finish ACK policy required")
        self.write(b"\x80")
        if acknowledge:
            self._operation_ack(35)

    def check_finish(self) -> bytes:
        """Native CheckFinishReprogramming1360: send3e, read one payload."""
        self.write(b"\x3e")
        return self.read()

    def change_cpu(self) -> None:
        self.write(b"\x65")
        self._operation_ack(19)


def common_prepare_requests(*, recovery_mode: bool = False) -> tuple[bytes, bytes]:
    """Common ChangeMode sends10/02 or10/60; expected native prefix is50."""
    if type(recovery_mode) is not bool:
        raise ValueError("Boolean mode required")
    return (bytes((0x10, 0x60 if recovery_mode else 2)), b"\x50")


# Packet families below consume explicit decoded calibration records; they never
# infer signed/authenticated material from a target identifier.
from dataclasses import dataclass

from scripts.calibration import crc16
from scripts.programming import (
    NativeDiagnosticError as BaseNativeDiagnosticError,
)
from scripts.programming import (
    NativeNegativeResponse,
    NativePendingTimeout,
    NativeProgrammingChannel,
    NativeUnexpectedResponse,
)
from scripts.programming import (
    NativeTransportError as NativeP5TransportError,
)


@dataclass(frozen=True)
class VendorSegment:
    address: int
    data: bytes
    checksum: bytes = b""

    def __post_init__(self) -> None:
        _uint(self.address, 32, "Segment address")
        if (
            not isinstance(self.data, bytes)
            or not 0 < len(self.data) <= 64 * 1024 * 1024
            or self.address + len(self.data) > 1 << 32
        ):
            raise ValueError("Bounded immutable nonempty segment required")
        if not isinstance(self.checksum, bytes) or len(self.checksum) not in (0, 2):
            raise ValueError("Segment checksum must be absent or supplied two bytes")


def psa_download_request(selector: int, address: int, data: bytes) -> bytes:
    """PSA native34: selector, low24address, length8, data, CRC16 little endian."""
    _uint(selector, 8, "PSA selector")
    _uint(address, 24, "PSA address")
    if not isinstance(data, bytes) or not 1 <= len(data) <= 255:
        raise ValueError("PSA record must contain1..255 bytes")
    request = (
        bytes((0x34, selector))
        + address.to_bytes(3, "big")
        + bytes((len(data),))
        + data
    )
    return request + crc16(request).to_bytes(2, "little")


def psa_identification_request(identification: bytes) -> bytes:
    """Native metadata body has22 supplied bytes, reserved zeros and two CRCs."""
    if not isinstance(identification, bytes) or len(identification) != 22:
        raise ValueError("PSA identification requires22 supplied bytes")
    field = identification[:2] + b"\0\0" + identification[2:] + b"\xff" * 21 + b"\x5c"
    body = b"\x34\x83\0\0\0\x30" + field + crc16(field).to_bytes(2, "little")
    return body + crc16(body).to_bytes(2, "little")


def _vendor_result(
    channel: NativeProgrammingChannel, family: str, action: Callable[[], None]
) -> dict:
    result = {
        "family": family,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "programming_completed": False,
        "automatic_retry": False,
        "provenance": "static-native-vendor-flow",
        "history": channel.history,
    }
    try:
        action()
        if channel.cancelled():
            raise InterruptedError("Vendor operation cancelled")
        if channel.clock() >= channel.deadline:
            raise TimeoutError("Vendor operation completed after deadline")
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - uncertain exchange must survive
        result.update(_native_error_info(exc))
        chain = _error_chain(exc)
        observed = chain[-1]
        result["error_chain"] = chain
        if channel.cancelled():
            exc = InterruptedError("Vendor operation cancelled")
        elif channel.clock() >= channel.deadline:
            exc = TimeoutError("Vendor operation deadline expired")
        result["observed_error"] = observed
        result.update(
            state="recovery_required"
            if channel.attempted
            else (
                "cancelled"
                if isinstance(exc, (InterruptedError, KeyboardInterrupt))
                else "failed"
            ),
            error=str(exc),
        )
    else:
        result["state"] = "writer_completed"
    return result


def psa_write(
    channel: NativeProgrammingChannel,
    selector: int,
    records: tuple[VendorSegment, ...],
    identification: bytes,
    *,
    wait: Callable[[int, float], None],
    diagnostic_session: bool = False,
) -> dict:
    """PSA erase, records, check, metadata and communication/session finish.

    Channel must bind the original old-CAN utility semantics. Flow-control filter
    lifecycle is the caller's explicit transport session, not synthesized here.
    """
    if (
        not isinstance(records, tuple)
        or not 1 <= len(records) <= 65536
        or any(not isinstance(s, VendorSegment) for s in records)
    ):
        raise ValueError("Immutable bounded PSA record tuple required")
    packets = tuple(psa_download_request(selector, s.address, s.data) for s in records)
    metadata = psa_identification_request(identification)
    if type(diagnostic_session) is not bool:
        raise ValueError("Boolean session selection required")

    def call(request: bytes, expected: bytes, code: int) -> bytes:
        return native_utility_call(channel, request, expected, code)

    def poll(routine: int) -> None:
        for _ in range(4096):
            response = call(
                bytes((0x31, routine, 1)),
                bytes((0x71, routine)),
                61 if routine == 0x81 else 63,
            )
            if len(response) < 3:
                raise VendorOperationError(
                    61 if routine == 0x81 else 63, "PSA routine status is truncated"
                )
            wait(250, channel.deadline - channel.clock())
            if channel.cancelled():
                raise InterruptedError("PSA poll cancelled")
            if channel.clock() >= channel.deadline:
                raise TimeoutError("PSA routine deadline expired")
            if response[2] in (0, 1):
                continue
            if response[2] != 2:
                raise VendorOperationError(
                    61 if routine == 0x81 else 63, "PSA routine failed"
                )
            return
        raise TimeoutError("PSA routine host poll budget exceeded")

    def run() -> None:
        call(bytes((0x31, 0x81, selector, 0xF0, 0x5A)), b"\x71\x81\x01", 61)
        poll(0x81)
        for packet in packets:
            call(packet, b"\x74\x02", 62)
        call(b"\x31\x82\0", b"\x71\x82\x01", 63)
        poll(0x82)
        call(metadata, b"\x74\x02", 64)
        call(
            b"\x10\x81" if diagnostic_session else b"\x82",
            b"\x50\x81" if diagnostic_session else b"\xc2",
            58,
        )

    return _vendor_result(channel, "PSA", run)


def psa_prepare(
    channel: NativeProgrammingChannel,
    key_provider: Callable[[bytes], bytes | Literal[False]],
    *,
    diagnostic_session: bool = False,
    periodic: Callable[[bool, bytes, int, float], None],
) -> dict:
    """Original81start or10/c0session,27/81four-byte seed, supplied27/82key."""
    if not callable(key_provider) or type(diagnostic_session) is not bool:
        raise ValueError("Explicit authorized key provider and boolean mode required")

    def call(request: bytes, expected: bytes) -> bytes:
        return native_utility_call(
            channel,
            request,
            expected,
            vendor_utility_error_code("PSA", "prepare", request),
        )

    def run() -> None:
        call(
            b"\x10\xc0" if diagnostic_session else b"\x81",
            b"\x50\xc0" if diagnostic_session else b"\xc1\xd0\x8f",
        )
        seed = call(b"\x27\x81", b"\x67\x81")
        if len(seed) < 6:
            raise VendorOperationError(16, "PSA seed response requires four bytes")
        try:
            periodic(True, b"\x3e", 2000, channel.deadline - channel.clock())
            key = key_provider(seed[2:6])
        finally:
            periodic(False, b"\x3e", 2000, max(0.0, channel.deadline - channel.clock()))
        if key is False:
            raise VendorOperationError(
                17, "Native authorization provider denied the request"
            )
        if not isinstance(key, bytes) or len(key) != 4:
            raise ValueError("PSA provider must supply four authorized key bytes")
        call(b"\x27\x82" + key, b"\x67\x82")

    result = _vendor_result(channel, "PSA-prepare", run)
    if result["state"] == "writer_completed":
        result["state"] = "prepare_completed"
    return result


def mmc_download_request(segment: VendorSegment, selector: int) -> bytes:
    _uint(selector, 8, "MMC selector")
    return (
        bytes((0x34, selector, 0x44))
        + segment.address.to_bytes(4, "big")
        + len(segment.data).to_bytes(4, "big")
    )


def mmc_write(
    channel: NativeProgrammingChannel,
    loader: tuple[VendorSegment, ...],
    image: tuple[VendorSegment, ...],
    *,
    loader_selector: int,
    image_selector: int,
    loader_routine: bytes,
    erase_areas: tuple[tuple[int, int], ...],
) -> dict:
    """MMC loader→0301start→ff00erase→image→0304finish flow.

    Each supplied segment includes the two native expected CRC response bytes;
    these bytes are calibration material, not a newly guessed checksum recipe.
    """
    for segments in (loader, image):
        if (
            not isinstance(segments, tuple)
            or not 1 <= len(segments) <= 4096
            or any(
                not isinstance(s, VendorSegment) or len(s.checksum) != 2
                for s in segments
            )
        ):
            raise ValueError(
                "MMC requires bounded loader/image segments with supplied CRC"
            )
    if sum(len(segment.data) for segment in loader + image) > 64 * 1024 * 1024:
        raise ValueError("MMC aggregate image limit exceeded")
    if not isinstance(loader_routine, bytes) or len(loader_routine) != 4:
        raise ValueError("MMC loader routine requires four bytes")
    if not isinstance(erase_areas, tuple) or not 1 <= len(erase_areas) <= 4096:
        raise ValueError("MMC erase areas required")
    packets = []
    for address, size in erase_areas:
        _uint(address, 32, "Erase address")
        _uint(size, 32, "Erase size")
        if not size or address + size > 1 << 32:
            raise ValueError("Invalid erase area")
        packets.append(
            b"\x31\x01\xff\x00" + address.to_bytes(4, "big") + size.to_bytes(4, "big")
        )
    for segments, selector in ((loader, loader_selector), (image, image_selector)):
        for segment in segments:
            mmc_download_request(segment, selector)

    def call(request: bytes, expected: bytes) -> bytes:
        return _p5_call(
            channel,
            request,
            expected,
            90 if request.startswith(b"\x31\x01\xff\0") else 10,
            vendor_utility_error_code("MMC", "write", request),
        )

    def transfer(segments: tuple[VendorSegment, ...], selector: int) -> None:
        for segment in segments:
            response = call(mmc_download_request(segment, selector), b"\x74\x20")
            if len(response) < 4:
                raise VendorOperationError(
                    26, "MMC response requires16-bit maximum block size"
                )
            width = min(int.from_bytes(response[2:4], "big"), 4095) - 2
            if width <= 0:
                raise ValueError("MMC block length cannot contain data")
            for index, offset in enumerate(range(0, len(segment.data), width), 1):
                sequence = index & 255
                call(
                    bytes((0x36, sequence)) + segment.data[offset : offset + width],
                    bytes((0x76, sequence)),
                )
            call(b"\x37", b"\x77" + segment.checksum)

    def run() -> None:
        transfer(loader, loader_selector)
        call(b"\x31\x01\x03\x01" + loader_routine, b"\x71\x01\x03\x01\x10")
        for packet in packets:
            call(packet, b"\x71\x01\xff\x00\x10")
        transfer(image, image_selector)
        call(b"\x31\x01\x03\x04", b"\x71\x01\x03\x04\x10\x02")

    return _vendor_result(channel, "MMC", run)


def common_check_id_frames(
    location_id: bytes, password: int, *, swap_endian: bool = False
) -> tuple[bytes, ...]:
    """CheckID five frames: supplied location8 and authorized password uint32."""
    _uint(password, 32, "Authorized password")
    if (
        not isinstance(location_id, bytes)
        or len(location_id) != 8
        or type(swap_endian) is not bool
    ):
        raise ValueError(
            "Supplied eight-byte location ID and boolean byte order required"
        )
    secret = password.to_bytes(4, "big")
    if swap_endian:
        location_id = b"".join(location_id[i : i + 2][::-1] for i in range(0, 8, 2))
        secret = secret[::-1]
    return (
        b"\0",
        b"\0",
        bytes(location_id[i] for i in (7, 6, 3, 2, 1, 0)),
        location_id[5:3:-1],
        secret[::-1],
    )


def common_memory_info(data: bytes) -> dict:
    """FlashWriterUtils1140: start3/4,end3/4,blocksizeKiB,firmware descriptor."""
    if not isinstance(data, bytes) or len(data) not in (8, 10):
        raise ValueError("Common memory descriptor must contain8 or10 bytes")
    width = 3 if len(data) == 8 else 4
    return {
        "address": int.from_bytes(data[:width], "big"),
        "end_address": int.from_bytes(data[width : width * 2], "big"),
        "block_size_kib": data[width * 2],
        "firmware_descriptor": data[width * 2 + 1],
    }


class NativeTransportError(OSError):
    """Provider-retained native transport error code; no invented retry class."""

    def __init__(self, code: int, message: str):
        self.code = _uint(code, 32, "Native transport error code")
        super().__init__(message)


class VendorUtilityTimeout(TimeoutError):
    """A recovered native utility pending/busy cap, not a host deadline."""

    def __init__(self, message: str, response: bytes | None = None):
        self.response = response
        super().__init__(message)


class VendorOperationError(BaseNativeDiagnosticError):
    """A proven native CPassThru operation failure, distinct from driver errors."""

    def __init__(self, code: int, message: str, response: bytes | None = None):
        self.code = _uint(code, 32, "Native CPassThru operation code")
        self.response = response
        super().__init__(message)


class VendorStatusAckError(ValueError):
    """Native status ACK false is CPassThruException4, distinct from driver I/O."""

    code = 4


class VendorInitialCommandError(OSError):
    """Native CheckID ACK false becomes CPassThruException code7 only."""

    code = 7


class NativeDiagnosticError(BaseNativeDiagnosticError):
    """Actual negative reply, retained for native explicitly permitted branches."""

    def __init__(self, response: bytes):
        self.response = response
        super().__init__(f"Negative vendor reply{response[:3].hex()}")


class VendorDiagnosticChannel(NativeProgrammingChannel):
    """Old CUW CAN utility: NRC21 resend, NRC78 receive, bounded native counters.

    Cleanup sends single-byte3e without waiting; it must be an explicit raw-write
    provider returning one complete message. Transport exceptions are never retried.
    """

    def __init__(
        self,
        *args,
        send_cleanup: Callable[[str, bytes], int] | None = None,
        pending_limit: int = 149,
        busy_limit: int = 255,
        get_timeout: Callable[[], int] | None = None,
        set_timeout: Callable[[int], None] | None = None,
        pending_timeout_ms: int = 5000,
        address_extension: int | None = None,
        response_address_extension: int | None = None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.pending_limit = _uint(pending_limit, 16, "Pending limit")
        self.busy_limit = _uint(busy_limit, 16, "Busy limit")
        self.address_extension = address_extension
        self.response_address_extension = (
            address_extension
            if response_address_extension is None
            else _uint(
                response_address_extension, 8, "Diagnostic response address extension"
            )
        )
        if address_extension is not None:
            _uint(address_extension, 8, "Diagnostic address extension")
        self.send_cleanup = send_cleanup
        if (get_timeout is None) != (set_timeout is None):
            raise ValueError("Native timeout controls must be supplied together")
        self.get_timeout = get_timeout
        self.set_timeout = set_timeout
        self.pending_timeout_ms = _uint(
            pending_timeout_ms, 32, "Native pending timeout"
        )

    def call(self, request: bytes, expected: bytes | None) -> bytes:
        saved = None

        def boundary() -> None:
            if self.cancelled():
                raise InterruptedError("Vendor diagnostic exchange cancelled")
            if self.clock() >= self.deadline:
                raise TimeoutError("Vendor diagnostic deadline expired")

        try:
            boundary()
            if self.get_timeout is not None:
                saved = _uint(self.get_timeout(), 32, "Saved native timeout")
                boundary()
            return self._call(request, expected, saved)
        except (Exception, KeyboardInterrupt):
            boundary()
            raise
        finally:
            if saved is not None:
                assert self.set_timeout is not None
                try:
                    self.set_timeout(saved)
                    boundary()
                except (Exception, KeyboardInterrupt):
                    boundary()
                    raise

    def _call(
        self, request: bytes, expected: bytes | None, saved_timeout: int | None
    ) -> bytes:
        if (
            not isinstance(request, bytes)
            or not 1 <= len(request) <= 4095
            or (
                expected is not None
                and (
                    not isinstance(expected, bytes)
                    or not expected
                    or len(expected) > 4095
                )
            )
        ):
            raise ValueError("Bounded immutable diagnostic request/prefix required")

        prefix = (
            b"" if self.address_extension is None else bytes((self.address_extension,))
        )
        response_prefix = (
            b""
            if self.response_address_extension is None
            else bytes((self.response_address_extension,))
        )
        if prefix and (not request.startswith(prefix) or len(request) < 2):
            raise ValueError("Request does not contain the bound address extension")
        sid = request[len(prefix)]

        def check() -> None:
            if self.cancelled():
                raise InterruptedError("Vendor diagnostic exchange cancelled")
            if self.clock() >= self.deadline:
                raise TimeoutError("Vendor diagnostic deadline expired")
            if self.received_count >= 65536:
                raise ValueError("Host diagnostic receive budget exceeded")

        def validate(response: bytes) -> bytes:
            self.received_count += 1
            if not isinstance(response, bytes) or not 1 <= len(response) <= 4095:
                raise ValueError("Malformed vendor diagnostic response")
            check()
            return response

        busy = 0
        for _ in range(65536):
            check()
            self.attempted = True
            try:
                response = validate(self.exchange(self.ecu, request))
            except (Exception, KeyboardInterrupt):
                check()
                raise
            pending = 0
            while response.startswith(response_prefix + bytes((0x7F, sid, 0x78))):
                pending += 1
                busy = 0  # Native NRC78 resets the consecutive NRC21 counter.
                if pending > self.pending_limit:
                    if self.send_cleanup is None:
                        raise TimeoutError(
                            "Native pending limit exceeded; explicit3e cleanup provider missing"
                        )
                    check()
                    count = self.send_cleanup(self.ecu, prefix + b"\x3e")
                    if type(count) is not int or count != 1:
                        raise OSError("Unproven native pending cleanup write")
                    raise VendorUtilityTimeout(
                        "Native pending response limit exceeded after3e cleanup",
                        response,
                    )
                if saved_timeout is not None and saved_timeout < 5000:
                    assert self.set_timeout is not None
                    self.set_timeout(self.pending_timeout_ms)
                    check()
                if self.receive is None:
                    raise ValueError(
                        "Pending response requires explicit receive provider"
                    )
                check()
                try:
                    response = validate(self.receive(self.ecu))
                except (Exception, KeyboardInterrupt):
                    check()
                    raise
            is_busy = response.startswith(response_prefix + bytes((0x7F, sid, 0x21)))
            if is_busy:
                busy += 1
                if busy > self.busy_limit:
                    raise VendorUtilityTimeout(
                        "Native busy repeat limit exceeded", response
                    )
            if saved_timeout is not None:
                assert self.set_timeout is not None
                self.set_timeout(saved_timeout)
                check()
            if is_busy:
                continue
            if response.startswith(response_prefix + b"\x7f"):
                raise NativeDiagnosticError(response)
            if expected is not None and not response.startswith(expected):
                raise NativeUnexpectedResponse(request, response)
            self.response_bytes += len(response)
            if self.response_bytes > 1024 * 1024 or len(self.history) >= 65536:
                raise ValueError("Host diagnostic history budget exceeded")
            self.history.append(
                {
                    "request_hex": request[:2].hex(),
                    "response_hex": response.hex(),
                    "busy_repeats": busy,
                    "pending_responses": pending,
                }
            )
            return response
        raise TimeoutError("Host diagnostic exchange attempt limit exceeded")


class VendorP5Channel(NativeProgrammingChannel):
    """NativeP5 utility timeout controls around the shared response engine.

    Initial reads retain the saved transport timeout. max(saved,param11) bounds
    receive-only native driver9/16 retries afterNRC78; those reads use1000ms
    plus the native final fractional adjustment. Every exit restores saved timeout.
    """

    def __init__(
        self,
        *args,
        get_timeout: Callable[[], int],
        set_timeout: Callable[[int], None],
        minimum_response_timeout_ms: int,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        if not callable(get_timeout) or not callable(set_timeout):
            raise TypeError("Concrete native P5 timeout controls required")
        self.get_timeout, self.set_timeout = get_timeout, set_timeout
        self.minimum_response_timeout_ms = _uint(
            minimum_response_timeout_ms, 32, "Native P5 minimum response timeout"
        )

    def call(self, request: bytes, expected: bytes | None) -> bytes:
        if (
            not isinstance(request, bytes)
            or not 1 <= len(request) <= 4095
            or expected is not None
            and (not isinstance(expected, bytes) or not 1 <= len(expected) <= 4095)
        ):
            raise ValueError("Bounded immutable P5 request/prefix required")
        saved = None
        original_receive = self.receive

        def boundary() -> None:
            if self.cancelled():
                raise InterruptedError("Vendor P5 exchange cancelled")
            if self.clock() >= self.deadline:
                raise TimeoutError("Vendor P5 exchange deadline expired")

        def pending_receive(ecu: str) -> bytes:
            assert saved is not None and original_receive is not None
            budget_ms = max(saved, self.minimum_response_timeout_ms)
            whole_seconds = budget_ms // 1000
            self.set_timeout(1000)
            boundary()
            failures = 0
            while True:
                boundary()
                if self.received_count >= 65536:
                    raise ValueError("Host pending-read attempt budget exceeded")
                try:
                    result = original_receive(ecu)
                    boundary()
                    return result
                except (NativeTransportError, NativeP5TransportError) as error:
                    boundary()
                    if error.code not in (9, 16):
                        raise
                    self.received_count += 1
                    failures += 1
                    if failures >= whole_seconds:
                        raise
                    if failures == whole_seconds - 1:
                        self.set_timeout(1000 + budget_ms % 1000)
                        boundary()

        try:
            boundary()
            saved = _uint(self.get_timeout(), 32, "Saved P5 timeout")
            boundary()
            if original_receive is not None:
                self.receive = pending_receive
            return super().call(request, expected)
        except (Exception, KeyboardInterrupt):
            boundary()
            raise
        finally:
            self.receive = original_receive
            if saved is not None:
                try:
                    self.set_timeout(saved)
                    boundary()
                except (Exception, KeyboardInterrupt):
                    boundary()
                    raise


def vendor_utility_error_code(family: str, stage: str, request: bytes) -> int:
    """Recovered literal utility param7; bytes never authorize a source module."""
    families = {
        "Common",
        "MMC",
        "SBR",
        "HINO",
        "HINO-DSS",
        "HINO-VCS",
        "PSA",
        "DH",
        "SoftwareInfo",
    }
    if family not in families or not isinstance(request, bytes) or not request:
        raise ValueError("Known family and nonempty native utility request required")
    if stage == "get_cid" and family != "PSA":
        return (
            92 if family in ("Common", "SoftwareInfo") and request == b"\x1a\x89" else 3
        )
    if stage == "prepare":
        if family == "Common" and request in (b"\x10\x02", b"\x10\x60"):
            return 18 if request[1] == 2 else 49
        seed_services = {
            "PSA": (0x81,),
            "MMC": (0x41,),
            "SBR": (1, 0x33),
            "HINO": (1,),
            "HINO-DSS": (3,),
            "HINO-VCS": (1,),
        }
        if len(request) >= 2 and request[0] == 0x27 and family in seed_services:
            if request[1] in seed_services[family]:
                return 16
            if request[1] in tuple(value + 1 for value in seed_services[family]):
                return 17
        if family == "PSA" and request in (b"\x81", b"\x10\xc0"):
            return 57
        if (
            family in ("MMC", "SBR", "HINO", "HINO-VCS")
            and request == b"\x10\x02"
            or family == "HINO-DSS"
            and request == b"\x10\x85"
        ):
            return 41
        if family == "SBR":
            if request == b"\x22\xf1\0":
                return 97
            if request == b"\x22\x10\x1c":
                return 98
            if request == b"\x31\x01\x02\0":
                return 81
            if request == b"\x31\x01\x02\x01":
                return 49
    if stage == "write" and family in ("MMC", "SBR", "HINO", "HINO-DSS", "HINO-VCS"):
        if request[0] in (0x34, 0x36, 0x37):
            return {0x34: 26, 0x36: 34, 0x37: 28}[request[0]]
        if family.startswith("HINO") and request[0] == 0x11:
            return 24
        prefixes = {
            "MMC": (
                (b"\x31\x01\x03\x01", 70),
                (b"\x31\x01\x03\x04", 68),
                (b"\x31\x01\xff\0", 69),
            ),
            "SBR": ((b"\x31\x01\xff\0", 90), (b"\x31\x01\xff\x01", 89)),
            "HINO": (
                (b"\x31\x01\x10\xff", 89),
                (b"\x31\x01\x10\xfe", 89),
                (b"\x31\x01\x10\xfd", 90),
                (b"\x31\x01\x10\xfc", 90),
            ),
            "HINO-DSS": ((b"\x31\xa2", 89), (b"\x31\xa3", 89), (b"\x31\xa0", 90)),
            "HINO-VCS": (
                (b"\x31\x05", 89),
                (b"\x31\x02", 89),
                (b"\x31\x01", 90),
                (b"\x31\x03", 90),
            ),
        }
        for prefix, code in prefixes[family]:
            if request.startswith(prefix):
                return code
    raise ValueError("No recovered native utility error mapping for this operation")


def native_utility_call(
    channel: NativeProgrammingChannel,
    request: bytes,
    expected: bytes | None,
    native_code: int,
    *,
    old_pending_timeout_ms: int = 5000,
) -> bytes:
    """Apply actual utility param7 only to proven native response failures."""
    _uint(native_code, 32, "Native utility error code")
    _uint(old_pending_timeout_ms, 32, "Native old utility pending timeout")
    previous = (
        (channel.pending_timeout_ms, channel.pending_limit, channel.busy_limit)
        if isinstance(channel, VendorDiagnosticChannel)
        else None
    )
    try:
        if previous is not None:
            assert isinstance(channel, VendorDiagnosticChannel)
            channel.pending_timeout_ms = old_pending_timeout_ms
            channel.pending_limit, channel.busy_limit = 149, 255
        try:
            return channel.call(request, expected)
        except (
            NativeNegativeResponse,
            NativeDiagnosticError,
            NativeUnexpectedResponse,
            NativePendingTimeout,
            VendorUtilityTimeout,
        ) as error:
            response = getattr(error, "response", None)
            raise VendorOperationError(
                native_code, "Native diagnostic utility failed", response
            ) from error
    finally:
        if previous is not None:
            assert isinstance(channel, VendorDiagnosticChannel)
            channel.pending_timeout_ms, channel.pending_limit, channel.busy_limit = (
                previous
            )


def _p5_call(
    channel: NativeProgrammingChannel,
    request: bytes,
    expected: bytes | None,
    seconds: int,
    native_code: int | None = None,
) -> bytes:
    previous = channel.pending_response_timeout_seconds
    channel.pending_response_timeout_seconds = seconds
    try:
        return (
            channel.call(request, expected)
            if native_code is None
            else native_utility_call(channel, request, expected, native_code)
        )
    finally:
        channel.pending_response_timeout_seconds = previous


def _hino_vcs_retry(
    channel: NativeProgrammingChannel,
    request: bytes,
    expected: bytes,
    wait: Callable[[int, float], None],
) -> bytes:
    for attempt in range(3):
        try:
            return native_utility_call(
                channel,
                request,
                expected,
                24 if request[0] == 0x11 else 41,
                old_pending_timeout_ms=6000,
            )
        except (
            NativeDiagnosticError,
            NativeTransportError,
            VendorOperationError,
        ) as exc:
            if isinstance(exc, VendorOperationError) and (
                not isinstance(exc.response, bytes)
                or not exc.response.startswith(b"\x7f")
            ):
                raise
            if (
                attempt == 2
                or isinstance(exc, NativeTransportError)
                and exc.code not in (9, 16)
            ):
                raise
            if channel.cancelled():
                raise InterruptedError("HINO-VCS retry cancelled") from exc
            remaining = channel.deadline - channel.clock()
            if remaining <= 0:
                raise TimeoutError("HINO-VCS retry deadline expired") from exc
            wait(1000, remaining)
    raise AssertionError("Unreachable HINO-VCS retry loop")


def hino_download_request(
    mode: str, segment: VendorSegment, *, selector: int = 1, size: int | None = None
) -> bytes:
    declared_size = (
        len(segment.data)
        if size is None
        else _uint(size, 32, "HINO declared download size")
    )
    if mode == "HINO":
        return (
            b"\x34\0\x44"
            + segment.address.to_bytes(4, "big")
            + declared_size.to_bytes(4, "big")
        )
    if mode == "HINO-VCS":
        _uint(selector, 8, "HINO-VCS selector")
        return (
            bytes((0x34, selector))
            + segment.address.to_bytes(4, "big")
            + declared_size.to_bytes(4, "big")
        )
    if mode == "HINO-DSS":
        _uint(segment.address, 24, "HINO-DSS address")
        # Native1110 constructs the size CBytes but leaves wire size bytes zero.
        return b"\x34" + segment.address.to_bytes(3, "big") + b"\0\0\0"
    raise ValueError("Unknown HINO programming mode")


def hino_write(
    channel: NativeProgrammingChannel,
    mode: str,
    loader: VendorSegment,
    image: VendorSegment,
    *,
    raw_write: Callable[[int, bytes, float], int],
    wait: Callable[[int, float], None],
    loader_size: int | None = None,
    image_size: int | None = None,
) -> dict:
    """Recovered three distinct HINO writer flows; no key or image fabrication."""
    if (
        not isinstance(loader, VendorSegment)
        or not isinstance(image, VendorSegment)
        or len(loader.data) + len(image.data) > 64 * 1024 * 1024
    ):
        raise ValueError("Bounded HINO loader and image required")
    packets = (
        hino_download_request(mode, loader, selector=1, size=loader_size),
        hino_download_request(mode, image, selector=2, size=image_size),
    )

    def call(request: bytes, expected: bytes | None) -> bytes:
        return (
            _p5_call(
                channel,
                request,
                expected,
                180,
                vendor_utility_error_code(mode, "write", request),
            )
            if mode == "HINO"
            else native_utility_call(
                channel,
                request,
                expected,
                vendor_utility_error_code(mode, "write", request),
                old_pending_timeout_ms=6000 if mode == "HINO-VCS" else 5000,
            )
        )

    def delay(milliseconds: int) -> None:
        if channel.cancelled():
            raise InterruptedError("HINO operation cancelled")
        remaining = channel.deadline - channel.clock()
        if remaining <= 0:
            raise TimeoutError("HINO deadline expired")
        wait(milliseconds, remaining)
        if channel.clock() >= channel.deadline:
            raise TimeoutError("HINO wait exceeded deadline")

    def raw(payload: bytes) -> None:
        if channel.cancelled():
            raise InterruptedError("HINO operation cancelled")
        if channel.clock() >= channel.deadline:
            raise TimeoutError("HINO deadline expired")
        channel.attempted = True
        count = raw_write(0x720, payload, channel.deadline - channel.clock())
        if type(count) is not int or count != 1:
            raise OSError("Unproven HINO communication-control write")
        if channel.clock() >= channel.deadline:
            raise TimeoutError("HINO raw write completed after deadline")

    def routine(identifier: bytes) -> None:
        request = (b"\x31\x01" if mode == "HINO" else b"\x31") + identifier
        expected = (
            (b"\x71\x01" if mode == "HINO" else b"\x71")
            + identifier
            + (b"\0" if mode != "HINO-VCS" else b"")
        )
        try:
            call(request, expected)
        except (NativeNegativeResponse, VendorOperationError) as error:
            if (
                mode == "HINO"
                and identifier in (b"\x10\xfd", b"\x10\xfc")
                and isinstance(error.response, bytes)
                and error.response.startswith(b"\x7f\x31\x31")
            ):
                return
            raise

    def transfer(segment: VendorSegment, packet: bytes, *, initial: bool) -> bool:
        try:
            response = call(packet, None)
        except (NativeDiagnosticError, VendorOperationError) as exc:
            if (
                initial
                and mode != "HINO"
                and isinstance(exc.response, bytes)
                and exc.response.startswith(b"\x7f\x34\x11")
            ):
                return False
            raise
        if initial and mode != "HINO" and response.startswith(b"\x7f\x34\x11"):
            return False
        prefix = (
            b"\x74\x01"
            if mode == "HINO-VCS" and initial
            else b"\x74\x02"
            if mode == "HINO-VCS"
            else b"\x74"
        )
        if not response.startswith(prefix):
            raise VendorOperationError(26, "Unexpected HINO download response")
        width = 1024
        if mode == "HINO":
            if len(response) < 3:
                raise VendorOperationError(
                    26, "Truncated HINO negotiated download size"
                )
            size_width = response[1] >> 4
            if not 1 <= size_width <= 15 or len(response) < size_width + 2:
                raise ValueError("Malformed HINO negotiated download size")
            width = min(int.from_bytes(response[2 : 2 + size_width], "big"), 4095) - 2
            if width < 1:
                raise ValueError("HINO negotiated length cannot contain data")
        for sequence, offset in enumerate(range(0, len(segment.data), width), 1):
            counter = bytes((sequence & 255,)) if mode == "HINO" else b""
            call(
                b"\x36" + counter + segment.data[offset : offset + width],
                b"\x76" + counter,
            )
        call(b"\x37", b"\x77")
        return True

    def run() -> None:
        loaded = transfer(loader, packets[0], initial=True)
        if loaded:
            routine(
                b"\x10\xff"
                if mode == "HINO"
                else b"\xa2"
                if mode == "HINO-DSS"
                else b"\x05"
            )
            if mode == "HINO-VCS":
                delay(1000)
        routine(
            b"\x10\xfd"
            if mode == "HINO"
            else b"\xa0"
            if mode == "HINO-DSS"
            else b"\x01"
        )
        transfer(image, packets[1], initial=False)
        routine(
            b"\x10\xfe"
            if mode == "HINO"
            else b"\xa3"
            if mode == "HINO-DSS"
            else b"\x02"
        )
        if mode == "HINO":
            routine(b"\x10\xfc")
        elif mode == "HINO-VCS":
            routine(b"\x03")
        if mode == "HINO-VCS":
            _hino_vcs_retry(channel, b"\x11", b"\x51", wait)
        else:
            call(
                b"\x11\x01" if mode == "HINO" else b"\x11",
                b"\x51\x01" if mode == "HINO" else b"\x51",
            )
        if mode == "HINO-VCS":
            for payload in (b"\xa0\x28\x01", b"\xa0\x85\x01"):
                raw(payload)
        else:
            for payload in (
                b"\xa0\x28\x01",
                b"\x28\x80\x01",
                b"\xa0\x85\x01",
                b"\x85\x81",
            ):
                raw(payload)
        delay(1000)

    return _vendor_result(channel, mode, run)


def hino_prepare(
    channel: NativeProgrammingChannel,
    mode: str,
    key_provider: Callable[[bytes], bytes | Literal[False]],
    *,
    raw_write: Callable[[int, bytes, float], int],
    wait: Callable[[int, float], None],
    configure: Callable[[str, int, float], None] | None = None,
    dcu: bool = False,
) -> dict:
    """HINO native broadcasts/session/security with explicitly authorized keys."""
    if (
        mode not in ("HINO", "HINO-DSS", "HINO-VCS")
        or not callable(key_provider)
        or type(dcu) is not bool
        or mode == "HINO"
        and not callable(configure)
    ):
        raise ValueError(
            "Known HINO mode, authorized provider and boolean DCU flag required"
        )

    def call(request: bytes, expected: bytes) -> bytes:
        return (
            _p5_call(
                channel,
                request,
                expected,
                180,
                vendor_utility_error_code(mode, "prepare", request),
            )
            if mode == "HINO"
            else native_utility_call(
                channel,
                request,
                expected,
                vendor_utility_error_code(mode, "prepare", request),
                old_pending_timeout_ms=6000 if mode == "HINO-VCS" else 5000,
            )
        )

    def run() -> None:
        broadcasts = (
            (b"\xa0\x85\x02", b"\x85\x82", b"\xa0\x28\x02", b"\x28\x81\x01")
            if mode == "HINO"
            else (b"\xa0\x85\x02", b"\x85\x82", b"\xa0\x28\x02", b"\x28\x81\x01")
            if mode == "HINO-DSS"
            else (b"\xa0\x85\x02", b"\xa0\x28\x02")
        )
        for payload in broadcasts:
            if channel.cancelled():
                raise InterruptedError("HINO preparation cancelled")
            if channel.clock() >= channel.deadline:
                raise TimeoutError("HINO preparation deadline expired")
            channel.attempted = True
            count = raw_write(0x720, payload, channel.deadline - channel.clock())
            if type(count) is not int or count != 1:
                raise OSError("Unproven HINO preparation broadcast")
        wait(1000, channel.deadline - channel.clock())
        session = b"\x10\x85" if mode == "HINO-DSS" else b"\x10\x02"
        expected = (
            b"\x50\x85"
            if mode == "HINO-DSS"
            else b"\x50\x02"
            if mode == "HINO"
            else b"\x50"
        )
        response = (
            _hino_vcs_retry(channel, session, expected, wait)
            if mode == "HINO-VCS"
            else call(session, expected)
        )
        if mode == "HINO":
            assert configure is not None
            if len(response) < 6:
                raise VendorOperationError(
                    41, "HINO programming session timing truncated"
                )
            configure(
                "transport_timeout_ms",
                int.from_bytes(response[2:4], "big"),
                channel.deadline - channel.clock(),
            )
            configure(
                "pending_timeout_ms",
                int.from_bytes(response[4:6], "big") * 10,
                channel.deadline - channel.clock(),
            )
        level = 3 if mode == "HINO-DSS" else 1
        width = 4 if mode == "HINO-DSS" or (mode == "HINO" and dcu) else 12
        seed = call(bytes((0x27, level)), bytes((0x67, level)))
        if len(seed) < width + 2:
            raise VendorOperationError(16, "HINO seed truncated")
        if mode == "HINO":
            assert configure is not None
            configure("ecu_block_size", 1, channel.deadline - channel.clock())
        key = key_provider(seed[2 : 2 + width])
        if key is False:
            raise VendorOperationError(
                17, "Native authorization provider denied the request"
            )
        if not isinstance(key, bytes) or len(key) != width:
            raise ValueError("HINO authorized provider returned invalid key width")
        call(
            bytes((0x27, level + 1)) + key,
            bytes((0x67, level + 1)) + (b"\x34" if mode == "HINO-DSS" else b""),
        )

    result = _vendor_result(channel, mode + "-prepare", run)
    if result["state"] == "writer_completed":
        result["state"] = "prepare_completed"
    return result


@dataclass(frozen=True)
class SBRFile:
    segment: VendorSegment
    alfid: int = 0x44
    erase: bool = True
    logical_size: int | None = None
    padded: bool = False

    def __post_init__(self) -> None:
        _uint(self.alfid, 8, "SBR ALFID")
        if (
            not isinstance(self.segment, VendorSegment)
            or not 1 <= self.alfid >> 4 <= 4
            or not 1 <= self.alfid & 15 <= 4
            or type(self.erase) is not bool
            or type(self.padded) is not bool
        ):
            raise ValueError(
                "SBR file requires explicit segment, valid widths and boolean flags"
            )
        size = self.size
        _uint(size, (self.alfid & 15) * 8, "SBR logical size")
        _uint(self.segment.address, (self.alfid >> 4) * 8, "SBR download address")
        if (
            size <= 0
            or size > len(self.segment.data)
            or (not self.padded and size != len(self.segment.data))
        ):
            raise ValueError("SBR logical size must match supplied image/padding")

    @property
    def size(self) -> int:
        return (
            len(self.segment.data) if self.logical_size is None else self.logical_size
        )

    @property
    def area(self) -> bytes:
        return (
            bytes((self.alfid,))
            + self.segment.address.to_bytes(self.alfid >> 4, "big")
            + self.size.to_bytes(self.alfid & 15, "big")
        )


def sbr_write(
    channel: NativeProgrammingChannel,
    files: tuple[SBRFile, ...],
    *,
    raw_write: Callable[[int, bytes, float], int],
    wait: Callable[[int, float], None],
    periodic: Callable[[bool, int, bytes, int, float], None],
    wait_after_function: bool = False,
    sumcheck_timeout_seconds: int = 30,
) -> dict:
    """SBR erase/download/addressed-counterdata/exit/sumcheck per native file."""
    if (
        not isinstance(files, tuple)
        or not 1 <= len(files) <= 4096
        or any(not isinstance(f, SBRFile) for f in files)
        or type(wait_after_function) is not bool
    ):
        raise ValueError("SBR bounded file tuple and explicit wait flag required")

    if sum(len(file.segment.data) for file in files) > 64 * 1024 * 1024:
        raise ValueError("SBR aggregate image limit exceeded")

    def call(request: bytes, expected: bytes) -> bytes:
        return _p5_call(
            channel,
            request,
            expected,
            30,
            vendor_utility_error_code("SBR", "write", request),
        )

    def remaining() -> float:
        if channel.cancelled():
            raise InterruptedError("SBR operation cancelled")
        value = channel.deadline - channel.clock()
        if value <= 0:
            raise TimeoutError("SBR deadline expired")
        return value

    def tester() -> None:
        count = raw_write(0x7DF, b"\x3e\x80", remaining())
        if type(count) is not int or count != 1:
            raise OSError("Unproven SBR tester-present write")
        if wait_after_function:
            wait(60, remaining())
        remaining()

    _uint(sumcheck_timeout_seconds, 22, "SBR sumcheck timeout seconds")

    def routine(file: SBRFile, checking: bool) -> None:
        previous_pending = channel.pending_response_timeout_seconds
        if checking:
            channel.pending_response_timeout_seconds = sumcheck_timeout_seconds or 30
        try:
            periodic(True, 0x7DF, b"\x3e\x80", 2500, remaining())
            mode = int(checking)
            _p5_call(
                channel,
                b"\x31\x01\xff" + bytes((mode,)) + file.area,
                b"\x71\x01\xff" + bytes((mode,)) + (b"\x01" if checking else b""),
                (sumcheck_timeout_seconds or 30) if checking else 30,
                89 if checking else 90,
            )
        finally:
            channel.pending_response_timeout_seconds = previous_pending
            periodic(
                False,
                0x7DF,
                b"\x3e\x80",
                2500,
                max(0.0, channel.deadline - channel.clock()),
            )
        if wait_after_function:
            wait(60, remaining())
        tester()

    def run() -> None:
        for file in files:
            if file.erase:
                routine(file, False)
            response = call(b"\x34\x04" + file.area, b"\x74\x20")
            if len(response) < 4:
                raise VendorOperationError(
                    26, "SBR response lacks maximum block length"
                )
            width = (
                min(int.from_bytes(response[2:4], "big"), 4095) - (file.alfid >> 4) - 2
            )
            if width <= 0:
                raise ValueError("SBR block maximum cannot contain data")
            count = (file.size + width - 1) // width
            if file.padded and len(file.segment.data) != count * width:
                raise ValueError(
                    "SBR padded image must supply every native transfer byte"
                )
            tester()
            for sequence, offset in enumerate(range(0, file.size, width), 1):
                chunk = file.segment.data[
                    offset : offset + width
                    if file.padded
                    else min(offset + width, file.size)
                ]
                counter = sequence & 255
                call(
                    bytes((0x36, counter))
                    + (file.segment.address + offset).to_bytes(4, "big")
                    + chunk,
                    bytes((0x76, counter)),
                )
                tester()
            call(b"\x37", b"\x77")
            tester()
            routine(file, True)

    return _vendor_result(channel, "SBR", run)


def common_cpu_matches(
    descriptor: int,
    cpuid: int,
    *,
    shrink: bool = False,
    configured_shrink: bool = False,
) -> bool:
    _uint(descriptor, 8, "Firmware descriptor")
    _uint(cpuid, 8, "CPU ID")
    if type(shrink) is not bool or type(configured_shrink) is not bool:
        raise ValueError("Boolean shrink settings required")
    return shrink == configured_shrink and cpuid == (
        descriptor & 0x7F if shrink else (descriptor >> 4) & 7
    )


def common_diagnostic_mask(
    raw_write: Callable[[int, bytes, float], int],
    wait: Callable[[int, float], None],
    *,
    wait_ms: int,
    timeout: float = 30,
    clock: Callable[[], float] = time.monotonic,
    cancelled: Callable[[], bool] = lambda: False,
) -> None:
    _uint(wait_ms, 32, "Diagnostic mask wait")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Finite positive deadline required")
    deadline = clock() + timeout

    def boundary() -> float:
        if cancelled():
            raise InterruptedError("Diagnostic mask cancelled")
        remaining = deadline - clock()
        if remaining <= 0:
            raise TimeoutError("Diagnostic mask deadline expired")
        return remaining

    for _ in range(3):
        try:
            count = raw_write(0x720, b"\xa0\x27", boundary())
            boundary()
            if type(count) is not int or count != 1:
                raise OSError("Unproven diagnostic mask write")
            wait(wait_ms, boundary())
            boundary()
        except (Exception, KeyboardInterrupt):
            boundary()
            raise


def sbr_prepare(
    channel: NativeProgrammingChannel,
    gateway: NativeProgrammingChannel,
    key_provider: Callable[[bytes, bytes], bytes | Literal[False]],
    gateway_key_provider: Callable[[bytes], bytes | Literal[False]],
    *,
    raw_write: Callable[[int, bytes, float], int],
    wait: Callable[[int, float], None],
    periodic: Callable[[bool, int, bytes, int, float], None],
    master: bool = False,
    slave: bool = False,
    central_gateway: bool = False,
    unit_status_check: bool = False,
    retry: bool = False,
    cpu_index: int = 0,
    retry_wait_ms: int = 0,
    aes: bool = False,
    wait_after_function: bool = False,
    master_channel: NativeProgrammingChannel | None = None,
    send_all_on_prepare_retry: bool = True,
    gateway_controls: VendorControls | None = None,
    master_controls: VendorControls | None = None,
    main_controls: VendorControls | None = None,
    error_kind: int = 0,
    prepare_retry: bool | None = None,
) -> dict:
    """SBR shared prepare order including gateway3334 authorization and mode0200/0201.

    Channels must share a caller-selected deadline. key_provider consumes actual
    SSM identifier and actual seed; all authorization material is supplied.
    """
    flags = (
        master,
        slave,
        central_gateway,
        unit_status_check,
        retry,
        aes,
        wait_after_function,
        send_all_on_prepare_retry,
    )
    if (
        any(type(flag) is not bool for flag in flags)
        or not callable(key_provider)
        or not callable(gateway_key_provider)
    ):
        raise ValueError("SBR boolean flags and explicit authorized providers required")
    _uint(error_kind, 32, "Native error kind604")
    if prepare_retry is not None and type(prepare_retry) is not bool:
        raise ValueError("Explicit PrepareRetry export state required")
    retry_export = retry if prepare_retry is None else prepare_retry
    _uint(cpu_index, 8, "CPU index")
    _uint(retry_wait_ms, 32, "Retry wait")

    def call(
        target: NativeProgrammingChannel, request: bytes, expected: bytes
    ) -> bytes:
        return _p5_call(
            target,
            request,
            expected,
            30,
            vendor_utility_error_code("SBR", "prepare", request),
        )

    def budget() -> float:
        if channel.cancelled() or gateway.cancelled():
            raise InterruptedError("SBR prepare cancelled")
        value = min(
            channel.deadline - channel.clock(), gateway.deadline - gateway.clock()
        )
        if value <= 0:
            raise TimeoutError("SBR prepare deadline expired")
        return value

    def delay(ms: int) -> None:
        wait(ms, budget())
        budget()

    def raw(identifier: int, payload: bytes) -> None:
        remaining = budget()
        channel.attempted = True
        count = raw_write(identifier, payload, remaining)
        if type(count) is not int or count != 1:
            raise OSError("Unproven SBR preparation write")

    def tester() -> None:
        raw(0x7DF, b"\x3e\x80")
        if wait_after_function:
            delay(60)

    def filtered(controls: VendorControls | None, action: Callable[[], None]) -> None:
        if controls is None:
            action()
            return
        handle = None
        try:
            handle = controls.start_filter()
            budget()
            action()
            budget()
        finally:
            if handle is not None:
                try:
                    controls.stop_filter(handle)
                except (Exception, KeyboardInterrupt):
                    budget()
                    raise
                budget()

    def programming_session(target: NativeProgrammingChannel) -> None:
        try:
            periodic(True, 0x7DF, b"\x3e\x80", 2500, budget())
            call(target, b"\x10\x02", b"\x50\x02")
        finally:
            periodic(
                False,
                0x7DF,
                b"\x3e\x80",
                2500,
                max(0.0, channel.deadline - channel.clock()),
            )
        if wait_after_function:
            delay(60)
        tester()

    def authorization() -> None:
        identification = call(channel, b"\x22\xf1\0", b"\x62\xf1\0")
        if len(identification) < 6:
            raise VendorOperationError(97, "SBR SSM identifier truncated")
        width = 16 if aes else 4
        seed = call(channel, b"\x27\x01", b"\x67\x01")
        if len(seed) < width + 2:
            raise VendorOperationError(16, "SBR seed truncated")
        if not any(seed[2 : 2 + width]):
            return  # Native zero seed is an observed unlocked response.
        tester()
        key = key_provider(identification[3:6], seed[2 : 2 + width])
        if key is False:
            raise VendorOperationError(
                17, "Native authorization provider denied the request"
            )
        if not isinstance(key, bytes) or len(key) != width:
            raise ValueError(
                "SBR key provider must supply the native4/16 authorized bytes"
            )
        call(channel, b"\x27\x02" + key, b"\x67\x02")
        tester()

    def gateway_authorization_body() -> None:
        seed = call(gateway, b"\x27\x33", b"\x67\x33")
        if len(seed) < 18:
            raise VendorOperationError(16, "SBR gateway seed truncated")
        try:
            periodic(True, 0x7DF, b"\x3e\x80", 2500, budget())
            key = gateway_key_provider(seed[2:18])
        finally:
            periodic(
                False,
                0x7DF,
                b"\x3e\x80",
                2500,
                max(0.0, channel.deadline - channel.clock()),
            )
        if wait_after_function:
            delay(60)
        if key is False:
            raise VendorOperationError(
                17, "Native authorization provider denied the request"
            )
        if not isinstance(key, bytes) or len(key) != 256:
            raise ValueError("SBR gateway requires256 supplied authorized key bytes")
        call(gateway, b"\x27\x34" + key, b"\x67\x34")

    def gateway_routine(mode: int) -> None:
        def operation() -> None:
            if mode == 1:
                tester()
            call(
                gateway,
                b"\x31\x01\x02" + bytes((mode,)),
                b"\x71\x01\x02" + bytes((mode,)),
            )

        filtered(gateway_controls, operation)

    def gateway_authorization() -> None:
        filtered(gateway_controls, gateway_authorization_body)
        gateway_routine(0)

    def run() -> None:
        if retry_export and not send_all_on_prepare_retry:
            for identifier in (0x7DF, 0x7DE, 0x782):
                raw(identifier, b"\x10\x63")
                if wait_after_function:
                    delay(100)
            raw(0x7DF, b"\x10\x03")
            delay(100)
            gateway_authorization()
            if not central_gateway:
                if wait_after_function:
                    delay(220)
                gateway_routine(1)
            return
        if error_kind != 0 or cpu_index != 1:
            delay(retry_wait_ms if retry and retry_wait_ms else 10000)
            for identifier in (0x7DF, 0x7DE, 0x782):
                raw(identifier, b"\x10\x63")
                if wait_after_function:
                    delay(100)
            raw(0x7DF, b"\x10\x03")
            delay(100)
            if not central_gateway or not retry:
                gateway_authorization()
            raw(0x7DF, b"\x85\x02")
            if wait_after_function:
                delay(150)
            tester()
            delay(120)
            raw(0x7DF, b"\x28\x03\x01")
            if wait_after_function:
                delay(100)
            tester()
            if not wait_after_function:
                delay(100)
            if not central_gateway:
                gateway_routine(1)
        if slave and (error_kind != 0 or cpu_index == 0):
            if master_channel is None:
                raise ValueError(
                    "SBR slave preparation requires explicit master channel"
                )
            selected_master = master_channel
            filtered(master_controls, lambda: programming_session(selected_master))

        def main_operation() -> None:
            if master or slave:
                call(channel, b"\x22\x10\x1c", b"\x62\x10\x1c\x01")
                tester()
                programming_session(channel)
                authorization()
            else:
                authorization()
                if unit_status_check:
                    call(channel, b"\x22\x10\x1c", b"\x62\x10\x1c\x01")
                    tester()
                programming_session(channel)

        filtered(main_controls, main_operation)

    result = _vendor_result(channel, "SBR-prepare", run)
    result["gateway_history"] = gateway.history
    if result["state"] == "writer_completed":
        result["state"] = "prepare_completed"
    return result


def _identifier_bytes(response: bytes, prefix: bytes, width: int) -> bytes:
    if (
        not isinstance(response, bytes)
        or not response.startswith(prefix)
        or len(response) < len(prefix) + width
    ):
        raise VendorOperationError(3, "Truncated or mismatched native identifier")
    return response[len(prefix) : len(prefix) + width].split(b"\0", 1)[0]


def common_cid_response(
    response: bytes, *, address_extension: int | None = None
) -> tuple[bytes, ...]:
    """CommonGetCID1960: optional address byte,4904,count,16-byte records."""
    prefix = b"\x49\x04"
    if address_extension is not None:
        _uint(address_extension, 8, "CAN address extension")
        prefix = bytes((address_extension,)) + prefix
    if (
        not isinstance(response, bytes)
        or not response.startswith(prefix)
        or len(response) < len(prefix) + 17
    ):
        raise VendorOperationError(
            3, "Common CID response requires one complete native record"
        )
    count = response[len(prefix)]
    if len(response) != len(prefix) + 1 + 16 * count:
        raise VendorOperationError(3, "Common CID count disagrees with response length")
    records = response[len(prefix) + 1 :]
    return tuple(
        value
        for offset in range(0, len(records), 16)
        if (value := records[offset : offset + 16].split(b"\0", 1)[0])
    )


def sbr_identifiers(
    data: bytes, *, ascii_records: bool, rom_width: int = 16
) -> tuple[bytes | str, ...]:
    """SBR native1a80 ASCII16 stride or binary5 uppercase hex (short leftpad)."""
    if (
        not isinstance(data, bytes)
        or len(data) > 4095
        or type(ascii_records) is not bool
    ):
        raise ValueError("Bounded identifier bytes and boolean format required")
    _uint(rom_width, 8, "SBR ROM identifier width")
    if not rom_width or (ascii_records and rom_width > 16):
        raise ValueError("SBR ASCII ROM width must be1..16")
    if ascii_records:
        if len(data) % 16:
            raise ValueError("SBR ASCII records must contain16 bytes each")
        return tuple(
            data[i : i + rom_width].split(b"\0", 1)[0] for i in range(0, len(data), 16)
        )
    if len(data) < 5:
        data = data.rjust(5, b"\0")
    if len(data) % 5:
        raise ValueError("SBR binary records must contain five bytes each")
    return tuple(data[i : i + 5].hex().upper() for i in range(0, len(data), 5))


def vendor_get_cid(
    channel: NativeProgrammingChannel,
    family: str,
    *,
    p5: bool = True,
    support_get_cid: bool = True,
    rom_id_bytes: int = 5,
    address_extension: int | None = None,
    response_address_extension: int | None = None,
    query_kind: int = 2,
    native_build: int = 18,
) -> dict:
    """Native query/codec for Common, MMC, HINO/P4/P5/DSS/VCS and SBR.

    A channel is already bound to one caller-selected ECU/filter; transport
    connect/disconnect and enumeration live in the explicit caller session.
    """
    if family not in ("Common", "MMC", "HINO", "HINO-DSS", "HINO-VCS", "SBR") or any(
        type(v) is not bool for v in (p5, support_get_cid)
    ):
        raise ValueError("Known vendor CID family and boolean query settings required")
    if type(native_build) is not int or native_build not in (12, 18):
        raise ValueError("Native getter build12/18 required")
    _uint(query_kind, 8, "Native CID query kind")
    if family == "SBR" and not support_get_cid:
        _uint(rom_id_bytes, 8, "ROM ID byte count")
        if not rom_id_bytes:
            raise ValueError("Nonzero ROM ID width required")
    if address_extension is not None:
        _uint(address_extension, 8, "CAN address extension")
    response_address_extension = (
        address_extension
        if response_address_extension is None
        else _uint(response_address_extension, 8, "Response address extension")
    )
    result: dict = {
        "family": family,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "history": channel.history,
        "provenance": f"static-native-CUW{native_build}-vendor-identification",
    }

    def call(request: bytes, expected: bytes | None) -> bytes:
        if family == "MMC":
            return _p5_call(channel, request, expected, 10, 3)
        if family == "HINO" and p5:
            return _p5_call(channel, request, expected, 180, 3)
        if family == "SBR" and not support_get_cid:
            return _p5_call(channel, request, expected, 30, 3)
        return native_utility_call(
            channel,
            request,
            expected,
            3,
            old_pending_timeout_ms=6000 if family == "HINO-VCS" else 5000,
        )

    try:
        if family == "Common":
            extension = (
                b"" if address_extension is None else bytes((address_extension,))
            )
            rx_extension = (
                b""
                if response_address_extension is None
                else bytes((response_address_extension,))
            )
            # Original accepts any response to0900 as support/probe success.
            try:
                call(extension + b"\x09\0", None)
            except (NativeDiagnosticError, VendorOperationError) as error:
                if (
                    not isinstance(error.response, bytes)
                    or b"\x7f" not in error.response[:2]
                ):
                    raise
                # Native0900 support probe accepts any returned diagnostic payload.
            response = call(extension + b"\x09\x04", None)
            identifiers = common_cid_response(
                response, address_extension=response_address_extension
            )
            result["identifiers"] = identifiers
            if native_build == 18 and query_kind != 2:
                from scripts.programming import decode_native_data, native_data_request

                assembly = native_data_request("assembly_p4")
                result["assembly_valid"] = False
                try:
                    assembly_response = native_utility_call(
                        channel,
                        extension + bytes.fromhex(assembly["request_hex"]),
                        rx_extension + bytes.fromhex(assembly["response_prefix_hex"]),
                        92,
                    )
                    result["assembly"] = decode_native_data(
                        "assembly_p4", assembly_response[len(rx_extension) :]
                    )
                    result["assembly_valid"] = True
                except VendorOperationError as exc:
                    result["assembly_error"] = dict(
                        error_chain=_error_chain(exc), **_native_error_info(exc)
                    )
        elif family == "MMC":
            primary = call(b"\x22\xf1\x11", b"\x62\xf1\x11")
            result["identifier_f111"] = _identifier_bytes(primary, b"\x62\xf1\x11", 24)
            try:
                secondary = call(b"\x22\xf1\x88", None)
            except (NativeNegativeResponse, VendorOperationError) as error:
                if (
                    not isinstance(error.response, bytes)
                    or error.response[:3] != b"\x7f\x22\x31"
                ):
                    raise
                secondary = error.response
            identifiers = (
                ()
                if secondary.startswith(b"\x7f\x22\x31")
                else (_identifier_bytes(secondary, b"\x62\xf1\x88", 24),)
            )
        elif family == "HINO-DSS":
            call(b"\x3e", b"\x7e")
            response = call(b"\x1a\x88\x01", b"\x5a\x88\x01")
            identifiers = (_identifier_bytes(response, b"\x5a\x88\x01", 16),)
        elif family == "HINO-VCS":
            call(b"\x3e", b"\x7e")
            call(b"\x3e\x01", b"\x7e")
            response = call(b"\x1a", b"\x5a\x03")
            identifiers = (_identifier_bytes(response, b"\x5a\x03", 13),)
        elif family == "HINO":
            call(b"\x3e\0" if p5 else b"\x3e\x01", b"\x7e\0" if p5 else b"\x7e")
            if p5:
                response = call(b"\x22\xf1\x88", b"\x62\xf1\x88")
                identifiers = (_identifier_bytes(response, b"\x62\xf1\x88", 12),)
            else:
                response = call(b"\x1a\x81", b"\x5a\x03")
                identifiers = (
                    _identifier_bytes(response, b"\x5a\x03", 13).replace(b" ", b""),
                )
        else:
            if support_get_cid:
                response = call(b"\x09\x04", b"\x49\x04\x01")
                data = response[3:]
                if len(data) < 16:
                    raise VendorOperationError(3, "SBR native CID requires16 bytes")
                identifiers = sbr_identifiers(data, ascii_records=True, rom_width=16)
            else:
                response = call(b"\x22\xf1\x82", b"\x62\xf1\x82")
                if len(response) < 3 + rom_id_bytes:
                    raise VendorOperationError(3, "SBR ROM response truncated")
                identifiers = sbr_identifiers(
                    response[3:], ascii_records=False, rom_width=rom_id_bytes
                )
        result.update(state="read_completed", identifiers=identifiers)
    except (
        NativeTransportError,
        NativeP5TransportError,
        BaseNativeDiagnosticError,
        NativeNegativeResponse,
        NativePendingTimeout,
        NativeUnexpectedResponse,
        VendorUtilityTimeout,
        VendorInitialCommandError,
        VendorStatusAckError,
    ) as exc:
        result.update(_native_error_info(exc))
        result.update(state="failed", error=str(exc))
    return result


@dataclass(frozen=True)
class PSAQuery:
    parameter: int
    offset: int
    width: int
    packed_decimal: bool = True
    suffix: int = 0

    def __post_init__(self) -> None:
        _uint(self.parameter, 8, "PSA SID21 parameter")
        if (
            type(self.offset) is not int
            or not 1 <= self.offset <= 4095
            or type(self.width) is not int
            or not 1 <= self.width <= 255
            or type(self.packed_decimal) is not bool
            or self.suffix not in (0, 1, 2)
        ):
            raise ValueError("Invalid PSA SID21 field definition")

    def field(self, response: bytes) -> bytes:
        # Native config offset includes its one-byte response-SID origin.
        start = self.offset - 1
        if (
            not response.startswith(bytes((0x61, self.parameter)))
            or len(response) < start + self.width
        ):
            raise ValueError("PSA SID21 field is truncated")
        data = response[start : start + self.width]
        if self.packed_decimal:
            # Native adds ASCII0 to EACH nibble; values A..F become :;<=>?.
            data = bytes(
                value for byte in data for value in ((byte >> 4) + 48, (byte & 15) + 48)
            )
        return data + (
            b"96" if self.suffix == 1 else b"14" if self.suffix == 2 else b""
        )


def psa_get_cid(
    channel: VendorDiagnosticChannel,
    hardware: PSAQuery,
    software: PSAQuery,
    *,
    diagnostic_session: bool = False,
) -> dict:
    """PSA parameterized SID21 hardware/software reads and native field offsets."""
    if (
        not isinstance(hardware, PSAQuery)
        or not isinstance(software, PSAQuery)
        or type(diagnostic_session) is not bool
    ):
        raise ValueError("Explicit PSA native query definitions required")
    result: dict = {
        "family": "PSA",
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "history": channel.history,
        "provenance": "static-native-CUW18-PSA-identification",
    }

    def call(request: bytes, expected: bytes, code: int) -> bytes:
        return native_utility_call(channel, request, expected, code)

    try:
        call(
            b"\x10\xc0" if diagnostic_session else b"\x81",
            b"\x50\xc0" if diagnostic_session else b"\xc1\xd0\x8f",
            57,
        )
        hard = call(
            bytes((0x21, hardware.parameter)), bytes((0x61, hardware.parameter)), 59
        )
        if len(hard) < 24:
            raise VendorOperationError(
                59, "PSA hardware identification requires24 native bytes"
            )
        soft = call(
            bytes((0x21, software.parameter)), bytes((0x61, software.parameter)), 60
        )
        if len(soft) < 26:
            raise VendorOperationError(
                60, "PSA software identification requires26 native bytes"
            )
        result["hardware_identifier"] = hardware.field(hard)
        result["identifiers"] = (software.field(soft),)
        result["hardware_response"] = hard
        result["software_response"] = soft
        call(
            b"\x10\x81" if diagnostic_session else b"\x82",
            b"\x50\x81" if diagnostic_session else b"\xc2",
            58,
        )
        result["state"] = "read_completed"
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - keep bounded read evidence
        result.update(_native_error_info(exc))
        result.update(
            state="cancelled"
            if isinstance(exc, (InterruptedError, KeyboardInterrupt))
            else "failed",
            error=str(exc),
        )
    return result


def psa_identification_field(
    target_s1: bytes, software_response: bytes, *, day: int, month: int, year: int
) -> bytes:
    """NativeReadIdentificationField1220 and metadata merge24b0, then prepare date."""
    from datetime import date

    date(year, month, day)
    if (
        not isinstance(target_s1, bytes)
        or len(target_s1) < 13
        or not isinstance(software_response, bytes)
        or len(software_response) < 26
        or software_response[0] != 0x61
    ):
        raise ValueError("PSA targetS1 and actual SID21 software response required")
    target = bytearray(22)
    target[:2] = target_s1[:2]
    target[2:4] = target_s1[4:6]
    target[7:11] = target_s1[6:10]
    target[19:22] = target_s1[10:13]
    target[4:7] = software_response[8:11]
    target[11:14] = bytes((day, month, year % 100))
    target[14] = software_response[18]
    target[15:18] = b"\x26\x66\x66"
    target[18] = software_response[22] + int(software_response[22] < 0xFD)
    return bytes(target)


def mmc_prepare(
    channel: NativeProgrammingChannel,
    key_provider: Callable[[bytes], bytes | Literal[False]],
    *,
    preparation_state: Callable[[], int],
    send_start: Callable[[bytes, float], int],
    periodic: Callable[[bool, int, bytes, int, int, float], None],
    configure: Callable[[str, int, float], None],
) -> dict:
    """MMC held1082→state3two-secondburst→periodic→1002→2741/2742.

    Native UI state callback is explicit:1 keeps requesting,3 confirms the
    two-second entry burst; other states cancel preparation before authorization.
    """
    if not callable(key_provider) or not callable(preparation_state):
        raise TypeError(
            "Explicit MMC preparation state and authorized key provider required"
        )

    def call(request: bytes, expected: bytes) -> bytes:
        return _p5_call(
            channel,
            request,
            expected,
            10,
            vendor_utility_error_code("MMC", "prepare", request),
        )

    proceeded = False

    def budget() -> float:
        if channel.cancelled():
            raise InterruptedError("MMC preparation cancelled")
        value = channel.deadline - channel.clock()
        if value <= 0:
            raise TimeoutError("MMC preparation deadline expired")
        return value

    def start() -> None:
        remaining = budget()
        channel.attempted = True
        count = send_start(b"\x10\x82", remaining)
        if type(count) is not int or count != 1:
            raise OSError("Unproven MMC preparation entry write")
        budget()

    def run() -> None:
        nonlocal proceeded
        for _ in range(65536):
            state = preparation_state()
            if type(state) is not int:
                raise ValueError("MMC preparation state must be a native integer")
            budget()
            if state != 1:
                break
            start()
        else:
            raise TimeoutError("MMC preparation entry host budget exceeded")
        if preparation_state() != 3:
            raise InterruptedError(
                "MMC preparation was not confirmed by its state provider"
            )
        until = channel.clock() + 2.0
        for _ in range(65536):
            start()
            if channel.clock() > until:
                break
        else:
            raise TimeoutError("MMC preparation burst host budget exceeded")
        proceeded = True
        periodic(True, 0x7DF, b"\x3e\x80", 2000, 100, budget())
        response = call(b"\x10\x02", b"\x50\x02")
        if len(response) < 6:
            raise VendorOperationError(41, "MMC session timing response truncated")
        configure(
            "transport_timeout_ms", int.from_bytes(response[2:4], "big"), budget()
        )
        configure(
            "pending_timeout_ms", int.from_bytes(response[4:6], "big") * 10, budget()
        )
        seed = call(b"\x27\x41", b"\x67\x41")
        if len(seed) < 10:
            raise VendorOperationError(16, "MMC seed requires eight bytes")
        key = key_provider(seed[2:10])
        if key is False:
            raise VendorOperationError(
                17, "Native authorization provider denied the request"
            )
        if not isinstance(key, bytes) or len(key) != 8:
            raise ValueError("MMC provider must supply eight authorized key bytes")
        call(b"\x27\x42" + key, b"\x67\x42")

    result = _vendor_result(channel, "MMC-prepare", run)
    result["periodic_active"] = proceeded
    if result["state"] == "writer_completed":
        result["state"] = "prepare_completed"
    return result


@dataclass(frozen=True)
class PowerTrainProfile:
    cpu_id: int
    block_info: str
    shrink: bool = False
    send_type: int = 0
    non_inverify: bool = False
    non_verify: bool = False
    timing: tuple[tuple[str, int], ...] = ()

    def __post_init__(self) -> None:
        _uint(self.cpu_id, 8, "CPU ID")
        if not isinstance(self.timing, tuple) or any(
            not isinstance(entry, tuple)
            or len(entry) != 2
            or not isinstance(entry[0], str)
            or type(entry[1]) is not int
            or not 0 <= entry[1] <= 0xFFFFFFFF
            for entry in self.timing
        ):
            raise ValueError("Bounded native profile timing required")
        if (
            not isinstance(self.block_info, str)
            or not 1 <= len(self.block_info) <= 65536
            or type(self.send_type) is not int
            or self.send_type not in (0, 1, 2)
            or any(
                type(flag) is not bool
                for flag in (self.shrink, self.non_inverify, self.non_verify)
            )
        ):
            raise ValueError("Explicit bounded powertrain parameter profile required")


def powertrain_write(
    stream: VendorCAN,
    location_id: bytes,
    password: int | None,
    image: bytes,
    profiles: tuple[PowerTrainProfile, ...],
    *,
    solar: bool = False,
    external_memory: bool = False,
    skip_check_id: bool = False,
    swap_endian: bool = False,
    change_cpu_before: bool = False,
    reset_after_check: bool = False,
    next_cpu: bool = False,
    finish_stream: VendorCAN | None = None,
    finish_ack: bool = True,
    s0_header: bytes | None = None,
    wait_ms: int = 0,
    wait_after_mode_ms: int = 0,
    first_timeout_ms: int = 0,
    set_timeout: Callable[[int, float], None] | None = None,
    blank_wait_ms: int = 0,
    erase_wait_ms: int = 0,
    write_wait_ms: int = 0,
    inverify_wait_ms: int = 0,
    verify_wait_ms: int = 0,
    finish_wait_ms: int = 0,
    native_build: int = 18,
    progress: Callable[[int, int], None] | None = None,
    flash_size: int | None = None,
    flash_timeout_ms: int | None = None,
    bh32: bool = False,
    resolve_profile: Callable[[int], PowerTrainProfile | None] | None = None,
    ranges_from_header: bool = False,
    initial_command_attempts: int = 1,
    solar_next_igoff: Callable[[], bool] | None = None,
    next_cpu_igoff: Callable[[], bool] | None = None,
    completion_callback: Callable[[int, float], None] | None = None,
    clear_native_flags: Callable[[tuple[str, ...], float], None] | None = None,
    set_native_flags: Callable[[dict[str, bool], float], None] | None = None,
) -> dict:
    """Native non-P4 PowerTrain/Solar CPU writer, using shared recovered block layout.

    Profiles are explicit resolved native parameter rows, including any alternate
    CPU profile. The real memory reply chooses a matching row; no CPU match is
    guessed. Caller supplies password and finish-address stream explicitly.
    """
    from scripts.programming_legacy import (
        block_ranges,
        block_sizes,
        complete_block_info,
        legacy_blocks,
        parse_block_info,
    )

    if (
        not isinstance(image, bytes)
        or not 0 < len(image) <= 64 * 1024 * 1024
        or not isinstance(profiles, tuple)
        or not 1 <= len(profiles) <= 64
        or any(not isinstance(profile, PowerTrainProfile) for profile in profiles)
    ):
        raise ValueError(
            "Bounded powertrain image and explicit native profiles required"
        )
    flags = (
        solar,
        external_memory,
        skip_check_id,
        swap_endian,
        change_cpu_before,
        reset_after_check,
        next_cpu,
        finish_ack,
        bh32,
        ranges_from_header,
    )
    if any(type(flag) is not bool for flag in flags):
        raise ValueError("Boolean native powertrain flags required")
    if password is None:
        if (
            not skip_check_id
            or not isinstance(location_id, bytes)
            or len(location_id) != 8
        ):
            raise ValueError("Executed CheckID requires its actual native password")
    else:
        common_check_id_frames(location_id, password, swap_endian=swap_endian)
    if solar and ranges_from_header and not s0_header:
        raise ValueError("Solar native S0 range mode requires an actual S0 header")
    if type(initial_command_attempts) is not int or initial_command_attempts not in (
        1,
        11,
    ):
        raise ValueError("Native initial command attempts must be1 or11")
    for delay in (
        wait_ms,
        wait_after_mode_ms,
        first_timeout_ms,
        blank_wait_ms,
        erase_wait_ms,
        write_wait_ms,
        inverify_wait_ms,
        verify_wait_ms,
        finish_wait_ms,
    ):
        _uint(delay, 32, "Powertrain native wait/timeout")
    if (
        type(native_build) is not int
        or native_build not in (12, 18)
        or progress is not None
        and not callable(progress)
    ):
        raise ValueError("Native build12/18 and callable progress observer required")
    native_flash_size = (
        len(image) if flash_size is None else _uint(flash_size, 32, "Native FlashSize")
    )
    if not 0 < native_flash_size <= len(image):
        raise ValueError("Native FlashSize must fit the supplied materialized image")
    progress_count = 0
    progress_percent = 0
    progress_total = native_flash_size * 2

    def advance(amount: int) -> None:
        nonlocal progress_count, progress_percent
        progress_count += amount
        if progress is not None:
            progress(progress_count, progress_percent)
        progress_percent = progress_count * 100 // progress_total
        if progress is not None:
            progress(progress_count, progress_percent)

    if flash_timeout_ms is not None:
        _uint(flash_timeout_ms, 32, "Native flash receive timeout")
        if set_timeout is None:
            raise ValueError(
                "Flash receive timeout requires explicit transport control"
            )
    available_profiles = list(profiles)

    def get_profile(index: int) -> PowerTrainProfile | None:
        if index < len(available_profiles):
            return available_profiles[index]
        if resolve_profile is None:
            return None
        profile = resolve_profile(index)
        stream.remaining()
        if profile is not None:
            if not isinstance(profile, PowerTrainProfile):
                raise TypeError("Selected alternate must be a native CPU profile")
            available_profiles.append(profile)
        return profile

    result: dict = {
        "family": "PowerTrain-Solar" if solar else "PowerTrain",
        "history": stream.history,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "provenance": f"static-native-CUW{native_build}-PowerTrain"
        + ("-Solar" if solar else ""),
        "programming_completed": False,
        "automatic_retry": False,
    }
    result["native_state_events"] = []

    def state_event(changes: dict[str, bool], *, cleanup: bool = False) -> None:
        result["native_state_events"].append(dict(changes))
        budget = (
            max(0.0, stream.deadline - stream.clock())
            if cleanup
            else stream.remaining()
        )
        if set_native_flags is not None:
            set_native_flags(dict(changes), budget)
        elif clear_native_flags is not None and not any(changes.values()):
            clear_native_flags(tuple(changes), budget)
        if not cleanup:
            stream.remaining()

    try:
        if change_cpu_before:
            stream.change_cpu()
        if not skip_check_id:
            assert password is not None
            stream.wait(wait_after_mode_ms)
            for initial_attempt in range(initial_command_attempts):
                result["native_initial_attempts"] = initial_attempt + 1
                try:
                    stream.check_id(
                        location_id,
                        password,
                        swap_endian=swap_endian,
                        wait_ms=wait_ms,
                        first_timeout_ms=first_timeout_ms,
                        set_timeout=set_timeout,
                    )
                    break
                except VendorInitialCommandError:
                    if not solar or initial_attempt + 1 >= initial_command_attempts:
                        raise
        if reset_after_check and not skip_check_id:
            stream.command(b"\x05")
        if solar:
            stream.wait(wait_ms)
        active = 0
        memory = None
        if bh32 and not solar:
            memory = stream.memory_info(wide=False)
            if memory["extended"] != profiles[active].shrink:
                active += 1
                if get_profile(active) is None:
                    raise ValueError("32BH requires its selected alternate CPU row")
        active_timeout = dict(available_profiles[active].timing).get(
            "flash_timeout_ms", flash_timeout_ms
        )
        if active_timeout is not None:
            if set_timeout is None:
                raise ValueError("Flash timeout requires explicit transport control")
            set_timeout(active_timeout, stream.remaining())
            stream.remaining()
        if memory is None or not any(
            memory[key]
            for key in (
                "address",
                "end_address",
                "block_size_kib",
                "firmware_descriptor",
            )
        ):
            memory = stream.memory_info(wide=external_memory if solar else False)
        result["memory"] = memory
        profile = get_profile(active)
        assert profile is not None
        if not common_cpu_matches(
            memory["firmware_descriptor"],
            profile.cpu_id,
            shrink=memory["extended"],
            configured_shrink=profile.shrink,
        ):
            alternate = get_profile(active + 1)
            if alternate is None or not common_cpu_matches(
                memory["firmware_descriptor"],
                alternate.cpu_id,
                shrink=memory["extended"],
                configured_shrink=alternate.shrink,
            ):
                raise VendorOperationError(
                    10, "Memory response did not match a supplied CPU profile"
                )
            profile = alternate
        if not solar:
            state_event({"flag_728": True})
        info = parse_block_info(profile.block_info)
        timing = dict(profile.timing)
        blank_wait_ms = timing.get("blank_wait_ms", blank_wait_ms)
        erase_wait_ms = timing.get("erase_wait_ms", erase_wait_ms)
        write_wait_ms = timing.get("write_wait_ms", write_wait_ms)
        inverify_wait_ms = timing.get("inverify_wait_ms", inverify_wait_ms)
        verify_wait_ms = timing.get("verify_wait_ms", verify_wait_ms)
        if solar and profile.non_verify:
            progress_total = 2 * (native_flash_size // 2)
            if not progress_total:
                raise ValueError("Native skip-verify progress denominator is zero")
        if not solar:
            info = complete_block_info(
                info, memory["address"], memory["end_address"], memory["block_size_kib"]
            )
        sizes = block_sizes(info)
        ranges = block_ranges(
            info,
            grouped=not solar,
            s0_header=s0_header if solar and ranges_from_header else None,
        )
        if not solar and ranges[0][0] != 1:
            sizes = (0, *sizes)
        blocks = legacy_blocks(image, sizes, ranges, memory["address"])
        for block_index, block in enumerate(blocks):
            if solar or not stream.common_block(
                "blank",
                block.first,
                block.last,
                wide=memory["extended"],
                wait_ms=blank_wait_ms,
            ):
                stream.common_block(
                    "erase",
                    block.first,
                    block.last,
                    wide=memory["extended"],
                    wait_ms=erase_wait_ms,
                )
            if block_index == len(blocks) - 1 and (solar or memory["extended"]):
                state_event({"flag_72c": True})
            stream.common_write(
                block.address,
                block.data,
                send_type=profile.send_type,
                wide=external_memory if solar else False,
                first_wait_ms=wait_ms if solar else 0,
                wait_ms=write_wait_ms,
                progress=advance,
            )
            if solar or not profile.non_inverify:
                stream.common_block(
                    "inverify",
                    block.first,
                    block.last,
                    wide=memory["extended"],
                    wait_ms=inverify_wait_ms,
                )
            if not solar or not profile.non_verify:
                stream.common_verify(
                    block.first,
                    block.last,
                    block.data,
                    wide=memory["extended"],
                    wait_ms=verify_wait_ms,
                    progress=advance,
                )
        if not solar:
            state_event({"flag_614": False})
        change_next = next_cpu and not solar
        if change_next and next_cpu_igoff is not None:
            igoff = next_cpu_igoff()
            stream.remaining()
            if type(igoff) is not bool:
                raise ValueError("Next CPU IG-off policy must be native boolean")
            change_next = not igoff
        if change_next:
            try:
                stream.change_cpu()
            finally:
                try:
                    if completion_callback is not None:
                        completion_callback(
                            1, max(0.0, stream.deadline - stream.clock())
                        )
                finally:
                    state_event({"flag_728": False, "flag_72c": False}, cleanup=True)
                stream.remaining()
            result["native_state_after"] = {
                "flag_614": False,
                "flag_728": False,
                "flag_72c": False,
            }
            result["completion_callbacks_invoked"] = (
                completion_callback is not None
                and (clear_native_flags is not None or set_native_flags is not None)
            )
            result["state"] = "cpu_completed"
        else:
            state_event({"flag_730": True})
            finish = stream if finish_stream is None else finish_stream
            previous_deadline = finish.deadline
            finish.deadline = min(finish.deadline, finish.clock() + stream.remaining())
            try:
                finish.finish(
                    acknowledge=True
                    if solar
                    else finish_ack
                    if native_build == 18
                    else False
                )
            finally:
                finish.deadline = previous_deadline
            stream.wait(finish_wait_ms)
            if not solar:
                result["native_state_after"] = {"flag_614": False, "flag_728": False}
                result["completion_callbacks_invoked"] = (
                    clear_native_flags is not None or set_native_flags is not None
                )
                state_event({"flag_728": False})
            if solar:
                slots = []
                if solar_next_igoff is not None:
                    igoff = solar_next_igoff()
                    stream.remaining()
                    if type(igoff) is not bool:
                        raise ValueError(
                            "Next CPU IG-off policy must be native boolean"
                        )
                    if not igoff:
                        slots.append(1)
                result["native_state_after"] = {
                    "flag_72c": False,
                    "flag_614": False,
                    "flag_610": False,
                }
                slots.append(7)
                result["completion_callback_slots"] = slots
                result["completion_callbacks_invoked"] = (
                    completion_callback is not None
                    and (clear_native_flags is not None or set_native_flags is not None)
                )
                if completion_callback is not None and 1 in slots:
                    completion_callback(1, stream.remaining())
                    stream.remaining()
                state_event({"flag_72c": False, "flag_614": False, "flag_610": False})
                if completion_callback is not None:
                    completion_callback(7, stream.remaining())
                    stream.remaining()
            result["state"] = "writer_completed"
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - retain uncertain raw write position
        observed = exc
        try:
            stream.remaining()
        except (Exception, KeyboardInterrupt) as boundary_error:  # noqa: BLE001 - preserve cancellation/deadline
            exc = boundary_error
        progress_count = 0
        try:
            if (solar or native_build == 18) and progress is not None:
                progress(0, progress_percent)
        except (Exception, KeyboardInterrupt) as callback_error:  # noqa: BLE001 - reset both native fields independently
            result["progress_callback_error"] = str(callback_error)
        finally:
            progress_percent = 0
        try:
            if (solar or native_build == 18) and progress is not None:
                progress(0, 0)
        except (Exception, KeyboardInterrupt) as callback_error:  # noqa: BLE001 - preserve original failure
            result["progress_callback_error"] = str(callback_error)
        result.update(_native_error_info(observed))
        result["observed_error"] = _error_chain(observed)[-1]
        result["error_chain"] = _error_chain(observed)
        result.update(
            state="recovery_required"
            if stream.attempted
            else "cancelled"
            if isinstance(exc, (InterruptedError, KeyboardInterrupt))
            else "failed",
            error=str(exc),
        )
    result["transferred"] = stream.transferred
    result.update(
        native_build=native_build,
        progress_bytes=progress_count,
        progress_percent=progress_percent,
    )
    return result


def common_bus_type(image: bytes, address: int | None) -> int:
    """CommonPrepare1630: byte0→bus0,byte1→bus1, absent/other→enum2."""
    if not isinstance(image, bytes) or len(image) > 64 * 1024 * 1024:
        raise ValueError("Bounded immutable CPU image required")
    if address is None:
        return 2
    _uint(address, 32, "CAN communication speed offset")
    if address >= len(image):
        raise ValueError("CAN communication speed offset outside CPU image")
    value = image[address]
    return value if value in (0, 1) else 2


def common_judge_gateway(
    old: VendorDiagnosticChannel,
    p5: NativeProgrammingChannel,
    *,
    expiry_write: Callable[[str, bytes], None] | None = None,
) -> int:
    """Native750/758/extension5f probe: old3e→enum2, permitted P53e00→enum1.

    P5 fallback uses180seconds,5530ms read budget, and explicit raw5f3e on native
    pending expiry. Its raw provider never exchanges/retransmits a request.
    """
    if old.address_extension != 0x5F or old.response_address_extension != 0x5F:
        raise ValueError("Native gateway probe requires address extension5f")
    old_prefix = b"\x5f"
    try:
        native_utility_call(old, old_prefix + b"\x3e", old_prefix + b"\x7e", 80)
    except (NativeTransportError, NativeP5TransportError) as error:
        if error.code not in (9, 16):
            raise
    except VendorOperationError as error:
        if error.response == old_prefix + b"\x7f\x3e\x78":
            raise
    else:
        return 2
    previous_write = p5.pending_timeout_write
    base_channel: NativeProgrammingChannel = p5
    previous_exchange, previous_receive = p5.exchange, p5.receive

    def unframe(response: bytes) -> bytes:
        if not isinstance(response, bytes) or not 1 <= len(response) <= 4095:
            raise ValueError("Malformed native gateway response")
        if len(response) < 3 or not response.startswith(b"\x5f"):
            raise VendorOperationError(
                79, "Native gateway response extension mismatch", response
            )
        return response[1:]

    def exchange(ecu: str, request: bytes) -> bytes:
        return unframe(previous_exchange(ecu, b"\x5f" + request))

    def receive(ecu: str) -> bytes:
        assert previous_receive is not None
        return unframe(previous_receive(ecu))

    previous_budget = (
        p5.minimum_response_timeout_ms if isinstance(p5, VendorP5Channel) else None
    )
    if expiry_write is None and previous_write is None:
        raise ValueError(
            "Native gateway fallback requires explicit raw pending-expiry provider"
        )
    try:
        raw_expiry = expiry_write if expiry_write is not None else previous_write
        assert raw_expiry is not None

        def framed_expiry(ecu: str, packet: bytes) -> None:
            raw_expiry(ecu, b"\x5f" + packet)

        p5.pending_timeout_write = framed_expiry
        p5.exchange = exchange
        if previous_receive is not None:
            p5.receive = receive
        if isinstance(p5, VendorP5Channel):
            p5.minimum_response_timeout_ms = 5530
        _p5_call(p5, b"\x3e\0", b"\x7e\0", 180, 79)
    finally:
        p5.pending_timeout_write = previous_write
        base_channel.exchange, base_channel.receive = (
            previous_exchange,
            previous_receive,
        )
        if previous_budget is not None:
            assert isinstance(p5, VendorP5Channel)
            p5.minimum_response_timeout_ms = previous_budget
    return 1


@dataclass(frozen=True)
class VendorControls:
    """Native lifecycle operations for an explicitly addressed transport session."""

    get_timeout: Callable[[], int]
    set_timeout: Callable[[int], None]
    start_filter: Callable[[], int]
    stop_filter: Callable[[int], None]
    connect: Callable[[int], None]
    disconnect: Callable[[], None]
    set_padding: Callable[[bool], None]


def vendor_stage(
    channel: NativeProgrammingChannel | VendorCAN,
    controls: VendorControls,
    action: Callable[[], dict],
    *,
    reading: bool = False,
    receive_timeout_ms: int | None = None,
    padding: bool | None = None,
    restore_timeout: bool = True,
    manage_filter: bool = True,
    before_timeout: Callable[[], None] | None = None,
) -> dict:
    """Native getter/programming filter lifecycle around a concrete recovered stage.

    Getters connect protocol6 and disconnect; prepare/write use the already
    connected session. Filter IDs and both CAN addresses remain explicit in the
    provider's start_filter closure. Cleanup faults remain visible in the result.
    """
    if (
        not isinstance(controls, VendorControls)
        or any(type(v) is not bool for v in (reading, restore_timeout, manage_filter))
        or padding is not None
        and type(padding) is not bool
    ):
        raise ValueError(
            "Explicit native lifecycle controls and boolean settings required"
        )
    if receive_timeout_ms is not None:
        _uint(receive_timeout_ms, 32, "Native receive timeout")
    connected = False
    token: int | None = None
    previous: int | None = None
    result: dict = {
        "state": "failed",
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "programming_completed": False,
    }
    failures: list[str] = []
    cleanup_details: list[dict] = []

    def boundary() -> None:
        if channel.cancelled():
            raise InterruptedError("Vendor lifecycle cancelled")
        if channel.clock() >= channel.deadline:
            raise TimeoutError("Vendor lifecycle deadline expired")

    try:
        boundary()
        if reading:
            controls.connect(6)
            connected = True
            boundary()
        if padding is not None:
            controls.set_padding(padding)
            boundary()
        if before_timeout is not None:
            before_timeout()
            boundary()
        if restore_timeout:
            previous = _uint(controls.get_timeout(), 32, "Saved native timeout")
            boundary()
        if receive_timeout_ms is not None:
            controls.set_timeout(receive_timeout_ms)
            boundary()
        if manage_filter:
            token = controls.start_filter()
            if type(token) is not int or not 0 <= token <= 0xFFFFFFFF:
                raise ValueError("Native filter provider did not return a valid handle")
            boundary()
        result = action()
        if not isinstance(result, dict) or not isinstance(result.get("state"), str):
            raise TypeError(
                "Concrete vendor action must return its verified stage result"
            )
        boundary()
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - cleanup applies to all failed native stages
        observed = exc
        try:
            boundary()
        except (Exception, KeyboardInterrupt) as boundary_error:  # noqa: BLE001 - cancellation/deadline wins
            exc = boundary_error
        observed_info = _native_error_info(observed)
        if result.get("native_error_code") is None:
            result.update(observed_info)
        elif observed_info.get("native_error_domain") is not None:
            result["observed_error_details"] = observed_info
        result = dict(
            result,
            state="recovery_required"
            if channel.attempted and not reading
            else "cancelled"
            if isinstance(exc, (InterruptedError, KeyboardInterrupt))
            else "failed",
            error=str(exc),
            history=channel.history,
            observed_error=_error_chain(observed)[-1],
            error_chain=_error_chain(observed),
        )
    finally:
        if token is not None:
            try:
                controls.stop_filter(token)
            except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - preserve every cleanup failure
                failures.append(f"stop_filter:{exc}")
                cleanup_details.append(
                    dict(
                        phase="stop_filter",
                        error_chain=_error_chain(exc),
                        error_type=type(exc).__name__,
                        **_native_error_info(exc),
                    )
                )
        if previous is not None:
            try:
                controls.set_timeout(previous)
            except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - restore independently of filter teardown
                failures.append(f"restore_timeout:{exc}")
                cleanup_details.append(
                    dict(
                        phase="restore_timeout",
                        error_chain=_error_chain(exc),
                        error_type=type(exc).__name__,
                        **_native_error_info(exc),
                    )
                )
        if connected:
            try:
                controls.disconnect()
            except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - disconnect independently of other cleanup
                failures.append(f"disconnect:{exc}")
                cleanup_details.append(
                    dict(
                        phase="disconnect",
                        error_chain=_error_chain(exc),
                        error_type=type(exc).__name__,
                        **_native_error_info(exc),
                    )
                )
    if failures:
        result = dict(
            result,
            state="recovery_required"
            if channel.attempted and not reading
            else "cancelled"
            if any(
                item.get("error_type") in ("KeyboardInterrupt", "InterruptedError")
                for item in cleanup_details
            )
            else "failed",
            cleanup_errors=failures,
            cleanup_error_details=cleanup_details,
        )
    try:
        boundary()
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - late cleanup cannot validate success
        result.update(
            state="recovery_required"
            if channel.attempted and not reading
            else "cancelled"
            if isinstance(exc, (InterruptedError, KeyboardInterrupt))
            else "failed",
            error=str(exc),
        )
    result["physical_status"] = "PHYSICAL_UNCONFIRMED"
    result["programming_completed"] = False
    return result


def psa_records(
    records: tuple[tuple[int, int, bytes], ...],
) -> tuple[int, bytes, tuple[VendorSegment, ...]]:
    """Native PSA S0selector and firstS1identification skip before data transfer.

    Input is the already validated decoded native S-format record stream; this
    function preserves record order and never merges image ranges.
    """
    if not isinstance(records, tuple) or not 1 <= len(records) <= 65536:
        raise ValueError("Bounded immutable native S-format record tuple required")
    selector: int | None = None
    identification: bytes | None = None
    segments = []
    total = 0
    for record in records:
        if not isinstance(record, tuple) or len(record) != 3:
            raise ValueError("Native S-format record requires kind/address/data")
        kind, address, data = record
        _uint(kind, 4, "S-format record type")
        _uint(address, 32, "S-format record address")
        if (
            kind not in (0, 1, 2, 3, 5, 7, 8, 9)
            or not isinstance(data, bytes)
            or len(data) > 255
        ):
            raise ValueError("Invalid native S-format record")
        total += len(data)
        if total > 64 * 1024 * 1024:
            raise ValueError("S-format aggregate byte limit exceeded")
        if kind == 0 and selector is None:
            if len(data) < 7:
                raise ValueError("PSA S0 header requires selector byte6")
            selector = data[6]
        elif kind == 1 and identification is None:
            if len(data) < 13:
                raise ValueError("PSA firstS1 identification requires13 bytes")
            identification = data
        elif kind in (1, 2, 3):
            _uint(address, 24, "PSA transferred record address")
            segments.append(VendorSegment(address, data))
    if selector is None or identification is None or not segments:
        raise ValueError(
            "PSA header, identification and transferred records are required"
        )
    return selector, identification, tuple(segments)


def mmc_segments(image: bytes) -> tuple[VendorSegment, ...]:
    """MMC native concatenation: addressBE32,sizeBE32,data,supplied CRC2."""
    if not isinstance(image, bytes) or not 0 < len(image) <= 64 * 1024 * 1024:
        raise ValueError("Bounded immutable MMC encoded image required")
    offset = 0
    result = []
    while offset < len(image):
        if len(result) >= 4096 or len(image) - offset < 10:
            raise ValueError("Truncated MMC segment or host segment limit exceeded")
        address = int.from_bytes(image[offset : offset + 4], "big")
        size = int.from_bytes(image[offset + 4 : offset + 8], "big")
        if not size or size > len(image) - offset - 10:
            raise ValueError("MMC declared segment does not fit image")
        end = offset + 8 + size
        result.append(
            VendorSegment(address, image[offset + 8 : end], image[end : end + 2])
        )
        offset = end + 2
    return tuple(result)


def powertrain_prepare_retry(
    stream: VendorCAN,
    previous_error: int,
    *,
    wait_after_dummy_ms: int = 0,
    special_cpu: bool = False,
) -> dict:
    """PowerTrainPrepareRetry2210:05ACK or prior13/15 zero-fill/resynchronize.

    The native B32RV85_512K branch only waits5000ms. For other CPUs a failed05
    ACK permits dummy1024bytes for write error13 or256bytes for verify error15.
    Native read-exception retry count3 is retained; host bounds all polling.
    """
    _uint(previous_error, 32, "Previous native programming error")
    _uint(wait_after_dummy_ms, 32, "Dummy-data wait")
    if type(special_cpu) is not bool:
        raise ValueError("Boolean native CPU branch required")
    result: dict = {
        "family": "PowerTrain-prepare-retry",
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "programming_completed": False,
        "history": stream.history,
        "automatic_retry": False,
    }
    try:
        if special_cpu:
            stream.wait(5000)
        else:
            for attempts in range(1, 4097):
                stream.write(b"\x05")
                try:
                    stream.ack()
                except (NativeTransportError, NativeP5TransportError) as exc:
                    if exc.code not in (9, 16):
                        raise
                else:
                    break
                if previous_error not in (13, 15):
                    raise ValueError(
                        "Native prepare retry requires previous write/verify failure20"
                    )
                stream.write(bytes(1024 if previous_error == 13 else 256))
                try:
                    for _ in range(65536):
                        if stream.read() in (b"\x3c", b"\xff"):
                            break
                    else:
                        raise TimeoutError(
                            "Host resynchronization receive limit exceeded"
                        )
                except (NativeTransportError, NativeP5TransportError):
                    if attempts == 3:
                        raise ValueError("Native prepare retry failed20") from None
                stream.wait(wait_after_dummy_ms)
            else:
                raise TimeoutError("Host prepare-retry iteration budget exceeded")
        result["state"] = "prepare_retry_completed"
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - preserve uncertain dummy write state
        observed = exc
        try:
            stream.remaining()
        except (Exception, KeyboardInterrupt) as boundary_error:  # noqa: BLE001 - host boundary takes precedence
            exc = boundary_error
        result["observed_error"] = _error_chain(observed)[-1]
        result.update(
            state="recovery_required"
            if stream.attempted
            else "cancelled"
            if isinstance(exc, (InterruptedError, KeyboardInterrupt))
            else "failed",
            error=str(exc),
        )
    return result


def common_is_finished(stream: VendorCAN, controls: VendorControls) -> dict:
    """Native Common2640 probe on the first supplied, already-bound CAN pair.

    The original accepts any successfully read payload after3e. This proves only
    that the native finish probe replied, never successful image programming.
    """

    def probe() -> dict:
        response = stream.check_finish()
        return {"state": "probe_completed", "response_hex": response.hex()}

    result = vendor_stage(stream, controls, probe, restore_timeout=False)
    result["finished"] = result["state"] == "probe_completed"
    result["family"] = "Common-finish-probe"
    return result


def hino_dss_prepare_retry(
    channel: VendorDiagnosticChannel,
    key_provider: Callable[[bytes], bytes | Literal[False]],
    *,
    raw_write: Callable[[int, bytes, float], int],
    wait: Callable[[int, float], None],
) -> dict:
    """DSS PrepareRetry1bc0 calls the same native PrepareWriteForDSS1b70 flow.

    Use vendor_stage for the caller-bound native flow-control filter lifecycle.
    """
    result = hino_prepare(
        channel, "HINO-DSS", key_provider, raw_write=raw_write, wait=wait
    )
    result["family"] = "HINO-DSS-prepare-retry"
    return result


def dh_identifier(
    response: bytes, complement: bytes, *, address_extension: int | None = None
) -> bytes:
    """DH1600: configured complement plus five bytes following5a."""
    if not isinstance(complement, bytes) or len(complement) > 260:
        raise ValueError("Bounded supplied ComplementCID bytes required")
    extension = (
        b""
        if address_extension is None
        else bytes((_uint(address_extension, 8, "Address extension"),))
    )
    prefix = extension + b"\x5a"
    if (
        not isinstance(response, bytes)
        or not response.startswith(prefix)
        or len(response) < 2
    ):
        raise VendorOperationError(3, "DH identifier response is truncated")
    # Native1600 tests the second payload byte for5a, even when it could be
    # an actual leadingZ identifier character without an address extension.
    offset = 1 + int(response[1] == 0x5A)
    if len(response) < offset + 5:
        raise VendorOperationError(3, "DH identifier response is truncated")
    identifier = (
        complement.split(b"\0", 1)[0] + response[offset : offset + 5].split(b"\0", 1)[0]
    )
    if not identifier:
        raise VendorOperationError(3, "Native DH identifier is empty")
    return identifier


def software_info_selectors(
    response: bytes, *, address_extension: int | None = None
) -> tuple[int, ...]:
    """SoftwareInfo16c0 requires every selector byte to be nonzero."""
    extension = (
        b""
        if address_extension is None
        else bytes((_uint(address_extension, 8, "Address extension"),))
    )
    prefix = extension + b"\x5a\x88\0"
    if (
        not isinstance(response, bytes)
        or not response.startswith(prefix)
        or not 1 <= len(response) - len(prefix) <= 4092
        or 0 in response[len(prefix) :]
    ):
        raise VendorOperationError(
            3, "Native SoftwareInfo selector list is empty, truncated or containsNUL"
        )
    return tuple(response[len(prefix) :])


def software_info_identifier(
    response: bytes,
    selector: int,
    *,
    byte_count: int = 0,
    address_extension: int | None = None,
) -> bytes:
    """SoftwareInfo1d10:16characters, explicit length, native trailing-space trim."""
    _uint(selector, 8, "SoftwareInfo selector")
    if type(byte_count) is not int or not 0 <= byte_count <= 16:
        raise ValueError("SoftwareInfoIDByteNum must be0..16")
    extension = (
        b""
        if address_extension is None
        else bytes((_uint(address_extension, 8, "Address extension"),))
    )
    prefix = extension + bytes((0x5A, 0x88, selector))
    if (
        not isinstance(response, bytes)
        or not response.startswith(prefix)
        or len(response) < len(prefix) + 16
    ):
        raise VendorOperationError(3, "SoftwareInfo identifier requires16 native bytes")
    raw = response[len(prefix) : len(prefix) + 16]
    # strncpy pads after the first NUL; trimming examines the full16-byte array.
    initial = raw.split(b"\0", 1)[0]
    field_bytes = bytearray(initial.ljust(16, b"\0"))
    if byte_count and byte_count < 16 and field_bytes[0]:
        field_bytes[byte_count] = 0
    for index in range(15, 0, -1):
        if field_bytes[index] != 0x20:
            break
        field_bytes[index] = 0
    field = bytes(field_bytes).split(b"\0", 1)[0]
    if not field:
        raise VendorOperationError(3, "Native SoftwareInfo identifier is empty")
    return field


def dh_get_cid(
    channel: VendorDiagnosticChannel,
    complement: bytes,
    *,
    address_extension: int | None = None,
    response_address_extension: int | None = None,
) -> dict:
    """DH1310 concrete1a81 query, with caller-bound native filter/session."""
    if not isinstance(complement, bytes) or len(complement) > 260:
        raise ValueError("Bounded supplied ComplementCID bytes required")
    if address_extension is not None:
        _uint(address_extension, 8, "Address extension")
    response_address_extension = (
        address_extension
        if response_address_extension is None
        else _uint(response_address_extension, 8, "Response address extension")
    )
    if (
        channel.address_extension != address_extension
        or channel.response_address_extension != response_address_extension
    ):
        raise ValueError("DH channel address extension does not match getter context")
    result = {
        "family": "DH",
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "programming_completed": False,
        "history": channel.history,
    }
    try:
        extension = b"" if address_extension is None else bytes((address_extension,))
        rx_extension = (
            b""
            if response_address_extension is None
            else bytes((response_address_extension,))
        )
        response = native_utility_call(
            channel, extension + b"\x1a\x81", rx_extension + b"\x5a", 3
        )
        result.update(
            state="read_completed",
            identifiers=(
                dh_identifier(
                    response, complement, address_extension=response_address_extension
                ),
            ),
        )
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - retain read evidence
        result.update(_native_error_info(exc))
        result.update(
            state="cancelled"
            if isinstance(exc, (InterruptedError, KeyboardInterrupt))
            else "failed",
            error=str(exc),
            error_chain=_error_chain(exc),
        )
    return result


def software_info_get_cid(
    channel: VendorDiagnosticChannel,
    *,
    start_filter: Callable[[], int],
    stop_filter: Callable[[int], None],
    set_bs: Callable[[bool, float], None] | None = None,
    kind_of_ecu: str = "",
    address_extension: int | None = None,
    response_address_extension: int | None = None,
    byte_count: int = 0,
    query_kind: int = 2,
    native_build: int = 18,
    request_id: bytes | None = None,
    existing_identifier_count: int = 0,
) -> dict:
    """Native SoftwareInfo discovery-filter then selector-filter workflow.

    Connection6/receive-timeout/disconnection are owned by the supplied outer
    session. set_bs maps J2534SET_CONFIG parameter0x1e to the supplied value.
    """
    if (
        type(native_build) is not int
        or native_build not in (12, 18)
        or not isinstance(kind_of_ecu, str)
        or len(kind_of_ecu) > 259
    ):
        raise ValueError("Native build12/18 and bounded ECU kind required")
    _uint(query_kind, 8, "CID query kind")
    _uint(existing_identifier_count, 32, "Existing CID record count")
    if (
        type(byte_count) is not int
        or not 0 <= byte_count <= 16
        or not callable(start_filter)
        or not callable(stop_filter)
    ):
        raise ValueError("Bounded byte count and concrete filter providers required")
    extension = (
        b""
        if address_extension is None
        else bytes((_uint(address_extension, 8, "Address extension"),))
    )
    if request_id is not None and (
        not isinstance(request_id, bytes) or len(request_id) not in (2, 3)
    ):
        raise ValueError("Native short request identifier requires2/3 supplied bytes")
    response_address_extension = (
        address_extension
        if response_address_extension is None
        else _uint(response_address_extension, 8, "Response address extension")
    )
    rx_extension = (
        b""
        if response_address_extension is None
        else bytes((response_address_extension,))
    )
    if (
        channel.address_extension != address_extension
        or channel.response_address_extension != response_address_extension
    ):
        raise ValueError(
            "SoftwareInfo channel address extension does not match getter context"
        )
    bs_enabled = address_extension is not None or kind_of_ecu == "38"
    if bs_enabled and not callable(set_bs):
        raise ValueError(
            "Native extended/APGS context requires explicit BS configuration"
        )
    result = {
        "family": "SoftwareInfo",
        "native_build": native_build,
        "physical_status": "PHYSICAL_UNCONFIRMED",
        "programming_completed": False,
        "history": channel.history,
    }

    def call(request: bytes, expected: bytes) -> bytes:
        return native_utility_call(channel, request, expected, 3)

    def budget() -> float:
        if channel.cancelled():
            raise InterruptedError("SoftwareInfo getter cancelled")
        remaining = channel.deadline - channel.clock()
        if remaining <= 0:
            raise TimeoutError("SoftwareInfo getter deadline expired")
        return remaining

    def filtered(action: Callable[[], object]) -> object:
        budget()
        token = _uint(start_filter(), 32, "Native filter handle")
        primary: BaseException | None = None
        try:
            budget()
            return action()
        except (Exception, KeyboardInterrupt) as exc:
            primary = exc
            raise
        finally:
            try:
                stop_filter(token)
                budget()
            except (Exception, KeyboardInterrupt) as exc:
                result.setdefault("cleanup_error_details", []).append(
                    dict(
                        phase="stop_filter",
                        error_chain=_error_chain(exc),
                        error_type=type(exc).__name__,
                        **_native_error_info(exc),
                    )
                )
                if primary is None:
                    raise

    try:
        budget()
        if bs_enabled:
            assert set_bs is not None
            set_bs(True, budget())
            budget()

        def discover_selectors() -> tuple[int, ...]:
            try:
                response = call(extension + b"\x1a\x88\0", rx_extension + b"\x5a\x88\0")
            except (NativeTransportError, NativeP5TransportError) as error:
                if error.code not in (9, 16):
                    raise
                raise VendorOperationError(
                    3, "Native SoftwareInfo selector probe failed"
                ) from error
            return software_info_selectors(
                response, address_extension=response_address_extension
            )

        selectors = filtered(discover_selectors)
        assert isinstance(selectors, tuple)

        def read_identifiers() -> tuple[bytes, ...]:
            identifiers = []
            for selector in selectors:
                identifiers.append(
                    software_info_identifier(
                        call(
                            extension + bytes((0x1A, 0x88, selector)),
                            rx_extension + bytes((0x5A, 0x88, selector)),
                        ),
                        selector,
                        byte_count=byte_count,
                        address_extension=response_address_extension,
                    )
                )
                result["identifiers"] = tuple(identifiers)
            if native_build == 18 and query_kind != 2:
                from scripts.programming import decode_native_data

                result["assembly_valid"] = False
                try:
                    assembly_response = native_utility_call(
                        channel, extension + b"\x1a\x89", rx_extension + b"\x5a", 92
                    )
                    result["assembly"] = decode_native_data(
                        "assembly_p4", assembly_response[len(rx_extension) :]
                    )
                    result["assembly_valid"] = True
                except VendorOperationError as exc:
                    result["assembly_error"] = dict(
                        error_chain=_error_chain(exc), **_native_error_info(exc)
                    )
            return tuple(identifiers)

        result.update(state="read_completed", identifiers=filtered(read_identifiers))
        if native_build == 18 and request_id is not None:
            result["communication_addresses"] = tuple(
                {"flag": 0, "request_id_hex": request_id.hex().upper()}
                for _ in result["identifiers"][: max(0, 32 - existing_identifier_count)]
            )
    except (Exception, KeyboardInterrupt) as original_error:  # noqa: BLE001 - preserve failed reads and cleanup
        result.update(_native_error_info(original_error))
        exc = original_error
        try:
            budget()
        except (Exception, KeyboardInterrupt) as boundary:  # noqa: BLE001 - boundary takes precedence
            exc = boundary
        result.update(
            state="cancelled"
            if isinstance(exc, (InterruptedError, KeyboardInterrupt))
            else "failed",
            error=str(exc),
            error_chain=_error_chain(exc),
        )
    finally:
        if bs_enabled:
            assert set_bs is not None
            try:
                set_bs(False, max(0.0, channel.deadline - channel.clock()))
                budget()
            except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - cleanup failure invalidates read success
                result.update(
                    state="cancelled"
                    if channel.cancelled()
                    or isinstance(exc, (InterruptedError, KeyboardInterrupt))
                    else "failed",
                    cleanup_error=str(exc),
                    cleanup_error_details=result.get("cleanup_error_details", [])
                    + [
                        dict(
                            phase="reset_bs",
                            error_chain=_error_chain(exc),
                            **_native_error_info(exc),
                        )
                    ],
                )
    return result


def vendor_write_inputs(
    container,
    cpu_index: int,
    family: str,
    parameter: Callable[[str], str],
    *,
    observed: dict | None = None,
    native_build: int = 18,
    resolve_parameter: Callable[[str], Callable[[str], str]] | None = None,
) -> dict:
    """Bind imported native CPU metadata to concrete vendor writer arguments.

    Returned bytes are execution inputs, not a printable report. Observed PSA
    identification/date and authorized passwords remain explicit caller data.
    Native geometry comes only from CUW fields or the selected parameter row.
    """
    from scripts.calibration import bind_native_cpu_records

    cpus = bind_native_cpu_records(container)
    if (
        type(cpu_index) is not int
        or not 0 <= cpu_index < len(cpus)
        or not callable(parameter)
    ):
        raise ValueError("Native CPU index and selected parameter getter required")
    if family not in (
        "PSA",
        "MMC",
        "HINO",
        "HINO-DSS",
        "HINO-VCS",
        "SBR",
        "PowerTrain",
        "Solar",
    ):
        raise ValueError("Known native vendor writer family required")
    context = {} if observed is None else observed
    if not isinstance(context, dict):
        raise TypeError("Explicit observed context mapping required")
    if type(native_build) is not int or native_build not in (12, 18):
        raise ValueError("Native vendor build12/18 required")
    cpu = cpus[cpu_index]

    def hexadecimal(value: str, bits: int, name: str) -> int:
        if (
            not isinstance(value, str)
            or not value
            or len(value) > bits // 4
            or any(c not in "0123456789abcdefABCDEF" for c in value)
        ):
            raise ValueError(f"Missing or malformed native hexadecimal {name}")
        return _uint(int(value, 16), bits, name)

    def flag(name: str) -> bool:
        value = parameter(name)
        if value not in ("", "0", "1"):
            raise ValueError(f"Invalid native boolean parameter {name}")
        return value == "1"

    def number(name: str) -> int:
        raw = parameter(name)
        value = int(raw or "0", 10)
        return _uint(value, 32, name)

    from scripts.programming_legacy import materialize_legacy_image

    materialized = {}

    def native_image(loader: bool = False):
        if loader not in materialized:
            record = cpu.flash_code if loader else cpu.image
            if record is None:
                raise ValueError(
                    "Native CPU metadata did not bind the required archive record"
                )
            filename = cpu.values.get("flashcodename" if loader else "cpuimagename", "")
            materialized[loader] = materialize_legacy_image(
                record.data, filename=filename
            )
        return materialized[loader]

    def data(loader: bool = False) -> bytes:
        if family == "PSA":
            if cpu.image is None:
                raise ValueError("Native PSA CPU image record is missing")
            return cpu.image.data
        return native_image(loader).data

    if family == "PSA":
        image = data()
        selector, target, segments = psa_records_from_image(image)
        software = context.get("software_response")
        date = context.get("date")
        if (
            not isinstance(software, bytes)
            or not isinstance(date, tuple)
            or len(date) != 3
        ):
            raise ValueError(
                "PSA requires the actual software reply and explicit day/month/year tuple"
            )
        return {
            "selector": selector,
            "records": segments,
            "identification": psa_identification_field(
                target, software, day=date[0], month=date[1], year=date[2]
            ),
            "diagnostic_session": flag("FlagToUseDiagnosticSessionProcessForPSA"),
        }
    if family == "MMC":
        try:
            image_header, loader_header = (
                cpu.headers["image"],
                cpu.headers["flash_code"],
            )
        except KeyError as exc:
            raise ValueError(
                "MMC native image/flash-code metadata is required"
            ) from exc
        return {
            "loader": mmc_segments(data(True)),
            "image": mmc_segments(data()),
            "loader_selector": hexadecimal(
                loader_header.get("dataformatid", ""), 8, "FlashCode DataFormatID"
            ),
            "image_selector": hexadecimal(
                image_header.get("dataformatid", ""), 8, "CPUImage DataFormatID"
            ),
            "loader_routine": hexadecimal(
                loader_header.get("01_startaddress", ""),
                32,
                "FlashCode first area start",
            ).to_bytes(4, "big"),
            "erase_areas": cpu.image_areas,
        }
    if family.startswith("HINO"):

        def area(name: str) -> tuple[int, int]:
            values = parameter(name).splitlines()
            if len(values) != 2:
                raise ValueError(
                    f"Native {name} must contain exactly two parameter entries"
                )
            return hexadecimal(values[0], 32, name), hexadecimal(values[1], 32, name)

        loader_address, loader_size = area("SBLStartAddressSize")
        image_address, image_size = area("DATAStartAddressSize")
        return {
            "mode": family,
            "loader": VendorSegment(loader_address, data(True)),
            "image": VendorSegment(image_address, data()),
            "loader_size": loader_size,
            "image_size": image_size,
        }
    if family == "SBR":
        files = []
        padded = flag("FlagToDataBlockPadding")
        supplied_padding = context.get("padded_files", {})
        if not isinstance(supplied_padding, dict):
            raise ValueError("Explicit native padded file mapping required")
        for file in cpu.files:
            if file.record is None:
                raise ValueError("Native SBR file record is missing")
            values = file.values
            erase = values.get("eraseblock", "")
            if erase not in ("0", "1"):
                raise ValueError("Native SBR EraseBlock must be0/1")
            address = hexadecimal(
                values.get("downloadaddress", ""), 32, "DownloadAddress"
            )
            size = hexadecimal(values.get("downloadmemsize", ""), 32, "DownloadMemsize")
            alfid = hexadecimal(values.get("alfid", ""), 8, "ALFID")
            payload = supplied_padding.get(file.index, file.record.data)
            files.append(
                SBRFile(
                    VendorSegment(address, payload),
                    alfid=alfid,
                    erase=erase == "1",
                    logical_size=size,
                    padded=padded,
                )
            )
        if not files:
            raise ValueError("Native SBR metadata declares no files")
        return {
            "files": tuple(files),
            "wait_after_function": flag("FlagToWaitAfterFuncReq"),
            "sumcheck_timeout_seconds": int(parameter("ReceveTimeoutSumCheck") or "30"),
        }
    finish_flags = context.get("finish_ack_flags")
    if family == "PowerTrain" and native_build == 18:
        if (
            not isinstance(finish_flags, tuple)
            or len(finish_flags) != len(cpus)
            or any(type(value) is not bool for value in finish_flags)
        ):
            raise ValueError(
                "CUW18 regular PowerTrain requires resolved finish flags for every CPU"
            )
        finish_ack = any(finish_flags)
    else:
        finish_ack = family == "Solar"
    location = cpu.values.get("locationid", "")
    if not isinstance(location, str) or len(location) != 16:
        raise ValueError("Native powertrain LocationID requires eight bytes")
    location_id = bytes.fromhex(location)
    recovery = context.get("recovery", False)
    if type(recovery) is not bool:
        raise ValueError("Explicit boolean recovery context required")
    special_cpu = cpu.values.get("cputype", "") == "22"
    skip_password = (
        family == "PowerTrain"
        and recovery
        and not flag("IGOffRetriableFlag")
        and not special_cpu
    )
    password = context.get("password")
    if password is None:
        if not skip_password:
            raise ValueError("Executed CheckID requires its actual native password")
    else:
        _uint(password, 32, "Explicit authorized native password")
    timing_keys = {
        "flash_timeout_ms": "ReceiveTimeoutBeforeFlashWrite",
        "blank_wait_ms": "WaitTimeBeforeStatusCheckForBlankCheck",
        "erase_wait_ms": "WaitTimeBeforeStatusCheckForEraseBlock",
        "write_wait_ms": "WaitTimeBeforeStatusCheckForWriteBlock",
        "inverify_wait_ms": "WaitTimeBeforeStatusCheckForInVerify",
        "verify_wait_ms": "WaitTimeBeforeStatusCheckForVerify",
    }

    def profile_from(getter: Callable[[str], str]) -> PowerTrainProfile:
        def selected_flag(key: str) -> bool:
            raw = getter(key)
            if raw not in ("", "0", "1"):
                raise ValueError("Invalid selected CPU boolean parameter")
            return raw == "1"

        return PowerTrainProfile(
            hexadecimal(getter("CPUIDNo"), 8, "CPUIDNo"),
            getter("BlockSizeInfo"),
            shrink=selected_flag("ShrinkFlag"),
            send_type=int(getter("SendDataByteForWriteBlockType") or "0"),
            non_inverify=selected_flag("FlagToNonInVerifyProcess")
            if family == "PowerTrain"
            else False,
            non_verify=selected_flag("FlagToNonVerifyProcess")
            if family == "Solar"
            else False,
            timing=tuple(
                (key, _uint(int(getter(native) or "0"), 32, native))
                for key, native in timing_keys.items()
            )
            if family == "PowerTrain"
            else (),
        )

    current_profile = profile_from(parameter)
    selected_rows = [parameter]

    def resolve_profile(index: int) -> PowerTrainProfile | None:
        if family != "PowerTrain" or not 1 <= index <= 2:
            return None
        previous = selected_rows[index - 1]
        alternate = previous("AlternateCPUType")
        if not alternate:
            return None
        if resolve_parameter is None:
            raise ValueError(
                "AlternateCPUType requires an actual selected-row resolver"
            )
        selected = resolve_parameter(alternate)
        if not callable(selected):
            raise TypeError("Alternate CPU resolver must return a parameter getter")
        selected_rows.append(selected)
        return profile_from(selected)

    recovery = context.get("recovery", False)
    if type(recovery) is not bool:
        raise ValueError("Explicit boolean recovery context required")
    special_cpu = cpu.values.get("cputype", "") == "22"
    base_parameter = parameter
    if family == "Solar" and cpu_index != 0:
        if resolve_parameter is None:
            raise ValueError("Solar CheckID requires actual CPU0 parameter row")
        base_parameter = resolve_parameter(cpus[0].values.get("cputype", ""))

    def next_igoff() -> bool:
        if resolve_parameter is None:
            raise ValueError("Next CPU completion requires actual catalog row")
        next_parameter = resolve_parameter(
            cpus[cpu_index + 1].values.get("cputype", "")
        )
        raw = next_parameter("FlagToDoIGOFFONAtCPUTypeChange")
        if raw not in ("", "0", "1"):
            raise ValueError("Native next CPU IG-off policy must be0/1")
        return raw == "1"

    base_big_endian = base_parameter("BigEndianFlag")
    if base_big_endian not in ("", "0", "1"):
        raise ValueError("Native CPU0 BigEndianFlag must be0/1")
    return {
        "location_id": location_id,
        "password": password,
        "native_build": native_build,
        "finish_ack": finish_ack,
        "image": data(),
        "flash_size": native_image().flash_size,
        "s0_header": (native_image().s0_header or None)
        if family == "Solar" and flag("ReadBlockRangeFromS0HeaderFlag")
        else None,
        "ranges_from_header": family == "Solar"
        and flag("ReadBlockRangeFromS0HeaderFlag"),
        "initial_command_attempts": 11 if family == "Solar" and recovery else 1,
        "solar_next_igoff": next_igoff
        if family == "Solar" and cpu_index + 1 < len(cpus)
        else None,
        "next_cpu_igoff": next_igoff
        if family == "PowerTrain" and cpu_index + 1 < len(cpus)
        else None,
        "profiles": (current_profile,),
        "resolve_profile": resolve_profile,
        "bh32": family == "PowerTrain" and flag("32BHFlag"),
        "next_cpu": family == "PowerTrain" and cpu_index < len(cpus) - 1,
        "skip_check_id": family == "PowerTrain"
        and recovery
        and not flag("IGOffRetriableFlag")
        and not special_cpu,
        "change_cpu_before": family == "PowerTrain" and not recovery and special_cpu,
        "reset_after_check": family == "PowerTrain"
        and flag("FlagToResetProcessAfterCheckProgramID"),
        "solar": family == "Solar",
        "external_memory": flag("ExternalMemoryFlag"),
        "swap_endian": base_big_endian == "1"
        if family == "Solar"
        else flag("BigEndianFlag"),
        "wait_ms": number("WaitTimeBetweenSF"),
        "wait_after_mode_ms": number("WaitTimeAfterReprogrammingMode")
        if family == "PowerTrain"
        else 0,
        "first_timeout_ms": number("ReceiveTimeoutBeforeInitialCommand"),
        "flash_timeout_ms": number("ReceiveTimeoutBeforeFlashWrite")
        if family == "PowerTrain"
        else None,
        "blank_wait_ms": number("WaitTimeBeforeStatusCheckForBlankCheck"),
        "erase_wait_ms": number("WaitTimeBeforeStatusCheckForEraseBlock"),
        "write_wait_ms": number("WaitTimeBeforeStatusCheckForWriteBlock"),
        "inverify_wait_ms": number("WaitTimeBeforeStatusCheckForInVerify"),
        "verify_wait_ms": number("WaitTimeBeforeStatusCheckForVerify"),
        "finish_wait_ms": number("WaitTimeAfterEndOfFlashing")
        if family == "Solar"
        else 0,
    }


def psa_records_from_image(
    image: bytes,
) -> tuple[int, bytes, tuple[VendorSegment, ...]]:
    """PSA native record order permits the identificationS1 before S2/S3data."""
    if not isinstance(image, bytes) or not 0 < len(image) <= 64 * 1024 * 1024:
        raise ValueError("Bounded native PSA S-record image required")
    widths = {0: 2, 1: 2, 2: 3, 3: 4, 5: 2, 7: 4, 8: 3, 9: 2}
    records = []
    for line in image.splitlines():
        if (
            len(records) >= 65536
            or not 4 <= len(line) <= 514
            or line[:1] != b"S"
            or line[1] - 48 not in widths
        ):
            raise ValueError("Malformed or excessive PSA S-record stream")
        kind = line[1] - 48
        try:
            raw = bytes.fromhex(line[2:].decode("ascii"))
        except (UnicodeError, ValueError) as exc:
            raise ValueError("Invalid PSA S-record hexadecimal data") from exc
        width = widths[kind]
        if len(raw) < width + 2 or raw[0] != len(raw) - 1 or sum(raw) & 255 != 255:
            raise ValueError("PSA S-record checksum/length mismatch")
        records.append(
            (kind, int.from_bytes(raw[1 : 1 + width], "big"), raw[1 + width : -1])
        )
    return psa_records(tuple(records))


def psa_getter_inputs(parameter: Callable[[str], str]) -> dict:
    """Native comma-separated hardware/software SID21 parameter definitions."""

    def query(name: str, software: bool) -> PSAQuery:
        values = parameter(name).split(",")
        if len(values) != (5 if software else 4) or any(
            not value or len(value) > 16 for value in values
        ):
            raise ValueError("Native PSA SID21 parameter list is malformed")
        sid = int(values[0], 16)
        offset, width, packed = (int(value, 10) for value in values[1:4])
        if packed not in (0, 1):
            raise ValueError("Native PSA packed-decimal flag must be0/1")
        return PSAQuery(
            sid, offset, width, bool(packed), int(values[4], 10) if software else 0
        )

    mode = parameter("FlagToUseDiagnosticSessionProcessForPSA")
    if mode not in ("", "0", "1"):
        raise ValueError("Native PSA diagnostic-session flag must be0/1")
    return {
        "hardware": query("PSASID21ParamListForHardwareID", False),
        "software": query("PSASID21ParamListForSoftwareID", True),
        "diagnostic_session": mode == "1",
    }


def vendor_prepare_inputs(
    family: str,
    parameter: Callable[[str], str],
    *,
    cpu_index: int = 0,
    retry: bool = False,
    kind_of_ecu: str = "",
    error_kind: int = 0,
    prepare_retry: bool | None = None,
) -> dict:
    """Resolve recovered vendor preparation flags without authorizing an ECU."""
    _uint(cpu_index, 8, "Native CPU index")
    if (
        type(retry) is not bool
        or not callable(parameter)
        or not isinstance(kind_of_ecu, str)
        or len(kind_of_ecu) > 259
    ):
        raise ValueError(
            "Explicit preparation context and selected parameter getter required"
        )

    def flag(name: str) -> bool:
        value = parameter(name)
        if value not in ("", "0", "1"):
            raise ValueError(f"Invalid native boolean parameter {name}")
        return value == "1"

    if family == "PSA":
        return {"diagnostic_session": flag("FlagToUseDiagnosticSessionProcessForPSA")}
    if family in ("HINO", "HINO-DSS", "HINO-VCS"):
        return {"mode": family, "dcu": family == "HINO" and kind_of_ecu == "106"}
    if family == "SBR":
        return {
            "master": flag("MasterFlag"),
            "slave": flag("SlaveFlag"),
            "central_gateway": flag("FlagToCentralGateway"),
            "unit_status_check": flag("FlagToUnitStatusCheck"),
            "retry": retry,
            "error_kind": _uint(error_kind, 32, "Native error kind604"),
            "prepare_retry": prepare_retry,
            "cpu_index": cpu_index,
            "retry_wait_ms": _uint(
                int(parameter("WaitTimeAfterIGOnAtRetry") or "0"),
                32,
                "Native retry wait",
            ),
            "aes": flag("FlagToEncryptLogicForAES"),
            "wait_after_function": flag("FlagToWaitAfterFuncReq"),
            "send_all_on_prepare_retry": flag("FlagToSendAllOnPrepareRetry"),
        }
    raise ValueError(
        "This family has no recovered parameterized vendor preparation flow"
    )


def vendor_module_profile(
    native_name: str,
    native_build: int,
    *,
    parameter: Callable[[str], str] | None = None,
    contact_type: str | None = None,
    cpu_type: str | None = None,
) -> dict:
    """Recovered dispatch/lifecycle policy after independent source identification.

    This describes already verified native entrypoints; it does not authenticate
    a DLL from its filename. The caller must bind its source identity first.
    """
    if (
        type(native_build) is not int
        or native_build not in (12, 18)
        or not isinstance(native_name, str)
    ):
        raise ValueError("Explicit identified CUW12/18 module required")
    name = native_name.rsplit("/", 1)[-1]
    modules = {
        "TCUWCanCIDGetter.dll": ("Common", "get_cid", "old", "vendor_get_cid"),
        "TCUWCanDHSoftwareIDGetter.dll": ("DH", "get_cid", "old", "dh_get_cid"),
        "TCUWCanSoftwareInfoIDGetter.dll": (
            "SoftwareInfo",
            "get_cid",
            "old",
            "software_info_get_cid",
        ),
        "TCUWCanPowerTrainFlashWriter.dll": (
            "PowerTrain",
            "write",
            "raw",
            "powertrain_write",
        ),
        "TCUWCanPowerTrainFlashWriterForSolar.dll": (
            "Solar",
            "write",
            "raw",
            "powertrain_write",
        ),
    }
    for family in ("PSA", "MMC", "SBR"):
        for suffix, stage in (
            ("FlashWriter", "write"),
            ("PrepareWriter", "prepare"),
            ("CIDGetter" if family != "SBR" else "SoftwareIDGetter", "get_cid"),
        ):
            modules[f"TCUWCan{family}{suffix}.dll"] = (
                family,
                stage,
                "old" if family == "PSA" else "p5",
                "psa_get_cid"
                if family == "PSA" and stage == "get_cid"
                else "vendor_get_cid"
                if stage == "get_cid"
                else family.lower() + "_" + stage,
            )
    for suffix, family in (
        ("", "HINO"),
        ("ForDSS", "HINO-DSS"),
        ("ForVCS", "HINO-VCS"),
    ):
        for kind, stage in (
            ("FlashWriter", "write"),
            ("PrepareWriter", "prepare"),
            ("CIDGetter", "get_cid"),
        ):
            modules[f"TCUWCanHINO{kind}{suffix}.dll"] = (
                family,
                stage,
                "p5" if family == "HINO" else "old",
                "vendor_get_cid" if stage == "get_cid" else "hino_" + stage,
            )
    if name not in modules:
        raise ValueError("Module is not a recovered vendor entrypoint owned here")
    family, stage, policy, operation = modules[name]
    if native_build == 12 and (family.startswith("HINO") or family == "SBR"):
        raise ValueError("This native vendor module is absent from CUW12")
    settings = {}
    if family == "HINO" and stage == "get_cid":
        if contact_type is None:
            raise ValueError("HINO CID policy requires the actual ContactType")
        settings["p5"] = contact_type == "P5-CAN"
        policy = "p5" if settings["p5"] else "old"
    if family == "SBR" and stage == "get_cid":
        if parameter is None:
            raise ValueError("SBR CID policy requires the selected native parameters")
        support = parameter("FlagToSupportGetCID")
        if support not in ("", "0", "1"):
            raise ValueError("Invalid native GetCID support flag")
        settings["support_get_cid"] = support == "1"
        if not settings["support_get_cid"]:
            settings["rom_id_bytes"] = int(parameter("SoftwareInfoROMIDByteNum") or "0")
        policy = "old" if settings["support_get_cid"] else "p5"
    entrypoints = {
        "StartGetCID"
        if stage == "get_cid"
        else "StartPrepareWrite"
        if stage == "prepare"
        else "StartFlashWrite": operation
    }
    if family == "PowerTrain":
        entrypoints["PrepareRetry"] = "powertrain_prepare_retry"
    if family == "SBR" and stage == "write":
        entrypoints["PrepareRetry"] = "sbr_prepare"
    if family == "HINO-DSS" and stage == "write":
        entrypoints["PrepareRetry"] = "hino_dss_prepare_retry"
    return {
        "native_name": name,
        "native_build": native_build,
        "family": family,
        "stage": stage,
        "policy": policy,
        "old_pending_timeout_ms": 6000 if family == "HINO-VCS" else 5000,
        "fixed_address_width": 2
        if family in ("PSA", "MMC", "HINO", "HINO-DSS", "HINO-VCS", "SBR")
        else None,
        "entrypoints": entrypoints,
        "settings": settings,
        "initial_native_flags": {"flag_730": False}
        if family == "Solar" and stage == "write"
        else {},
        "reading": stage == "get_cid",
        "connect_protocol": 6 if stage == "get_cid" else None,
        "receive_timeout_parameter": "ReceiveTimeoutBeforeGetCID"
        if stage == "get_cid"
        else None,
        "wait_before_timeout_ms": int(
            parameter("WaitTimeAfterReprogrammingMode") or "0"
        )
        if family == "Solar" and stage == "write" and parameter is not None
        else 0,
        "fixed_receive_timeout_ms": int(
            parameter("ReceiveTimeoutBeforeFlashWrite") or "0"
        )
        if family == "Solar" and stage == "write" and parameter is not None
        else 5000
        if family == "SBR" and stage == "write"
        else 100
        if family == "SBR" and stage == "prepare"
        else None,
        "restore_timeout": family in ("PowerTrain", "Solar"),
        "manage_filter": family != "SoftwareInfo"
        and not (family == "SBR" and stage == "prepare"),
        "address_scope": "all"
        if family in ("Common", "DH", "SoftwareInfo", "SBR")
        else "first",
        "padding": False if family == "PSA" and stage == "get_cid" else None,
        "wait_before_ms": 10000 if family == "SBR" and stage == "get_cid" else 0,
        "wait_before_filter_ms": 2000
        if family == "PowerTrain" and cpu_type == "22"
        else 0,
        "gateway_request_id": 0x763 if family == "SBR" and stage == "prepare" else None,
        "gateway_response_id": 0x76B
        if family == "SBR" and stage == "prepare"
        else None,
        "master_address_index": 1 if family == "SBR" and stage == "prepare" else None,
        "master_catalog_address_offsets": (7, 10)
        if family == "SBR" and stage == "prepare"
        else None,
        "pending_response_timeout_seconds": 180
        if family == "HINO"
        else 10
        if family == "MMC"
        else 30
        if family == "SBR"
        else None,
        "minimum_response_timeout_ms": 5530
        if family == "HINO" and stage == "get_cid" and policy == "p5"
        else 5000
        if policy == "p5" and (stage == "get_cid" or family == "SBR")
        else 5000
        if policy == "p5"
        else None,
        "pending_expiry_tester_present": False,
        "response_timeout_updates_from_session": policy == "p5"
        and family in ("MMC", "HINO")
        and stage != "get_cid",
        "provenance": "static original CUW12/18 entrypoint calls and lifecycle",
    }


def vendor_finish_ack(
    container, catalog, kind_of_ecu: str, contact_type: str
) -> tuple[bool, ...]:
    """CommonUtils12c0 resolves callback19 for EVERY calibration CPU row."""
    from scripts.calibration import bind_native_cpu_records

    result = []
    for cpu in bind_native_cpu_records(container):
        selection = catalog.select_native(
            kind_of_ecu, cpu.values.get("cputype", ""), contact_type
        )
        value = selection.value("FlagToReceiveRespForFinish")
        if value not in ("", "0", "1"):
            raise ValueError("Invalid native finish response flag")
        result.append(value == "1")
    return tuple(result)


def vendor_password_input(
    context,
    current_cids: tuple[str, ...],
    parameter: Callable[[str], str],
    *,
    family: str,
    use_new: bool,
    recovery: bool = False,
) -> int | None:
    """Bind the executed native old/new password branch to imported CPU data."""
    from scripts.programming_legacy import native_cpu_passwords

    if (
        family not in ("PowerTrain", "Solar")
        or type(use_new) is not bool
        or type(recovery) is not bool
    ):
        raise ValueError("Explicit native password branch flags required")
    raw = parameter("IGOffRetriableFlag")
    if raw not in ("", "0", "1"):
        raise ValueError("Native IGOffRetriableFlag must be0/1")
    igoff = raw == "1"
    special = context.selected.values.get("cputype", "") == "22"
    if family == "PowerTrain" and recovery and not igoff and not special:
        return None
    external = parameter("ExternalMemoryFlag")
    if external not in ("", "0", "1"):
        raise ValueError("Native ExternalMemoryFlag must be0/1")
    selected_new = use_new and (
        (special or igoff) if family == "PowerTrain" else external != "1"
    )
    old, new = native_cpu_passwords(
        context,
        current_cids,
        require_new=selected_new,
        resolve_new=selected_new,
        use_metadata_new_password=family == "Solar",
    )
    return new if selected_new else old
