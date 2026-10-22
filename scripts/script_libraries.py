"""Recovered CSDF ScriptLib callbacks over explicit, injected host services.

No original DLL is loaded. Native addresses and host-policy differences are
recorded in docs/script-libraries.md. All byte strings remain binary values.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Self

from scripts.native_memory import NativeMemoryArena
from scripts.script_vm import MAX_SIZE, LibraryContext
from scripts.utility_ex import UtilityImportBinding, uint32


class SequenceError(Exception):
    """Controller sequence error, before ScriptLib's 0/8/9/10/0x31xx mapping."""

    def __init__(self, code: int):
        if type(code) is not int or not 0 <= code <= 65535:
            raise ValueError("Sequence error must fit u16")
        self.code = code
        super().__init__(f"Controller sequence error 0x{code:04x}")


@dataclass(frozen=True)
class CommunicationOptions:
    retry_count: int
    address_type: bool
    plural: bool


@dataclass(frozen=True)
class ExchangeResult:
    sequence_code: int
    responses: tuple[bytes, ...]


def _bytes(value: bytes) -> bytes:
    if type(value) is not bytes or len(value) > MAX_SIZE:
        raise ValueError("Expected binary data of at most 16 MiB")
    return value


def pack_replies(replies: Sequence[bytes]) -> bytes:
    """Native plural-receive envelope: repeated LE-u16 size followed by body."""
    if not isinstance(replies, (tuple, list)) or len(replies) > 256:
        raise ValueError("Plural reply count exceeds 256")
    blocks = []
    total = 0
    for reply in replies:
        _bytes(reply)
        if len(reply) > 65535:
            raise ValueError("Plural reply body exceeds u16")
        total += len(reply) + 2
        if total > MAX_SIZE:
            raise ValueError("Plural reply aggregate byte budget exceeded")
        blocks.append(len(reply).to_bytes(2, "little") + reply)
    result = b"".join(blocks)
    return _bytes(result)


def unpack_replies(data: bytes) -> tuple[bytes, ...]:
    _bytes(data)
    result = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 2:
            raise ValueError("Truncated native plural reply length")
        size = int.from_bytes(data[offset : offset + 2], "little")
        offset += 2
        if size > len(data) - offset or len(result) >= 256:
            raise ValueError("Truncated or excessive native plural reply")
        result.append(data[offset : offset + size])
        offset += size
    return tuple(result)


def _fill_zero(data: bytes, mask: bytes) -> bytes:
    if len(mask) > 255 or sum(bool(value) for value in mask) > len(data):
        raise ValueError("Fill-zero mask exceeds native u8 domain or source data")
    source = iter(data)
    return bytes(next(source) if value else 0 for value in mask)


class ScriptLibraries:
    """One isolated native library state per script/ECU session.

    `exchange` handles one ECU reply; `plural_exchange` handles multiple replies.
    `native_exchange` instead receives the native communication options and
    supplies the controller sequence code. Injected callbacks must bound their
    own blocking I/O; this synchronous host checks cancellation on both sides.
    """

    def __init__(
        self,
        exchange: Callable[[str, bytes], bytes],
        *,
        ecu: str,
        ecu_id: int,
        plural_exchange: Callable[[str, bytes], Sequence[bytes]] | None = None,
        native_exchange: Callable[[str, bytes, CommunicationOptions], ExchangeResult]
        | None = None,
        read_record: Callable[[bytes], bytes] | None = None,
        did_ranges: Sequence[tuple[int, int]] | None = None,
        post_message: Callable[[int], None] | None = None,
        debug: Callable[[tuple[tuple[int, bytes], ...]], None] | None = None,
        cancelled: Callable[[], bool] | None = None,
        deadline: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        if (
            not isinstance(ecu, str)
            or not ecu
            or type(ecu_id) is not int
            or not 0 <= ecu_id <= 255
        ):
            raise ValueError("Explicit ECU name and u8 ECU identifier required")
        if deadline is not None and not math.isfinite(deadline):
            raise ValueError("Deadline must be finite")
        self.exchange, self.ecu, self.ecu_id = exchange, ecu, ecu_id
        self.plural_exchange, self.native_exchange = plural_exchange, native_exchange
        self.read_record, self.did_ranges = read_record, did_ranges
        self.post_message, self.debug = post_message, debug
        self.cancelled, self.deadline, self.clock = cancelled, deadline, clock
        self.retry_count, self.address_type = 2, False
        self.pid_data: dict[int, bytes] = {}
        self.events: list[dict] = []
        self.log_messages: list[dict] = []
        self._retained = 0
        self.libraries: dict[
            bytes, dict[int, Callable[[LibraryContext, int], None]]
        ] = {
            b"ScriptLibCommunication": {
                identifier: self._bind(self._communication, identifier)
                for identifier in range(1, 12)
            },
            b"ScriptLibLang": {
                identifier: self._bind(self._language, identifier)
                for identifier in (1, 2)
            },
            b"ScriptLibDebug": {1: self._print},
            b"ScriptLibSystem": {1: self._message},
            b"ScriptLibRMLib": {1: self._record},
        }

    @staticmethod
    def _bind(
        function: Callable[[int, LibraryContext, int], None], identifier: int
    ) -> Callable[[LibraryContext, int], None]:
        return lambda context, argc: function(identifier, context, argc)

    def _check(self) -> None:
        if self.cancelled is not None and self.cancelled():
            raise InterruptedError("CSDF library execution cancelled")
        if self.deadline is not None and self.clock() >= self.deadline:
            raise TimeoutError("CSDF library deadline exceeded")
        if len(self.events) >= 4096 or len(self.log_messages) >= 4096:
            raise ValueError("CSDF library event budget exceeded")

    def _retain(self, delta: int) -> None:
        if self._retained + delta > MAX_SIZE:
            raise ValueError("CSDF library aggregate byte budget exceeded")
        self._retained += delta

    def _args(
        self, context: LibraryContext, argc: int, allowed: tuple[int, ...]
    ) -> None:
        self._check()
        if type(argc) is not int or argc not in allowed or len(context.stack) < argc:
            raise ValueError(
                f"Invalid CSDF library argument count {argc}; expected {allowed}"
            )

    @staticmethod
    def _byte(context: LibraryContext) -> int:
        payload = context.pop()[1]
        if not payload:
            raise ValueError("CSDF library requires a nonempty byte argument")
        return payload[0]

    def _language(self, identifier: int, context: LibraryContext, argc: int) -> None:
        self._args(context, argc, (1,) if identifier == 2 else (2, 3))
        if identifier == 2:
            context.push(1, bytes([len(context.pop()[1]) & 255]))
            return
        count = self._byte(context) if argc == 3 else None
        start = self._byte(context)
        data = context.pop()[1]
        size = len(data) & 255
        count = max(0, size - start) if count is None else count
        context.push(3, data[start : start + count] if start + count <= size else b"")

    def _receive(self, request: bytes, plural: bool) -> tuple[int, tuple[bytes, ...]]:
        self._check()
        if not request:
            raise ValueError("Empty diagnostic request")
        try:
            if self.native_exchange is not None:
                result = self.native_exchange(
                    self.ecu,
                    request,
                    CommunicationOptions(self.retry_count, self.address_type, plural),
                )
                if not isinstance(result, ExchangeResult):
                    raise ValueError("Native exchange must return ExchangeResult")
                code, responses = result.sequence_code, result.responses
            elif plural and self.plural_exchange is not None:
                code, responses = 0, self.plural_exchange(self.ecu, request)
            else:
                code, responses = 0, (self.exchange(self.ecu, request),)
        except SequenceError as exc:
            code, responses = exc.code, ()
        self._check()
        if type(code) is not int or not 0 <= code <= 65535:
            raise ValueError("Controller sequence code must fit u16")
        if not isinstance(responses, (tuple, list)) or len(responses) > 256:
            raise ValueError("Invalid native response sequence")
        for response in responses:
            _bytes(response)
        if sum(len(response) for response in responses) > MAX_SIZE:
            raise ValueError("Native response aggregate byte budget exceeded")
        if not plural and len(responses) > 1:
            raise ValueError("Single receive returned multiple replies")
        status = {0: 0, 8: 1, 9: 2, 10: 3}.get(code, 5 if code >> 8 == 0x31 else 4)
        if status:
            return status, ()
        for response in responses:
            if len(self.log_messages) >= 4096:
                raise ValueError("CSDF library event budget exceeded")
            self._retain(2 * (len(request) + len(response)))
            self.log_messages.append(
                {"request_hex": request.hex(), "response_hex": response.hex()}
            )
        return status, tuple(responses)

    def _communication(
        self, identifier: int, context: LibraryContext, argc: int
    ) -> None:
        self._args(
            context,
            argc,
            {
                1: (1, 2),
                2: (2,),
                3: (0,),
                4: (3,),
                5: (1, 2),
                6: (2,),
                7: (1,),
                8: (2,),
                9: (2,),
                10: (1,),
                11: (1,),
            }[identifier],
        )
        if identifier in (1, 5):
            reference = context.pop(resolve=False) if argc == 2 else None
            if reference is not None:
                if reference[0] != 4 or len(reference[1]) != 2:
                    raise ValueError("Send output must be a native variable reference")
                index = int.from_bytes(reference[1], "little") - 0x8000
                if not 0 <= index < len(context.variables):
                    raise ValueError("Send output variable outside declared table")
            request = _bytes(context.pop(resolve=False)[1])
            status, responses = self._receive(request, identifier == 5)
            reply = (
                pack_replies(responses)
                if identifier == 5
                else (responses[0] if responses else b"")
            )
            if reference is not None:
                context.store(reference, (3, reply))
            context.push(1, bytes([status]))
        elif identifier == 2:
            support = context.pop()[1]
            pid = self._byte(context)
            if not support:
                raise ValueError("Support bitmap cannot be empty")
            bit = ((pid - 1) & 255) % (len(support) * 8)
            context.push(1, bytes([bool(support[bit >> 3] & (0x80 >> (bit & 7)))]))
        elif identifier == 3:
            context.push(1, bytes([self.ecu_id]))
        elif identifier == 4:
            mask, source = context.pop()[1], context.pop()[1]
            pid = self._byte(context)
            filled = _fill_zero(source, mask)
            self._retain(len(filled) - len(self.pid_data.get(pid, b"")))
            self.pid_data[pid] = filled
            context.push(3, filled)
        elif identifier in (6, 8):
            data = context.pop()[1]
            selector = self._byte(context)
            result = b""
            if identifier == 6:
                frames = unpack_replies(data)
                result = frames[selector] if selector < len(frames) else b""
            else:
                frame = 0
                scanned = 0
                while frame < len(data) and not result:
                    if scanned % 256 == 0:
                        self._check()
                    scanned += 1
                    if len(data) - frame < 4:
                        raise ValueError("Truncated support frame header")
                    size = int.from_bytes(data[frame : frame + 2], "little")
                    offset = frame + 4
                    # The native field is a cursor fence; shipped tables can
                    # contain a final TLV extending one byte beyond that fence.
                    while offset < frame + 2 + size:
                        if scanned % 256 == 0:
                            self._check()
                        scanned += 1
                        if len(data) - offset < 2:
                            raise ValueError("Truncated support TLV header")
                        key, length = data[offset : offset + 2]
                        offset += 2
                        if length > len(data) - offset:
                            raise ValueError("Truncated support TLV value")
                        if key == selector:
                            result = data[offset : offset + length]
                            break
                        offset += length
                    frame += size + 2
            context.push(3, result)
        elif identifier in (7, 10):
            new = self._byte(context)
            old = self.retry_count if identifier == 7 else int(self.address_type)
            if identifier == 7:
                self.retry_count = new
            else:
                self.address_type = new == 1
            context.push(1, bytes([old]))
        elif identifier == 9:
            service = self._byte(context)
            if service not in (0x21, 0x12):
                return
            mask = context.pop()[1]
            if not self.log_messages:
                raise ValueError("No communication log response to update")
            response = bytes.fromhex(self.log_messages[-1]["response_hex"])
            if len(response) < 2:
                raise ValueError("Communication log response lacks service header")
            used = sum(bool(value) for value in mask)
            filled = _fill_zero(response[2:], mask)
            updated = (response[:2] + filled + response[2 + used :]).hex()
            self._retain(len(updated) - len(self.log_messages[-1]["response_hex"]))
            self.log_messages[-1]["response_hex"] = updated
            context.push(1, b"\0")
        else:
            did = context.pop()[1]
            if len(did) < 2:
                raise ValueError("Target DID requires two bytes")
            if self.did_ranges is None:
                raise RuntimeError("DID range database has not been injected")
            supported = False
            number = int.from_bytes(did[:2], "big")
            if len(self.did_ranges) > 65536:
                raise ValueError("DID range database exceeds u16 domain")
            for index, (start, end) in enumerate(self.did_ranges):
                if index % 256 == 0:
                    self._check()
                if (
                    type(start) is not int
                    or type(end) is not int
                    or not 0 <= start <= end <= 65535
                ):
                    raise ValueError("Invalid DID database range")
                if start >> 8 <= did[0] <= end >> 8 and (
                    did[1] == 0 or start <= number <= end
                ):
                    supported = True
            context.push(1, bytes([supported]))
        self._check()

    def _record(self, context: LibraryContext, argc: int) -> None:
        self._args(context, argc, (2,))
        ordinal = self._byte(context)
        name = context.pop()[1].split(b"\0", 1)[0]
        if not name:
            raise ValueError("Record source name is empty")
        if self.read_record is None:
            raise RuntimeError("Record database reader has not been injected")
        try:
            source = _bytes(self.read_record(name))
        except FileNotFoundError:
            source = b""
        self._check()
        result, offset, current = b"", 0, 0
        while offset < len(source):
            if current % 256 == 0:
                self._check()
            size = source[offset]
            offset += 1
            if size > len(source) - offset:
                raise ValueError("Truncated record database entry")
            current += 1
            if current == ordinal:
                result = source[offset : offset + size]
                break
            offset += size
        context.push(3, result)

    def _print(self, context: LibraryContext, argc: int) -> None:
        self._args(context, argc, tuple(range(256)))
        values = tuple(reversed([context.pop() for _ in range(argc)]))
        self._retain(sum(2 * len(value[1]) + 16 for value in values))
        if self.debug is not None:
            self.debug(values)
        self._check()
        self.events.append(
            {
                "kind": "debug",
                "values": [
                    {"tag": tag, "hex": payload.hex()} for tag, payload in values
                ],
            }
        )
        # Native Print pushes an empty object with an uninitialized type field.
        context.push(3, b"")

    def _message(self, context: LibraryContext, argc: int) -> None:
        self._args(context, argc, (1,))
        wparam = self._byte(context)
        self._retain(16)
        if self.post_message is not None:
            self.post_message(wparam)
        self._check()
        self.events.append({"kind": "post_message", "wparam": wparam})
        # Native PostMessage has the same empty, untyped return as Print.
        context.push(3, b"")


# Original18 TY2 receiver methods; values are (IAT RVA, DWORD write offset).
_TY2_METHODS: dict[int, tuple[int, int | None]] = {
    0x1230: (0xC1978, 0x17450),
    0x19870: (0xC1974, None),
    0x19D60: (0xC1970, None),
    0x1A640: (0xC196C, None),
    0x1A650: (0xC1980, None),
    0x1A660: (0xC197C, None),
    0x1A670: (0xC1940, None),
    0x1A680: (0xC193C, None),
    0x1A690: (0xC1938, None),
    0x1B0A0: (0xC1934, None),
    0x1B9B0: (0xC1930, 0x0),
    0x1DA60: (0xC192C, 0x0),
    0x1E2A0: (0xC1928, None),
    0x1E2B0: (0xC1924, None),
    0x1E2C0: (0xC1920, None),
    0x1E9A0: (0xC191C, None),
    0x1F960: (0xC1914, None),
    0x1FFE0: (0xC1910, None),
    0x1FFF0: (0xC190C, None),
    0x21550: (0xC1904, None),
    0x226D0: (0xC1900, 0x0),
    0x250D0: (0xC18FC, None),
    0x27140: (0xC18F8, None),
    0x27B90: (0xC18F4, None),
    0x28350: (0xC18EC, None),
    0x28A20: (0xC18E8, 0x0),
    0x29300: (0xC18E4, 0x1090),
    0x2B020: (0xC18E0, 0x0),
    0x2C090: (0xC18DC, None),
    0x2C0A0: (0xC18D8, None),
    0x2F650: (0xC18D4, None),
    0x30480: (0xC18C8, 0x0),
    0x311C0: (0xC18C4, None),
    0x31CA0: (0xC18BC, None),
    0x33180: (0xC18B4, None),
    0x33650: (0xC18B0, None),
    0x33660: (0xC18AC, None),
    0x33670: (0xC18A8, None),
    0x34130: (0xC18A4, None),
    0x37390: (0xC18A0, 0x0),
    0x37A00: (0xC189C, 0x0),
    0x384B0: (0xC1894, 0x0),
    0x39050: (0xC1890, None),
    0x397E0: (0xC1984, None),
    0x39CB0: (0xC1944, None),
}


_LARGE_TY18_SHA = "d9fc5bb2f9d7bd583a9fbe317c3d45a2ed4eb60b210ea9623a8230f3baec1e8d"
_LARGE_TY18_METHODS: dict[int, tuple[int, int | None]] = {
    0x57EC0: (0x226FA0, None),  # TPW03
    0x9A470: (0x227644, None),  # 4WD05 WriteHistoryData
    0x9A450: (0x22764C, None),  # 4WD05 SendMessage
    0x99700: (0x227654, None),  # AWD04 ReadValues
}


class NativeProcedureLibraries(UtilityImportBinding):
    """Source-bound native method marshalling into the actual UtilityEx engine.

    `buffer` is the caller's stable mutable storage beginning at this+0xe8.
    It remains alive across asynchronous engine work; no pointer copy is made.
    This is a library seam, not a procedure selector or a scheduler.
    """

    def call_method(
        self, method_rva: int, buffer: bytearray, args: tuple[int, ...] = ()
    ) -> int | None:
        methods = {
            "ecba533aeaa2ec2a014fa59a113d025a8efe90338767c2786b8a5a891ca0f599": _TY2_METHODS,
            _LARGE_TY18_SHA: _LARGE_TY18_METHODS,
        }.get(self.caller_sha256)
        if methods is None:
            raise LookupError("Native receiver method unavailable for exact caller")
        method = methods.get(uint32(method_rva))
        if method is None:
            raise LookupError("Native receiver method has no reviewed body")
        iat_rva, offset = method
        if type(buffer) is not bytearray or not 4 <= len(buffer) <= MAX_SIZE:
            raise ValueError("Stable bounded native bytearray storage required")
        if type(args) is not tuple or len(args) != (offset is not None):
            raise ValueError("Native receiver method argument count mismatch")
        if offset is not None:
            value = uint32(args[0])
            if offset + 4 > len(buffer):
                raise ValueError("Native receiver write exceeds selected storage")
            buffer[offset : offset + 4] = value.to_bytes(4, "little")
        return self.invoke_iat(iat_rva, (buffer,))

    def borrow_receiver(
        self, memory: NativeMemoryArena, address: int
    ) -> NativeReceiverProjection:
        """Pin a source/owner-bound receiver until explicit safe release."""
        return NativeReceiverProjection(self, memory, address)

    def create_awd04_receiver(self) -> NativeReceiverProjection:
        """18 TY99710 zeros exactly 12 DWORDs at native receiver+e8."""
        if self.caller_sha256 != _LARGE_TY18_SHA:
            raise LookupError("AWD04 receiver initializer unavailable for exact caller")
        memory = self.engine.context.native_memory
        if memory is None:
            raise LookupError("Selected context has no native arena")
        memory.assert_owner(
            self.engine.context.module_sha256, self.engine.context.native_memory_owner
        )
        address = memory.alloc(0x30)
        try:
            return NativeReceiverProjection(self, memory, address, owned_kind="AWD04")
        except BaseException:
            memory.free(address)
            raise

    def create_tpw03_receiver(self) -> NativeReceiverProjection:
        """18 TY57bf0: allocate/copy seven read masks and one write mask."""
        if self.caller_sha256 != _LARGE_TY18_SHA:
            raise LookupError("TPW03 receiver initializer unavailable for exact caller")
        memory = self.engine.context.native_memory
        if memory is None:
            raise LookupError("Selected context has no native arena")
        memory.assert_owner(
            self.engine.context.module_sha256, self.engine.context.native_memory_owner
        )
        allocated: list[int] = []
        try:
            address = memory.alloc(0xC4)
            allocated.append(address)
            descriptors = (
                (6, 0, b"\xe0"),
                *((identifier, 2, b"\x0f\xff\xff\xff") for identifier in range(15, 20)),
                (0x36, 0, bytes((255,)) * 5),
                (0x36, 0, bytes((255,)) * 5),
            )
            for index, (identifier, position, mask) in enumerate(descriptors):
                pointer = memory.alloc(len(mask))
                allocated.append(pointer)
                memory.write(pointer, mask)
                descriptor = (
                    bytes((identifier, position, 0, 0))
                    + pointer.to_bytes(4, "little")
                    + len(mask).to_bytes(4, "little")
                    + bytes(8)
                )
                memory.write(address + 0x24 + index * 0x14, descriptor)
            return NativeReceiverProjection(self, memory, address, owned_kind="TPW03")
        except BaseException:
            for pointer in reversed(allocated):
                memory.free(pointer)
            raise

    def create_4wd05_receiver(self, file_bytes: bytes) -> NativeReceiverProjection:
        """18 TY9a530 loads its native length-prefixed, nibble-coded history file."""
        if self.caller_sha256 != _LARGE_TY18_SHA:
            raise LookupError("4WD05 receiver loader unavailable for exact caller")
        if type(file_bytes) is not bytes or not 68 <= len(file_bytes) <= 131138:
            raise ValueError("Bounded native 4WD history file required")
        declared = int.from_bytes(file_bytes[:4], "little")
        if not 32 <= declared <= 32 + 65535 or len(file_bytes) != 4 + 2 * declared:
            raise ValueError("Native 4WD file declared/encoded length mismatch")

        def nibble(value: int) -> int:
            # TY156b10 uses signed division by16 and byte-sized shifts, not ASCII hex.
            signed = value if value < 128 else value - 256
            quotient = signed // 16 if signed >= 0 else -((-signed) // 16)
            return (
                (((value - (quotient << 4)) & 255) >> 2) + ((quotient + 62) << 2)
            ) & 255

        decoded = bytes(
            ((nibble(file_bytes[index]) << 4) + nibble(file_bytes[index + 1])) & 255
            for index in range(4, len(file_bytes), 2)
        )
        memory = self.engine.context.native_memory
        if memory is None:
            raise LookupError("Selected context has no native arena")
        memory.assert_owner(
            self.engine.context.module_sha256, self.engine.context.native_memory_owner
        )
        allocated: list[int] = []
        try:
            address = memory.alloc(0x58)
            allocated.append(address)
            history = decoded[32:]
            pointer = memory.alloc(len(history)) if history else 0
            if pointer:
                allocated.append(pointer)
                memory.write(pointer, history)
            memory.write(address + 8, decoded[:16])
            memory.write(
                address + 0x18, (16 if any(decoded[:16]) else 0).to_bytes(4, "little")
            )
            memory.write(address + 0x1C, decoded[16:32])
            memory.write(
                address + 0x2C, (16 if any(decoded[16:32]) else 0).to_bytes(4, "little")
            )
            memory.write(address + 0x50, pointer.to_bytes(4, "little"))
            memory.write(address + 0x54, len(history).to_bytes(2, "little"))
            return NativeReceiverProjection(self, memory, address, owned_kind="4WD05")
        except BaseException:
            for pointer in reversed(allocated):
                memory.free(pointer)
            raise


class NativeReceiverProjection:
    """A live native receiver's exact mutable storage, without host pointers.

    A busy engine prevents close, retaining the pin. The owner must finish or
    explicitly stop that engine and retry close; this object never stops work.
    """

    def __init__(
        self,
        libraries: NativeProcedureLibraries,
        memory: NativeMemoryArena,
        address: int,
        *,
        owned_kind: str | None = None,
    ):
        self.libraries, self.memory, self.address = libraries, memory, uint32(address)
        context = libraries.engine.context
        if context.native_memory is not memory:
            raise ValueError("Receiver arena is not the selected engine's native arena")
        memory.assert_owner(context.module_sha256, context.native_memory_owner)
        self._lease = memory.borrow(address)
        self._buffer = self._lease.__enter__()
        self._closed = False
        if owned_kind not in (None, "AWD04", "TPW03", "4WD05"):
            self._lease.__exit__(None, None, None)
            raise ValueError("Unknown source-owned receiver lifecycle")
        self._owned_kind = owned_kind

    @property
    def buffer(self) -> bytearray:
        if self._closed:
            raise ValueError("Native receiver projection is closed")
        context = self.libraries.engine.context
        if context.native_memory is not self.memory:
            raise ValueError("Selected native arena changed during receiver lifetime")
        self.memory.assert_owner(context.module_sha256, context.native_memory_owner)
        return self._buffer

    def call_method(self, method_rva: int, args: tuple[int, ...] = ()) -> int | None:
        return self.libraries.call_method(method_rva, self.buffer, args)

    def close(self) -> None:
        if self._closed:
            return
        if self.libraries.engine.worker.running:
            raise BufferError("Native receiver must outlive the running engine worker")
        buffer = self.buffer
        offsets = {
            None: (),
            "AWD04": (0x24,),  # TY99670: free receiver+10c (buffer+24).
            "4WD05": (0x50,),  # TY9a390: free receiver+138 (buffer+50).
            "TPW03": (*range(0x28, 0x28 + 7 * 0x14, 0x14), 0xB4),  # TY57b40.
        }[self._owned_kind]
        for offset in offsets:
            pointer = int.from_bytes(buffer[offset : offset + 4], "little")
            if pointer == self.address:
                raise ValueError("Corrupt nested pointer aliases its receiver")
            self.memory.free(pointer)
            buffer[offset : offset + 4] = bytes(4)
        self._lease.__exit__(None, None, None)
        self._closed = True
        if self._owned_kind is not None:
            self.memory.free(self.address)

    def __enter__(self) -> Self:
        _ = self.buffer
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()
