# CSDF native library providers

`scripts/script_libraries.py` supplies the five raw CSDF libraries through
`ScriptLibraries(...).libraries`, accepted by `script_vm.evaluate`. Original
DLLs are inspected statically and never loaded or executed. The implementation
uses no adapter on import, construction, or synthetic execution.

```python
from scripts.script_libraries import ScriptLibraries
from scripts.script_vm import ScriptObject, Step, evaluate

host = ScriptLibraries(
    lambda ecu, request: bytes.fromhex("6102aabb"),
    ecu="synthetic-engine", ecu_id=3,
)
script = ScriptObject(1, (), (b"ScriptLibCommunication", b"ScriptLibLang"), (
    Step(0, 0x40, b"\x03\x00\x00"),  # ECU identifier
    Step(0, 0x13, b"\x21\x02"),       # authored request
    Step(0, 0x15, b"\x00\x80"),       # native output variable 0x8000
    Step(0, 0x40, b"\x01\x00\x02"),  # Send(request, output_variable)
    Step(0, 0x15, b"\x00\x80"),
    Step(0, 0x40, b"\x02\x01\x01"),  # DataLength(output_variable)
    Step(0, 0x44, b""),
))
assert evaluate(script, libraries=host.libraries) == (
    (1, b"\x03"), (1, b"\x00"), (1, b"\x04"),
)
```

## Recovered script function tables

Arguments below appear in script push order, left to right. Byte arguments use
their first byte after native variable resolution. Scalars return type 1 and
binary data returns type 3. The opcode's high byte selects the script library
ordinal; its low byte selects the function ID. It is not a PE export ordinal.

| Library / ID | Native name | Arguments and effect | Handler RVA |
|---|---|---|---|
| Communication / 1 | Send | Request, optional output variable; store raw single reply, return sequence status | `0x2f80` |
| Communication / 2 | ChkSupport | PID, bitmap; return MSB-first support bit | `0x1910` |
| Communication / 3 | GetECUID | No arguments; return injected u8 ECU identifier | `0x2770` |
| Communication / 4 | PIDDataFillZero | PID, source, mask; insert zeros for zero mask bytes, cache by PID, return filled bytes | `0x2bd0` |
| Communication / 5 | SendPluralRecv | Request, optional output variable; store length-framed replies, return sequence status | `0x3300` |
| Communication / 6 | ExtractRecvData | Zero-based index, framed replies; return selected body or empty bytes | `0x24d0` |
| Communication / 7 | SetRetryCnt | New u8 retry count; return previous count; initial value 2 | `0x3870` |
| Communication / 8 | GetSupportData | Identifier, framed support table; return matching TLV value or empty bytes | `0x2870` |
| Communication / 9 | UpdateCommLogFillZero | Mask, service; for `0x21`/`0x12`, fill last logged response after its two-byte header, preserve tail, return zero byte | `0x3e20` |
| Communication / 10 | SetAddrType | Byte equal to 1 enables address mode; return previous boolean; initially false | `0x3680` |
| Communication / 11 | TargetDidCheck | Two-byte big-endian DID; check injected inclusive ranges, low byte zero matches the high-byte range | `0x3a30` |
| Lang / 1 | ExtractData | Source, u8 start, optional u8 count; default count is remaining low-byte length | `0x1230` |
| Lang / 2 | DataLength | Data; return length modulo 256 | `0x1090` |
| Debug / 1 | Print | Consume 0–255 resolved values; publish a host debug event | `0x1090` |
| System / 1 | PostMessage | Byte WPARAM value; invoke host callback and publish event | `0x1130` |
| RMLib / 1 | ReadRecord | Binary source name, one-based u8 record ordinal; return selected record | `0x1090` |

The original tables contain exactly 11, 2, 1, 1, and 1 entries respectively.
All 16 occur in the 19 inspected Techstream 18 raw CSDF programs. There are no
unreferenced script function IDs in these five tables. Their PE export counts
are 60 (Communication), 9 (Lang), 9 (Debug), 17 (System), and 9 (RMLib): the
additional exports are constructors, vtables, list helpers, parameter accessors,
and library metadata, rather than extra script function IDs.

## Binary and host contracts

`Send` preserves the native raw request stack value. Its optional output must be
a type-4 native variable reference (`0x8000 + zero-based slot`); it is not resolved
before writing. A failed sequence clears output bytes. Controller sequence codes
map as recovered at Communication RVA `0x4910`: `0 → 0`, `8 → 1`, `9 → 2`,
`10 → 3`, other `0x31xx → 5`, all other nonzero codes → `4`. Unexpected host
exceptions propagate; they are not reported as successful exchanges.

The normal `exchange(ecu, request) -> bytes` callback supplies a single raw ECU
reply. `plural_exchange(ecu, request) -> tuple[bytes, ...]` supplies independent
reply bodies. Without it, a plural call frames the one normal exchange reply.
`pack_replies` encodes repeated little-endian u16 length/body records.

For a controller bridge that honors native retry and address settings, inject
`native_exchange(ecu, request, CommunicationOptions) -> ExchangeResult` instead.
The options contain the current retry count, address-mode boolean, and plural
flag. Results provide the native sequence code and tuple of response bodies;
`SequenceError(code)` also conveys a controller code. The two-argument callback
does not receive or emulate low-level retry/address behavior. These parameters
are recovered at Communication RVA `0x47c0`; the host does not invent a retry
algorithm or silently retransmit vehicle requests.

Support tables contain the plural length prefix, a two-byte body header, then
`identifier:u8, length:u8, value` TLVs. Native `GetSupportData` uses the outer
length as a cursor fence and stops at the selected TLV. A selected final TLV may
extend beyond that fence while remaining within the supplied source; this occurs
in an inspected original script literal. The provider preserves that behavior,
while rejecting any read beyond the actual source bytes. `ExtractRecvData`
validates its length-delimited reply records. Empty bitmaps are rejected rather
than reproducing the native divide-by-zero in `ChkSupport`. Support-bit indexing
uses `((pid - 1) & 255) % (bitmap_length * 8)` and `0x80 >> (bit % 8)`.

`ReadRecord` passes the source name up to its first NUL to injected
`read_record(name: bytes) -> bytes`. The returned database consists of repeated
u8-length/body records. Ordinal 1 means the first record. A missing source or
missing ordinal returns empty bytes; a truncated entry raises `ValueError`.
Absent `read_record` or DID database dependencies raise explicit `RuntimeError`.
No original database is bundled or opened implicitly.

The recovered Debug handler discards its arguments; its result object has empty
storage and no initialized type field. System has the same undefined return
type and invokes its configured Windows message target. The Python host chooses
an empty type-3 return for those two handlers and exposes structured debug/message
events plus optional callbacks. This deterministic return type is a host policy,
not a claimed native scalar success value. The byte argument is WPARAM; native
HWND and UINT message ID come from configured system parameters. Windows message
delivery is replaced by the explicit WPARAM callback; the native caller's
uninitialized auxiliary stack value is not reproduced. Original callers discard
these results.

Malformed argument counts, output references, byte ranges, frame boundaries, and
database records fail explicitly. VM and provider retained state each have a
16 MiB aggregate byte limit; provider logs/events also have a 4096-entry limit.
Plural exchanges have at most 256 replies with u16 body sizes. Cancellation and
monotonic deadlines are checked before/after host callbacks and during long
support/database scans. Injected callbacks must enforce their own blocking-I/O
timeout; synchronous Python cannot interrupt an indefinitely blocked callback.

## Evidence and checks

Static disassembly and focused REA/Ghidra decompilation were reconciled against
the original script tables and call sites. Native PE SHA-256 identities:

| DLL | SHA-256 |
|---|---|
| ScriptLibCommunication.dll | `b5315e4d007ddec52c179070eb8398da8e2598bb340b1eb651e00c606c986b06` |
| ScriptLibLang.dll | `8f0759e10d2f42341ae95ebc618b0bad53f174dd2050d9da3b04ce8b95541e6e` |
| ScriptLibDebug.dll | `bd5d3eb8b655284d346610cd4f608fe7afc41b006e70c70d94bd3a52228d8ce8` |
| ScriptLibSystem.dll | `86c79aa89f64223741b8a01a2a8cac2f14ef1a83ab43337af2891dc7fddd4046` |
| ScriptLibRMLib.dll | `a905aaa95f71bfa3cc15d6dd38c2220adb116461d364d70062ce977083fdef32` |

Run authored portable checks with:

```sh
python -m unittest discover -s tests -p test_script_libraries.py -v
```

The private corpus check executes all 19 original programs with deterministic
synthetic ECU responses and controller-timeout responses, plus two focused
profiles for DID and plural-DTC paths: 40 completed runs, all 16 declared function
IDs dynamically observed, no unsupported library call. The synthetic host
explicitly initializes script variables to empty byte arrays. Coverage does not
assert every branch or vehicle equivalence. Original scripts, extracted data,
disassembly, decompiler output, private runner, and detailed coverage remain
outside the published tree. Public tests and the example above are authored.

Physical adapter/ECU behavior remains `PHYSICAL_UNCONFIRMED`.


## Native IT3 procedure library seam

`NativeProcedureLibraries(caller_bytes, engine)` extends the exact source-bound
`UtilityImportBinding` in `scripts.utility_ex`; direct imported calls use its
`invoke_iat(iat_rva, args)`. It does not create successful business callbacks or
execute an original PE. The original18 caller SHA and its exact UtilityEx engine
SHA are checked before any operation; no 12/18/Plus alias is inferred.

`call_method(method_rva, buffer, args=())` additionally executes 45 original18
`IT3UtilityTY2` native receiver-method bodies. Its source identity is
`ecba533aeaa2ec2a014fa59a113d025a8efe90338767c2786b8a5a891ca0f599`.
`buffer` is the stable mutable native storage starting at receiver offset
`0xe8`; it is passed unchanged to the actual engine export. The caller keeps
this storage for the lifetime of asynchronous work. Source bodies either pass
that buffer directly, first write an argument DWORD to its offset zero, or first
write a DWORD to offset `0x1090` (`VIF01`) or `0x17450` (`VC05`). These writes
precede the imported call and remain visible even if that call raises a host
exception. No buffer snapshots, scalar reinterpretation or success substitution
are used. Host bounds reject native out-of-range writes before dispatch.

Private static evidence is `analysis/evidence/no-car-9/IT3UtilityTY2.asm`,
`IT3UtilitySpNK.asm` and `native-marshalling.json`. The test checks every one of
these 45 authored mappings against the original instruction bytes, including the
IAT operand, scalar write offset and return argument cleanup; its authored
marshalling tests verify pointer identity, exact retained writes, malformed
arguments and cancellation/fault propagation. The private image test skips in a
public checkout without the supplied image; synthetic checks still run.

This is a marshalling-body port, not a full native procedure implementation.
The native UI/controller selection, scheduler, host common lifecycle, alternate
native methods, native exception paths and actual selected-input-to-wire
composition belong to the ongoing OWN3/83/108 integration. Earlier accepted
CSDF corpus results do not close that new integration gate. The native TY2
`AHC03 EndExtendedSession` receiver supplies a buffer; the previously rejected
argument was reported and its owner corrected the target ABI. No source argument
is discarded by this bridge.

The private `door-host-lifecycle.json` and `door-mfc-lifecycle.asm` also resolve
the actual Door controller's status and cleanup chains. Status reaches the
concrete `Ex2GetThreadStatus` IAT slot. Cleanup selects the first nonzero progress
dialog among controller fields `0x50/0x54/0x58/0x5c`, kills timer `0xfa00`, hides
and ends that dialog, clears its pointer and restores host focus. Exact supplied
MFC42 ordinal bodies identify those UI primitives and preserve conditional modal
and windowless-control branches. This is not a call to stop an engine worker.
The native procedure controller consumes this evidence separately.


The bounded native pointer integration is documented in
[native-memory.md](native-memory.md). The exact original18 large TY caller adds
four reviewed receiver bodies for TPW03, AWD04 and 4WD05, with source-fixed
receiver producers and source-owned nested allocation cleanup. A real native
history-file→receiver→IAT→chassis→typed raw SDK test now covers literal success,
malformed nested spans, cancellation and SDK faults. This selected integration
is distinct from the still broader native procedure/UI closure work.
