# CUW2026 retained programming primitives

This adapter owns four exact-source modules: CommonFlashWriter (23 callable
names), HINOUtils (26), CanCIDGetter (one), and P4 security powertrain preparation
(one). The HINO exported virtual-table symbol is data; its first target resolves
to the authored Halt implementation. It is never executed as a PE pointer.

The original inventory retains all 63 modules, 149 callable names and six data
symbols. Consolidated, M16C/VFOREST, Unified/Ethernet, HINO/SBR, MMC, generic CAN,
body, P4/P5 getters and P5 preparation have separate owners and required parent
gates. Matching names or hashes do not establish older-version behavior parity.
All current 51 names have implementation paths and an independent scoped source
and importer review. Engine-owned CID record/count persistence and the remaining
delegated families retain separate required parent gates.

`CommonFlash2026(runtime)` implements acknowledgment/status, memory descriptors,
authorized nonce/key transfer, ID checking, finish polling, CPU transition and
block checking/erasure/transfer/verification over injected primitives. Requests
include their complete CAN header. `get_status` makes up to four attempts and
catches the native CPassThru base class, including its CJ2534 driver subclass.
Driver status and inherited native error enum remain separate. ACK driver
statuses 9/16 return false only within the recovered acknowledgment catch.

Verify's inner catch permits a nonfinal status failure only while the preceding
status remains zero. A final failure or a fault after a pending status becomes
native error 15. Sleeps occur outside that inner catch. `write_bytes` updates
cursor/count before the count observer, then percentage before its observer.
`writing_error_dispose` clears count/notifies before clearing percentage/notifying.
Geometry comes from imported native metadata: leading zero sizes are permitted
outside the selected range, while every selected block must have a positive size.

`HINOUtils2026` implements DSS session/security, tester-present, transfer and
preparation. DSS security complements the four received seed bytes. It uses no
external whole-stage callback. `HINODSSPreparationResult` separates preparation
success, inherited native enum, optional driver status and notification result.
Preparation releases its filter before requesting the failure notification.
An explicit `NativeException2026` native catch-all maps to 9999; a base CPass exception does not
invent a driver status. Copy/move helper operations preserve injected references.
The SIL helpers emit full KWP headers/checksums and preserve native errors
1006/1007, ANSI/NUL CID extraction and baud/FastInit parameters.

Native callback12 and host cancellation are distinct. AMT/CAN tester-present
skips its request when native callback12 is true. The generic getter similarly
skips its outer CID request, while its diagnostic receive loop has its own
native cancellation check. HINO Halt and AMT also check callback12 at every
receive-loop head after writing; native cancellation returns the previous native
response buffer and restores timeout. Host cancellation and deadlines always propagate.
Human callbacks are checked before and after invocation.

`bind_native_context(...)` binds only the exact2026 P4 security preparation
identity. `bind_can_cid_context(...)` binds the exact2026 generic getter identity.
Both revalidate their `NativeParameterBinding2026` against the imported CUW and
original catalog sources, then use the actual2026 metadata/address producers.
Public stage runners require the original factory-issued context and repeat that
binding before I/O. Replaced or unissued contexts fail without provider calls.
Private raw-ABI helpers support isolated literal fixtures; they are not importer
entrypoints.
P4 global ECU/service authorization keys are distinct from node overloads.
Explicit authorized key attachments must agree with imported values. Immutable
`previous_addresses` contains typed native getter history; the source history
selector intersects its request IDs and widths with actual catalog candidates.
Address geometry cannot be supplied through attachments or arbitrary observations.

`prepare_p4_security_powertrain(context, runtime, key_provider)` implements the
raising internal wire flow. It acquires target filters, sends `27 01` with global
ECU authentication bytes, transforms the sixteen-byte seed using the authorized
`(seed, service_auth_key) -> key16` provider, waits, and sends `27 02`. Native
unavailable errors 22/23 skip a target. No prepared target fails with 17 unless
the source retry flag permits the skip. Successful targets receive diagnostic
mask and `10 02`. An empty imported address vector follows the same native
error17/retry-flag branch without I/O. Caller-owned connections and periodic resources survive.

The actual export adapter is `run_p4_security_powertrain(...)`: its
`native_return` is the direct BOOL. Typed native failure writes error kind 1 and
the inherited enum; a derived driver failure also writes driver status. The
native catch-all leaves those fields unwritten. `None` output fields preserve
caller state. `native_success` is None because this export has no separate
success-output BOOL. Preparation never reports completed programming.

`run_can_cid(context, runtime)` owns a protocol-6 connection, probes `09 00`
using the recovered support bitmap, then reads `09 04`. CID decoding retains
seven/eight-byte full-Data framing, exact count-times-16 length, ANSI bytes,
NUL termination and trailing spaces. Partial CID vectors survive later native
failure. `native_return=None` represents the pointer-return ABI;
`native_success` is the seventh output parameter BOOL. `query_ids` contains
uppercase ASCII hex from the original two/three-byte request ID, with matching
`query_cpu_indices` of zero for the first 34 CID records. The controller consumer must apply
those writes to existing records while preserving bytes beyond the native NUL.
Typed address history and query associations remain private controller inputs.

Ordinary provider `OSError`, `ValueError` and other Python host faults propagate
without inventing a terminal native BOOL or native error9999. Native catch-all
branches accept explicit typed source-native exceptions only. Host validation
rejects unsafe native buffer/array cases before I/O. Host abort,
deadline and cleanup failure propagate. Cleanup attempts all owned releases;
failed resources remain owned. When cleanup also fails during an existing abort,
the primary exception survives with cleanup notes. These bounds and cleanup
rules are explicit host policy. Security payloads and native buffers are absent
from public reports and context repr. No OEM code, keys or binaries are published.

Run the authored software checks with:

```sh
python -m unittest discover -s tests -p test_programming_2026_legacy.py -v
```

The checks include actual imported CUW -> parameter -> address -> typed J2534
provider paths, literal wire frames, inherited exception catches, partial results,
observer faults, cancellation and cleanup. Injected providers do not execute a
vendor DLL or contact a device. Physical behavior is **PHYSICAL_UNCONFIRMED**.
