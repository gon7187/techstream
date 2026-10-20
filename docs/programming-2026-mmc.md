# CUW2026 MMC

`scripts/programming_2026_mmc.py` implements the three source-identified MMC
exports: `StartGetCID`, `StartPrepareWrite`, and `StartFlashWrite`. A matching
filename does not select this implementation: the registered CUW2026 module
identity, imported calibration, selected native parameter row, CPU and native
communication-address producer must agree.

`bind_native_context(container, node, observed_cids, selection, identity,
attachments, observations)` consumes the actual `NativeParameterBinding2026`,
`native2026_metadata`/`native2026_archive` and
`communication_addresses_from_parameter` producers. Archive bytes, selectors,
loader start address and erase geometry come from the imported CPU; attachments
cannot override them. The raw native image header is explicitly converted to
numeric areas at the operation boundary; malformed declared geometry is rejected
before I/O, rather than becoming an empty erase list. The writer selects the current CPU address; getters and
preparation select the first native address, matching the original exports.

`run_native(context, runtime, preparation_state=..., notify=...)` consumes
`NativeRuntime2026`, `CanDiag2026`, and the actual `J2534Device2026.primitive`
bridge. The injected provider performs individual typed J2534/OS operations.
There is no callback that declares an entire native stage successful.

The getter observes the native abort callback before each query; an asserted
callback skips that individual query with an empty field. This is distinct from
host cancellation, which propagates after resource cleanup. The getter connects CAN protocol6, installs its native filter, reads fixed24-byte
F111 and F188 strings, removes the filter and disconnects the native device. Source
`1C7F` dereferences the saved `CJ2534IF` object vtable slot+8; it is a device
disconnect, not a UI callback. Partial acquisition and faults still attempt both
filter and connection cleanup. A failed F188 query, including NRC31, fails the export; the older
vendor getter's inferred empty-success rule is not reused.

Preparation observes native UI state1 while transmitting1082, then state3 to
confirm entry. The native wall-clock millisecond producer drives the strict
`>2000` burst and wraps at86400000. The filter and functional7DF `3E80`
periodic message follow the burst. Native entry-write exceptions are suppressed
and retried inside the entry loops, preserving the deadline/cancellation bound. Session1002 supplies receive/P2* timing;
2741/2742 uses the recovered16-round uint32 algorithm and the selected native
18-word/256-word tables. Engine_MMC is the CalibrationFile exported literal
`65`; other kinds use the second native table. The successful preparation keeps
its periodic resource owned by the runtime for the writer or explicit
`runtime.close()`; the filter is always released.

Preparation requires `attachments['prepare_engine']`: the exact registered
reconstructed-inspection MMC preparation PE bytes. `security_tables` reads only
its code bytes and extracts immediate constructors from the four initializers.
It never executes PE code. The source contains no OEM security table constants.
The existing static CUW split-module decoder supplies this private artifact from
an imported original and companion. Authentication history redacts the key.

The writer performs loader records → loader-start routine0301 → imported erase
areasFF00 → image records → completion0304 → periodic stop → functional7DF1181
→ parameterized final wait. It clamps the negotiated transfer maximum to4095,
subtracts the two-byte service/sequence header, wraps the sequence byte and
checks the supplied two-byte transfer-exit CRC. Progress includes encoded record
headers/trailers and uses the native image byte offset. Native typed failures
preserve distinct operation and J2534 status values, reset count then percent
with notifications in that order, and distinguish failure before/during writing.
Native generic getter catches preserve prior fields. Preparation assigns9999/status1
only inside its post-filter native handler; entry observations are outside it.
Writer business has typed handlers only; unknown native exceptions propagate. A bare pass-thru exception
preserves the previous driver detail; `native_driver_error_code` explicitly
binds that caller-owned field. Host cleanup still releases resources after
generic exceptions, closing the original leak without inventing native errors.

Host safety policy adds bounded images/calls/resources, rejects invalid lengths
and zero-width transfers, propagates cancellation/deadlines, and stops periodic
resources after failed preparation. Every cleanup is attempted after faults;
native filter cleanup faults preserve the previously stored native Boolean while
the host report records cleanup failure. Writer cleanup StopSync faults propagate. These are explicit host
policies where the original permits unsafe/unbounded behavior.

Run the authored regression set:

```sh
python -m unittest discover -s tests -p test_programming_2026_mmc.py -v
```

The tests import authored CUW and native parameter tables through the actual
31/47/48 providers, check literal wire traffic, and exercise real typed
`PrimitiveResult`/`NativeMessage` driver chronology. Private static verification
also compares all548 extracted initializer words against the source-bound
reconstruction and executes actual-material preparation through the typed bridge.
No vendor executable, adapter, vehicle or network is used. Vehicle behavior
remains `PHYSICAL_UNCONFIRMED`.

Canonical native ABI results are separate from host state: `native_return` is
the actual direct writer/preparation Boolean, while the pointer-return getter
uses `native_return=None` and its actual out-parameter `native_success`. The
writer success instruction precedes its final notification; its native Boolean
can therefore remain true when that observer throws and host state is failed.
Unknown Disconnect handback and host abort do not invent a native Boolean.
Untyped host provider exceptions propagate unchanged after cleanup, including
entry-write faults; only explicit native-domain faults enter native catch-all scopes.


When a concrete CUW2026 engine is supplied to `run_native(engine=...)`, the getter
requires its owned phase0 and the same source CUW before I/O. Immediately after
the actual F111 C-string assignment it calls the engine's identity-checked
`apply_mmc_getter_hardware`. This updates working994 before F188. Empty F111
also writes an empty string. F188 native or host failures retain that working
field; they do not publish D4C4. The actual controller's5a050 commit publishes
`received_hardware`, which47 uses for VBF target hardware selection. Isolated
handoff tests do not substitute for the complete public reception/selection path.

The optional static-image checks cover positive/empty F111, native and host
F188 failures, prior authoritative hardware, and owner/phase rejection before
I/O. They use authored CUW and replies with the concrete statically inspected
engine; the original binaries are never executed.


`runtime/no-car-72/verify_hardware_public.py` exercises the actual public importer,
controller reception and engine commit against the typed48 SDK driver. Matching
hardware with empty CID selects the VBF target. A native F188 failure retains a
false native BOOL and an empty CID vector but still publishes F111 hardware at
5a050. An F188 host failure preserves working994 without publishing D4C4. Native
cancellation after F111 skips F188; empty hardware matches only an explicitly
empty target. A mismatched target is rejected by47. Every exercised return/fault
path releases the getter filter and channel.
