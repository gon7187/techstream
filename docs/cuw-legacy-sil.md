# Original executable SIL programming

`scripts/cuw_legacy_sil.py` reconstructs original CUW executable byte-level
algorithms. It imports the common host deadline and cancellation runtime through
`cuw_legacy_engine`; it does not invoke a Windows executable or delegate programming success to a
callback. Individual library/J2534 operations remain explicit host primitives.

The concrete boundary is `write_messages` and `read_messages`, with native protocol
ID, flags, message count and immutable message bytes. Reads preserve complete
`NativeMessage` fields. M16C password and page operations submit one atomic native
two-message batch. `ioctl`, timeout changes, waits and progress notifications are
separate chronological primitives. Initializations require an explicit observed
padding flag because native RxStatus `0x10` has two different meanings.

Implemented primitives include:

- Original raw SIL initialization, baud selector mapping, memory probing, blank,
  erase, internal verification, packet writing and external verification, including
  wide block ranges and source-specific pending statuses.
- EMPS packet construction and its separate stale-response and retransmission
  counters. Each packet contains exactly 1024 data bytes; final and non-final
  acknowledgements have different valid status values.
- Original M16C password, status, erase, write and verify operations across its
  three fixed regions, with source-exact atomic message arrays and address bytes.
- Original K-line exchange pending and busy branches, including the native stop
  request after pending exhaustion, and DCMPRL seed/key, download, transfer and
  checksum primitives.
- Original executable memory geometry shared with `cuw_legacy_can`.

The EMPS controller now binds imported CPU metadata and image bytes to an
authenticated original12 or original18 executable, runs the native packet loop,
and preserves error fields, partial packet index, timeout restoration and GUI
callbacks. Original12 retains its extra 2000 ms wait before initialization. Its
channel recreation branch uses the shared original driver lifecycle and preserves
the completed packet index across retries.

The DCMPRL controller also binds both originals to complete initialization,
security, geometry, transfer, countdown and final callbacks. Error-dialog
reconnection finalizes the failed invocation; its saved retry mode changes the
next invocation. Geometry uses the materialized first-image length, while
progress uses the declared FlashSize.

`execute_sil(context, io)` now dispatches all five concrete
original12/18 controllers. Generic SIL binds the native selected target/password
RAM through the shared getters and combines `selected_driver_delay(context)`
from the actual copied selected-library record with the source CPU comparison
before applying the 20 ms
narrow verification delay. Its native failure path uses the concrete recovery
store, reconnect helper and final callbacks. Generic reconnect catches CJ and
CPass into the native error-dialog loop; foreign native exceptions propagate
from Connect. EMPS initial scope copies error fields only for CJ: CPass and
foreign native exceptions take the native flag-only catch-all.

Occupant executes short and long security, its source-specific initialization,
always-grouped programming, manager `ed6`/`ed7` branches, final long-form `80`
command and timeout restoration. Those manager fields remain distinct from saved
recovery `Writing` and `WritingEndBlock`. M16C selects the first eligible other
CPU from source string pointers, uses its selected target password for bootstrap,
then uses the selected M16C CPU password and programs all three regions. Its
native catch-all domain is explicit and does not swallow host cancellation.

Imported authored SREC replays enter the shared engine Execute dispatcher for
all five families and both original builds. Native target indices are produced by
`initialize_executable_targets` and `complete_executable_targets`, including a
direct unresolved-CID fallback producer that appends the image-derived password.
That direct control does not establish ordinary outer admission after every CPU
is excluded from compaction. The source classifier and selected library record are bound through
`select_library`; caller delay booleans are rejected. VBF-specific target preparation,
post-compaction work-order composition and independent complete source/EH review
remain open. Positive tests do not close those integration gates
or prove complete original12/18 application compatibility.

`discover_sil_cids(context, io, *, terminated)` executes the original generic
`CSilCIDGetter`: source attempt bytes select slow initialization or three fast
variants, `09/03` supplies the quartet count and `09/04` supplies the 16-byte CID
strings. Pending and busy handling, receive-only followups, secondary target,
partial termination and native CJ/CPass/catch-all scopes retain their distinct
behavior. The returned `SilCIDResult` binds the build, calibration and retained
channel; `validate(context)` rejects changed fields and another channel. Native
error fields are returned independently of writer callbacks. Hardware publication
belongs to a separate worker phase and is not inferred from a CID string. The actual catalog DLL-switch and specific getter factory are checked before I/O.
The normal source completion pair is retained independently of zero error fields;
failed/terminated/tampered/reused records cannot enter the normal publisher.
Forty Generic controls join the actual getter, publisher, target producers and
writer consumer. Thirty-two matched controls compact actual source rows; eight
select compact CPU1/source CPU2 through `select_executable_cpu`, retain saved
cursor0, and emit its distinct C7 image, A1B2C3D4 password and location. Eight
unmatched fallback controls assert that ordinary compaction rejects zero CPUs.
The getter closes its channel. These controls invoke the actual source manager
`connect_executable_context`, then `select_executable_cpu` to reconstruct the
selected constructor with current timeout snapshots. Every writer I/O requires
a live channel. Eight additional both-build Connect fault controls preserve CJ,
foreign native, host and cancellation identities; only CJ writes manager e60/e64.
The outer GUI decision to invoke Connect, manager success/error latch and separate
hardware worker remain open; this is not a whole outer manager replay.

The common K-line exchange also rewrites a caught native CPass category to its
caller's method category before rethrowing the same object, matching the original
12/18 helper. Host error identity and timeout restoration remain independent. Native CPass
category storage has coherent unsigned byte and signed category views; handlers
publish byteff as DWORDffffffff, including after category setters.

CPU and block-range tables are decoded from each supplied original executable.
Their startup pointer assignments are reconstructed statically; no original
executable is run and no table contents are embedded in this module.

The original18 status helper has three effective attempts when retry is enabled;
this was checked against static x86 and intentionally differs from a four-attempt
CUW2026 implementation. The original initialization uses only the first four
LocationID bytes, reversed, followed by a little-endian password. No protocol
parity with newer DLLs is assumed.

The public suite has54 source-free authored checks and skips none. It does not
read owner binaries or depend on environment variables:

```sh
python -m unittest discover -s tests -p test_cuw_legacy_sil.py -v
```

The47 exact-original checks are preserved in the private corpus runner. Set both
`LEGACY_CUW12` and `LEGACY_CUW18` to the owner's original executable files, then run:

```sh
python -m unittest discover -s runtime/no-car-70 -p legacy_sil_corpus.py -v
```

Missing corpus inputs fail explicitly; exact executable hashes are checked by the
actual binder. The private suite uses authored CUW/SREC data and message streams,
not vendor execution. Portable and private checks together preserve the original
83 existing methods and add runtime cleanup, native CPass rewrite and actual
serial CID getter checks; neither suite skips checks.

Physical behavior remains `PHYSICAL_UNCONFIRMED`. Private static evidence binds the
original12 and original18 executable hashes and native body ranges; original
executables, extracted code, resource tables and actual authorization material are
not part of this document or its fixtures.

Native CID termination returns from each helper locally. Fast initialization
returns still lead to the caller Sleep100; a terminated count exchange still
leads through the native data-request/clear path, and kind0 mode2/3 still invokes
the optional helper prefix before the final termination selector. Host
cancellation remains an exception. Both-build operation-tail regressions cover
termination after baud setup and count write.
