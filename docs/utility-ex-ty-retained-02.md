# Retained TY DP2, FRD, VCIB, EVB and FAS bodies

The provider is `scripts.utility_ex_ty_retained_02`, through the source-identified
`utility_ex_ty` dispatcher. `supported_exports(sha)` admits only the implemented
exact build/export combinations. `run_body(export, args, TYContext)` verifies the
SHA-256 of the supplied module bytes before requesting communication. No DLL is
loaded or executed. The common engine owns wrapper admission and scheduling.

Native pointer arguments use `TYRetainedBlock(bytearray(...))`. The buffer identity
is preserved. The UI may change its native fields while the shared worker waits;
start/result pairs reuse the same native manager, rather than create a new device
connection for a retained result action. The native lifecycle branches explicitly
retain successful FRD01, FRD05, FAS action1 and VCIB03 action3 sessions. Every result
and abort branch follows the source's normal-session restoration and release order.

EVB sends `3b2301` after one native 10000 ms sleep. FRD03 copies its complete DID
reply before modifying offset6 for the write. FRD04 clears and verifies one bit while
preserving all other received bytes. FRD05 polls its real routine every200 ms until
result, error or live UI stop; the decompiler's omitted loop is restored from ASM.
VCIB05 copies received DWORDs into caller storage; its18 C incorrectly displayed
zero assignments. FAS preserves the native ESI error result across secondary DID
reads instead of inventing a generic successful business callback.

The DP2 classic support bodies consume the concrete native support snapshots and
build packed offsets. DP2 active polling preserves native masks,1000/100 ms delays,
strict35-second timeout, stop request and mutable output bytes. DP2_14 executes
all seven supplied support rows, packed byte selection, modulo256 additive command
construction and actual `2103`/`3b02` packets. The UDS support scanner keeps four
independent target observations and restores the original target/protocol.

Direct native `Sleep` uses `context.native_sleep`, preserving one host call and
its original delay, including zero. Unbounded UI and pending-reply continuations
check host cancellation at loop boundaries. This explicit HOST termination policy
replaces native forced worker termination; source UI stop flags remain separate.
Cancellation restores the source session and releases non-retained resources.

The private `analysis/evidence/no-car-121/wrapper-packet.json` binds all51 assigned
source/export pairs to exact wrapper C/ASM hashes, callbacks, modes, arity and
10000 ms wrapper timeout. This packet proves wrappers, not complete body coverage.
All51 assigned source/export pairs are implemented and advertised. The ready-only
`reviewed-wrapper-packet.json` also binds authored body hashes, scheduler admission
and source12 inline support returns. G2/G3 remain OPEN pending concrete selected
communication lower joins and independent full source review. Nothing here
establishes physical behavior.

The BSM and dealership offset algorithms implement target enable/read-modify-verify,
native UI acknowledgement and outcome counters, retained10008 startup, cleanup-error
precedence and exact original target/protocol restoration. Empty target selections
access uninitialized native memory and are rejected at the authored host boundary.
Native result globals are published after cleanup, with exact source-specific
addresses; inline12 support returns and unsupported wrapper modes leave them alone.

VCIB02 uses `VCIBBlock` with a validated `VCIBHost` primitive provider for clock,
allocation, files and ZIP operations. All seven action branches remain in this
module: timestamp tables, selection, partial transfer, retry, storage, archive and
cleanup. Source18 retains its ANSI/32-bit CRT layout and Shell ZIP count polling
with `0x414` copy flags; Plus uses UTF-16/64-bit CRT data and the statically decoded
managed ZIP algorithm. The latter proof is pinned in the private managed source
packet. Missing host operations fail before communication. No whole-procedure
callback substitutes for business logic.

The selected TY18 FRD05 test composes the actual engine, dispatcher, facade,
fixed lifecycle, CAN pool and raw SDK primitives. It checks literal session/start/
pending/result/normal packets, retained connection identity and final disconnect.
Other source/lower combinations remain outside this concrete join.

Validation: `python -m unittest discover -s tests -p test_utility_ex_ty_retained_02.py -v`.
Fixtures are authored HOST traces. Tests isolate the module-identity check only
when exercising source-derived bodies; a separate test proves mismatched real
bytes cannot enter communication. No proprietary data is embedded in fixtures.
