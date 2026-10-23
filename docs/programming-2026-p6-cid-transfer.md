# Reconstructed Phase6 CID companion transfer

The source-bound P6 getter records each node's pre-call CID total and appends
new IDs to the getter vector. Its companion helper writes from that saved total
through the current vector length, bounded by 34 raw slots. Every ID appended
by one node receives that node's `GetDiagID()` value; a node that returns no IDs
does not advance the range. This is a per-node CID range, not a one-ID-per-node
mapping.

Each written record is 12 bytes. The producer zeros bytes 0..3, copies at most
six `DiagID` bytes plus NUL into bytes 4..10, preserves seeded bytes after an
early NUL, and leaves byte 11 untouched. The host reducer takes the exact
per-node CID counts and returns records only for IDs that were appended, up to
the same 34-slot model bound.

The importer at `0x1005a050` clears the canonical ID and record vectors, then
copies exactly the raw returned-ID count using ID cells at `+0x264+i*0x22` and
records at `+0x6ec+i*12`. Count zero therefore clears both vectors. It has no
visible count clamp; the host's 34-ID bound reflects the fixed source raw-ID
area and is not a claim that native oversized counts are safe.

## Caller and host path

For the collected `CUW.dll`, the worker calls selected module `Execute` with
arg2=`CStart+0x14c` (`0x1005ae41..0x1005ae52`). The P6 getter's record pointer
calculation reaches `CStart+0x6ec`. After `Execute` returns, CUW stores thunk
`0x1005a6a0` in `CStart+0x10`; the owner invokes that callback at
`0x1003d00d`, and the thunk jumps to importer `0x1005a050`. This is a callback
field path, not a vtable entry. Exact instruction evidence is in
`runtime/luna-reverse-20261023/source-p6-import-dispatch/report.md`.

The Python implementation returns a private receipt from selected P6
`Execute`, carries it with the existing issued getter return, and consumes it
in the existing outer worker import after validating the final returned ID
vector. A subsequent getter attempt clears the prior receipt so an empty P6
primary cannot overwrite a successful alternate result. Standalone replay
reports do not consume the receipt or publish IDs into live CUW state.

The tracked `RawControlStageMachineTests.test_issued_phase6_getter_imports_counted_records_before_selection`
drives an actual issued `EngineThreadJob2026` through stage cloning, selected
P6 execution, the outer callback, the ordinary getter-return receipt, counted
import, and successful Phase6 G selection. Its authored P6 producer returns two
CIDs from one node and checks both 12-byte records in the live CUW vectors.
The test substitutes the P6 helper's host traffic; it does not execute the
vendor DLL. No physical ECU was used.
