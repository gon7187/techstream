# Retained TY GWY, STRACT, LAMP, ABG and EOM

`scripts.utility_ex_ty_retained_12` implements exactly 46 assigned source/export
pairs: 22 for TY18, 22 for TYPlus, and two LAMP01 operations for TY12. Admission
uses the full SHA-256 of the supplied original module. The existing core GWY02
TimeoutInit, GWY03 EndInitErr, STRACT03 EndExtendedSession and SBW operations are
excluded. Names alone never establish source compatibility.

`supported_exports(source_sha256)` lists the exact subset. `run_body(export,
args, context)` preserves the caller's mutable bytearray. The selected TY engine
joins this provider; the common engine owns asynchronous launch and completion.

Native structure DWORDs use little endian:

| Operation | Mutable structure |
|---|---|
| GWY02 StartInit | At least 20 bytes; count byte at 4, uint16 identifiers at 6, delay DWORD at 12, poll flag at 16 |
| GWY03 StartInitResult | DWORD host status; native pending exit marker 1002 |
| STRACT01 ModeTransition | Three DWORDs: transition, optional prerequisite, live host completion |
| STRACT01 SupportCheck | Two output DWORDs; only these eight bytes are overwritten |
| STRACT03 StartTestMode | Live host stop DWORD |
| STRACT04 SendMessage | Action DWORD and live host completion DWORD |
| LAMP01 SupportCheck / initialization | Output/input size DWORD and offset DWORD |
| LAMP04 SendMessage | Live stop byte at 0 and phase DWORD at 4 |
| ABG02 CheckLoadSpecInfo | Live host stop DWORD |

The algorithms preserve gateway DTC record stride/masks, ordered routine IDs,
200 ms polls and the 180 second GWY timeout, LAMP support snapshot offset tables,
the TY12 versus TY18 delay difference, the assembly-restored LAMP positive response branch in all three sources,
STRACT support-mask copies and host handshake, ABG preparation delays, exact
business error values, and successful retained communication ownership.
Successful start operations deliberately leave the manager available to the
following result/finalization operation. Original callbacks do not add a UI
layer; their mutable host structures are the UI handshake.

Each original request is sent through concrete `TYComm` primitives. Communication
initialization, session/keepalive, exchange, support snapshots and finalization
remain owned by the shared selected controller. The module never loads a vendor
DLL, opens an adapter, contacts a service or substitutes successful callbacks.
Literal sleeps use `context.native_sleep`. Host cancellation is checked around
calls and waits and releases manager ownership; safe Python cancellation replaces
the native unsafe forced-thread termination boundary. Buffer span checks are
host safety policy, not invented native business return codes. LAMP zero-fill
size plus three and its indexed write must fit the native 4128-byte allocation.
Primary host/cancellation exceptions keep their identity if cleanup also fails;
manager finalization is attempted once per body invocation.

Run the authored branch vectors with:

```sh
python -m unittest discover -s tests -p test_utility_ex_ty_retained_12.py -v
```

The 26 tests exercise all 46 exact pairs, wire bytes, output identity, malformed
structures, source identity, unsupported modes, source deltas, native failures,
live host mutation, cancellation and retained lifetimes. Unit vectors replace
only image authentication with an explicitly authored fixture identity; the
private replay instead authenticates the real supplied image bytes and enters
both the actual selected TY consumer and the public engine invoke/thread/status
path. Both use authored communication
primitives, so these checks do not establish actual transport equivalence.

Private evidence under `analysis/evidence/no-car-131` records wrapper/callback
C/ASM hashes, original PE instruction-byte equality, per-mode Plus GWY callbacks,
and actual selected97/public83 replay of all 46 authenticated pairs. The TY18 STRACT01
ModeTransition decompiler string is resolved by the literal wrapper PUSH of
`100a3240`; recovered assembly is authoritative for that callback. Original
modules and recovered source remain private.

G2 and G3 remain open until the real shared lower controller composition and
independent exact-source branch review pass. Physical behavior remains
`PHYSICAL_UNCONFIRMED`.
