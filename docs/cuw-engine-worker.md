# CUW2026 engine worker

`EngineWorker2026` is the source-bound owner of the native state between
`CUWEngine2026` and `ControlCommPhase2026`. Applications obtain it only through
`engine.bind_worker(controller)`. Direct construction, a second controller
lease, a changed runtime, or a source outside the issued FILE set fails before
a native primitive runs.

The worker owns the current FILE/node/CPU positions, ordered target vector,
progress fields, the effective CPU type retained by `36800`, the `be8`
handshake, callback bytes, phase timing, battery observation, continuation
state and controller copy-in fields. Read-only frozen views expose these values;
callers cannot replace them with flags or snapshot dictionaries.

After a joined native child, worker reissue is transactional. The replacement
retains only CUW-engine fields passed by pointer to `59070`, including the live
FILE projection, selection vectors, positions and timing. True `59070` locals
such as `be8`, local fatal/failed and the `c48/c4c` vector reset. Dependent
owner rebind can finalize the swap or roll it back to the still-valid previous
lease without publishing a half-replaced worker.

## CID and CPU selection

The constructor leaves every target slot at `-1`. A committed CID vector is not
enough to select a writer target. The owned `mark_cid_reception_complete()`
entry runs only `34e10`: it retains the authored target indices, unmatched CIDs,
bounded companion records and original CPU count without rebuilding metadata or
changing `D308/D30C`.
The later `36800` prepare entry applies `3ddf0 -> 3e710`. That stage applies the
exact M16C/FOREST order, evaluates `PasswordAddress` and full-DWORD `ByteOrder`
before an unmatched FOREST append, and installs the rebuilt CPU/logical backing.

The method returns the native CheckTarget Boolean. An all-unmatched set returns
false and preserves the original metadata and unresolved target vector. A true
result retains the raw match until prepare. `36800` skips the rebuild entirely
when effective CPU zero's image contains the case-sensitive `.vbf` marker or
its indexed-image vector is nonempty; those paths do not evaluate M16C/FOREST or
password General parameters. A rebuilding path preserves a nonzero native
`D308`; only zero is replaced by the issued `D30C` offset. Writer and USB access
reject unresolved slots. Blank-ECU, nonzero Configure-bit and other target-map
producer branches whose inputs are not modeled fail closed.

Cold `D30C` and the progress base start at zero. Loaded
`OffsetOfWriteCpuMultiCalIndex` is ED58, read into the progress base D9D4 at
the actual recovery `36800` point after the primary notification callback.
It never initializes D30C. A real FOREST move in `3ddf0` produces D30C;
worker reissue preserves that reached value. D304 rebuild completion is a
separate native Boolean, preserved on reissue and pointer projection and
cleared only by its actual reset/file/retry source producers.

Modern CUW formats can leave the effective native `CPUType` empty. `36800`
retains only the effective first native CPU field; it never substitutes a raw
INI alias. The VBF handshake uses the source's case-sensitive substring test.
If a later prepare entry sees nonrecovery `be8 == 1`,
`prepare_reentry_handshake()` changes it to three and reports that the entry was
consumed. The thread owner returns without reserving a phase or dispatching a
second export.

## VBF prepare resume

The external VBF prepare receipt path acknowledges the native `be8` decision:
actual `1` is changed to `2` and requires the child wait; a non-`1` value is
preserved and is admitted only when the persistent child is already parked.
Recovery-mode VBF resume is outside this bounded path and is rejected before
the prefix. The exact lexical prepare owner then runs the shared `36800` output
prefix and reads local time once. Resume skips only the VBF-specific `3e710`
rebuild; it still applies the common D308/D30C selection tail. It restores
`be8` to `1` and records the prepared timestamp in the same receipt. When the
actual adopting child starts phase1, it imports that timestamp and enters
`running` without repeating the prefix, local-time read, or handshake write.
Calls without a receipt retain the existing phase-start and `1 -> 3` behavior.

An authenticated actual `141` FILE reset replaces the current FILE and CPU
mapping while preserving the worker's prefix offset. The offset is native
D30C state, distinct from current CPU D308 and the authored CPU count.

These host-thread transitions do not establish successful programming or
physical vehicle support; native and hardware outcomes retain their existing
source-bound evidence requirements.

## Continuations

`notify_next_cpu()` implements the `581a0` outer barrier. It verifies that both
current and following CPUs have source-selected targets before changing state,
applies the selection synchronously while the engine phase is owned, persists
an allowed FILE transition, queues one immutable continuation, and returns.
The outer controller consumes it after the previous export unwinds. It never
recursively enters `run_bound_phase()`.

P6 callback1 uses `notify_logical_cpu_boundary()`: a same-FILE, same-node CPU
change while the same writer export continues. A bound persistent thread job
hands both callback forms from the child to the actual outer phase owner. The
worker brackets each owned transition with the `3c410` continuation backup and
`3c5b0` clear. `65a40` uses the backup CPU/base/offset/cycle while active and
keeps the current percentage lookup.

The remaining `3f620` terminal, periodic-message, next-FILE and notification
branches are not represented by the logical-boundary helper.

## Held CONTROL FILE capture

At the engine's once-only `59ab0` identifier import, the active worker can issue
one `ControlFileCapture2026`. It freezes the exact imported metadata projection,
ordered CPU mapping, target vector and scalar `control_cpu_start` from the same
boundary. `metadata_for_cpu(index)` accepts only an unsigned ordered index and
maps through that held projection; it never consults a later selected FILE.

The capture remains valid through legitimate FILE/CPU changes in the owning
phase, then the worker invalidates it during phase finish or failure. Copied,
forged, foreign-thread and expired captures fail validation. The engine import
hook must set `_identifier_context_importing` only around the real identifier
copy and call `worker.capture_control_file2026(controller)` there; calling the
worker API elsewhere is rejected. This capture preserves FILE ownership and
does not provide a cursor setter or extend authority after unwind.

The capture also freezes the source-set identity and issued pointer/flow views,
the independent native flow index, exact configuration, the engine's current
34-record query seed, configured CPU bits, and the engine+39c sequence bit. A
standalone phase has no thread lease/session/completion identities; an actual
thread phase carries its concrete current job lineage. Captured source views
are validated against their captured source set, not a later pointer or flow
selection. At issuance, the pointer-view fallback must match the actual
metadata's source container identity and digest; a mismatched admission view
is rejected.

## Engine-global native getter lifetime

The worker carries native D71C (`_flow_file_index2026`) independently from its
current FILE projection, engine+39c, all 16 engine+A34 history records, and
the live M/32M getter vectors and bitsets. Cold worker construction starts
D71C at zero and creates 16 genuinely empty history records. Live vectors use
the configured `cpu_maximum` and its 32-cell capacity; configured bits start
from the actual configuration. The authenticated 40580 cleanup path rebuilds
the history records with exact M/32M shapes and clears the live getter arrays.
Creating or closing a worker does not simulate that native reset.

The accepted initial 34050/40580 path may project its exact cold reset once,
while the engine-issued worker is still unpublished. The consumer requires the
engine's lexical first-bind origin and the current issued worker/controller
pair; it records that origin's monotonic reset epoch. Its shared literal reset
factor is limited to the sixteen A34 records and 43ab0 live auxiliary arrays.
It leaves configured 4e0 masks and file 4f0 masks, D71C, +39c, FILE state,
selection state, and cleanup resources to their own source producers. The
history and auxiliary vector sizes use the historical M captured at the cold
bind, including M=0; a later Configure does not upgrade them. A typed getter
import still checks every live auxiliary vector against the current
configuration before mutation, while unsupported untyped imports retain their
legacy path. The ordinary cleanup reset uses the same factor only after its
authenticated cleanup trace reaches `global-prefix-reset`, `device-clear`, and
`vectors-reset`.

The worker also retains the mutable engine-global 4f0 mask projection as
sixteen per-FILE boolean vectors. A real Configure seeds it from
`source_cpu_flags`; worker reissue copies its current values, while authenticated
40580 cleanup clears it at the then-current M. The literal private 34cb0
consumer validates source capacities before its first write, clears published
errors, switches the concrete J2534 engine view only when the current contact
requires it, then delegates CID/query/phase/prompt writes to the engine owner.
It resets live 4e0 and copies the actual D71C 4f0 slot only when source 39c is
set. It does not reset A34 histories, D71C, or 39c.

The programming-log receiving result comes from the engine's canonical native
CFE2/prompt status projection; worker activity and phase are not substitutes
for those source fields.

`_replace_engine_worker` transfers these engine-global values before retiring
the previous worker. Mutable arrays are copied, immutable history records are
preserved, and child-local capture/return capabilities remain retired. A
manual `close()` revokes the binding; binding a fresh worker while the engine
still owns that old carrier is rejected. The real mode2 FILE reset obtains its
flow from the old table's source group start, with the source-proven direct
zero-map branch resetting flow to zero. The replacement pointer is not used as
a flow substitute.

Persistent getter observation and continuation dataclasses describe immutable
values only. This worker stage does not issue observations or continuations;
those require the later source-authenticated getter pipeline.

## Ordinary getter return import

The real 4be0 snapshot registration advances the worker's monotonic ordinary
return sequence only after the current pair and snapshot identities validate.
The 5a050 import validates the exact registered snapshot and COMMON getter
output, then checks the complete M/32M raw shape before importing the pair or
changing getter scratch. Unsupported typed families still import their actual
raw identifier vector and J2534 snapshot, with no typed output exposed.

Typed CanCID buffers convert within their fixed source widths. The raw cell
type byte is MOVSX-expanded to 32 bits; CPU state protected by the previous
retention mask remains in place; tails always import; and the configured mask
updates only in source mode1. The read-only imported-output accessor is bound
to the exact still-active old context. Worker state keeps only a weak
reference to the output, which is retired when that context unwinds. Persistent
observations, 3d120 history merges and 34cb0/32ff0 source transitions remain
later-stage producers.

The focused worker regression replays source-bound CanCID outputs with issued
paired J2534 traces, exercises the ordinary-return receipt, and imports typed
outputs once on both true and false raw-al results. The false case comes from
an actual recorded J2534 filter-start status16 and still imports the typed
empty identifier vector; it does not enter the later history merge. The
companion unsupported-family false-result test keeps legacy raw identifier/
J2534 import untyped and rejects reuse or access after unwind.

## CONTROL output buffers

The worker creates count scratch once from the engine's native output length
with zero values, and percentage scratch once as a copy of the engine's current
percentage vector. Repeated `59ab0` imports retain these buffers. A new worker
starts fresh from the then-current engine outputs. Context observation returns
immutable tuples; target-bound DWORD stores update scratch only.

`publish_control_count2026(context)` copies the whole count vector. Percentage
publication first snapshots the old whole engine percentage vector into the
existing `_cpu_percentages` C48/C4C observation vector, then copies the whole
scratch vector. Both methods
validate the active source-issued context and fixed vector lengths. They do not
publish implicitly during import or phase cleanup.

The worker also exposes narrowly scoped source hooks for SBR byte publication,
the shared DH gateway type, and the ordinary raw return snapshot. Its SBR hook
requires the retained internal parent `Vendor2026Context`, the exact selected
CONTROL binding, and its active runtime export scope; a standalone SBR utility
has no engine publication authority. The internal `prepare_sbr` path issues this
context, and `read_ssm` publishes its actual byte immediately after storing it.
The ordinary snapshot is accepted only after the common raw-tail registry issues
the exact pair snapshot; getter-only
import occurs at the outer getter handoff and is marked consumed after the pair
import and identifier commit succeed. Post-export 28/2f cache reads require the
authenticated 8990 primary-return receipt and read the worker's C25/C08 values.
The C08 setter accepts a DH `PrepareRetry` write only while the exact
`PrepareRetry` export and its 4c10/5c30 helper lease are active; ordinary write
exports and alternate export names do not grant that publication authority.

The private `_record_control_helper_cpass2026` path accepts only the native CPass
error domain while a common-owned family-helper entry lease is active. It writes
the exception code into the native primary-error field, preserves the existing
error kind and J2534 status, sets native fatal state, and leaves write-failure
state unchanged. The outer loader-prelude catch remains a separate transition.

## Control and retry state

Host faults and cancellation change lifecycle state only; they do not create
native `fatal`, `failed` or completion values. Controller local fatal, copied
`D34B`, controller `+80`, and engine `CFD0` are separate. The exact `5b1b0`
tail publishes `+80` to `CFD0`, then callback9 publishes local fatal to `D34B`.
The protected `5a813` loader-prelude catch accepts only the native CPass
hierarchy, copies the exception DWORD at `+0xc` into controller `+60`, and then
sets `+80`. The preceding `5a790` entry clears `+68/+70` only when `bd0` is
zero. Neither transition is inferred from a general execute fault.

`copy_control_retry_decision()` implements the pure callback8 copy from engine
`399` to local `75c`. `import_control_error_query_decision()` adds only the
`4780` conditional branch. Captured `5e950` input clears the worker `c48/c4c`
percentage-vector length before history/event publication. Static xref audit
found constructor, destructor, read and clear sites but no authenticated 2026
producer that grows this vector, so the issued port keeps it source-empty and
provides no caller setter.

The successful `3b90` recovery probe preserves source order: clear local
`75c`, publish callback7 to engine `399`, then clear notification fields
`968/96c`. It does not clear error fields or context `964`.

The mapped JSON delta `4b900` transition is joined atomically with the engine,
FILE-source and cleanup owners. The delta-active flag is sticky native engine
state; clone matching compares the live selected source to the retained A48
source rather than an admission-time role. Plain and mapped retry branches are
implemented. `34e10` retains a typed per-FILE raw match and the separate A48
selection cache. The native `47e60` tail copies target indices, unmatched CID
and companion vectors, and authored CPU count; it does not rebuild FILE metadata
or choose D308. The later `36800` performs any source-gated rebuild. A named
WHOLE cannot acquire this A48 selection through a legacy direct completion call
that lacks its actual indexed producer. The owned negative check covers that
rejection; the full G7/H-A48 restore positive remains open. No snapshot dictionary
or hash-only FILE alias participates in that transition. The logical `3ffa0` branch validates the actual `19710` predicate,
clears vector `368`, remaps `358` to the selected node's first logical block,
and, only when captured `EB48` is nonzero, applies the source `05/01`
ReproMethod mutation and nonzero flash-size result.

`native_context_970` comes from the family-produced `flashing_ended` field.
It is distinct from the worker's IG-cycle input and the engine's published
`D348` cycle output.

Callback24 retains the raw gateway byte in `DAT8ed0c`. Callback25 later copies
that cached byte into `typData990/BF9`; it does not rerun classification or
convert the byte to a Boolean. New-password use remains exactly BF9 equal to
one.

## Gateway, device and logging

`run_gateway_startup()` is the `5a835` phase-1 gate. It reads the current FILE's
effective CPU0 type, General flag and alternate-CID state, then runs the issued
`1ad30/5b1e0` producer. Returned `AL`, output flag and classifier validity are
kept separate: only returned `AL` sets `be0/980`; a fresh classifier publishes
its byte, while a successful fallback may return without replacing BF9. An
`AL=0/output=false` result continues without retry state. An
`AL=0/output=true` result publishes the outer failed/error-kind branch after
the wrapper has copied only its typed local error fields. New-password use is
exactly BF9 equal to one.

Battery acquisition follows `33f80 -> 33e50`: check the device version, issue
`GET_CONFIG` for key 1 with value zero, read `READ_VBATT`, and divide the DWORD
by 1000. Typed native faults acknowledge `be8`; probe and voltage failures map
to literal native integers zero and one. Host exceptions retain identity. With
the persistent thread job bound, the acknowledgement request is completed by
the outer `41e60` barrier after the real child publishes its `+1c` parked state.
An external `5e950/5d830` probe uses the same issued job and waits outside the
worker lock, so the child can reach that parked checkpoint.

Program-log eligibility is evaluated before device access. Status uses engine
CFD0, copied native errors, active online-key handle/state, configured
authorization, exact recovery status and the continuation backup. The log uses
the engine-side J2534 view, runtime connecting state, last exchange,
persistence and the worker percentage vector.

`online_context()` exposes the engine VIN/region, current ECU kind and actual
native FILE-table metadata. Daihatsu detection follows `4a6f0`: P5-Unified
checks the first gateway diagnostic ID of each node for `0751`; other contacts
accept metadata format versions 10 or 12. `usb_recovery_context()` exposes the
selected target and imported CID/software-vector count used by DH USB recovery.

## Getter and flashability source work

The successful getter tail keeps the issued runtime projection object across
both named-next and named-terminal `32ff0` calls. Each pointer publication
prepares the worker FILE/CPU/target mirror before the engine publishes its
metadata and persistence proofs. Old CONTROL captures continue to hold their
original FILE; later captures use the new coherent pointer mirror.

The native judge keeps `5ffc0` caller Boolean, temporary row vector and actual
count separate. An early `3006` leaves those outputs as the caller supplied
them. A normal matcher return publishes its Boolean before row allocation;
row and label writes preserve their reached state if a later lookup fails.
The row allocation is bounded by selected received count plus authored CPU
count. Public rows use the actual count, then the four stable source passes.

Live matcher inputs, per-FILE `770/A28` vectors, merged `A34` history and the
pointer-keyed `AF4`/A48 caches have separate roles. A compacted table index does
not re-key an original AF4 cache. Every PART of one archive maps to the same
original archive-cache ordinal; it is neither the current FILE slot nor the
original member position. `46d60` refreshes only global A48 CIDs; `67680` stores
them once into that shared archive cache before its numeric FILE fanout.
Member matching writes its per-FILE target
and append-only unmatched/count records; it does not overwrite A48 selection.
The group tail runs `47e60` after completed WHOLE evaluation and successful
reset return, including a false WHOLE Boolean. It does not run after an
escaping reset fault or rebuild metadata as a substitute for copying targets.

Mode1 factories run once before reset writes and issue an unpublished exact
replacement. Direct reset publishes the native early zero flow before cache
clears. Mapped reset preserves numeric flow/CPU and compacts the source caches.
Both prepare the entire replacement pointer tuple before publication; the
worker publisher assigns only precomputed fields. Real `41940` General and
address-table `SetKeys` operations follow the pointer store. Mapped reset then
restores A48, performs the second `41940`, and reaches the authenticated
`23b10` persistence tail. The existing atomic disk replacement is host policy;
it does not reproduce native Delete-first file failure behavior.

This work is still under integration. The focused checks cover native
`41940` failure/key chronology, reused `3006` outputs and cross-pass row
deduplication. The actual threaded getter/judge/mode1/VBF consumer and reset
fault matrix remain required before acceptance. The C44 late wait restore is also under integration: a one-use origin binds
the actual requested slot to the current successful shared admission identity
and engine timing epoch, after41940 and CID/query restoration. Direct46be0
does not run this restore. Native `3fc/410/424` are wait timings, not DH error
outputs; a metadata view cannot create timing provenance.

The shared engine selector now supplies the actual selected General/address
parameter objects to H labels. G next and terminal use their existing common
origin at the postpointer source point; selection validation is read-only.
Their late wait point is created after the applicable CID/query copies and
consumed once on that same origin. Lexical cleanup retires only the identical
point, leaving the outer getter authority alive through its remaining tail.
No-table getter execution creates neither named selection nor wait points.

The complete ordinary `36800` prechild path is under integration with the
engine scope and thread-owned origin/receipt. Its source body runs before
record/lease reservation, retains native partial writes, and authenticates
each CPU store with its literal EC94, D30C or logical-image input. Recovery
password state uses the existing DH password field; gateway classification
does not supply that Boolean. The staged current-state `3ddf0`/`3e710`
iterator and actual child receipt delivery now have genuine consumer checks;
this does not establish every remaining ordinary source branch or the full G7
pipeline.

## Verification boundary

The no-car suite authenticates shipped PE modules and executes only the Python
port over authored CUW and replay data. It performs no OEM DLL execution,
network access, JVM work, vehicle I/O or physical device I/O. Physical
programming remains `PHYSICAL_UNCONFIRMED`.

The current-state `3e710` iterator publishes each reached FILE projection even
when its CPU rows are empty or shorter than the retained numeric D308. The
shared cursor helper returns an ordinary CPU view only while that row exists;
otherwise it retains the exact issued FILE view and the previous local
node/CPU cursor. It never clamps D308 or selects CPU0. The classic `19710`
contact branch returns false before looking up a CPU; modern CPU-dependent
faults remain at their reached source point. A lower-source zero/short-vector
check does not establish acceptance of the full ordinary prechild path.

Actual paired `job.start` checks now reach zero and short FILE projections before
the later `19710` CPU getter fails. Recovery inputs come from encoded, parsed
and imported RecoveryInfo with the same initial held CPU. They prove phase2,
unchanged EC94/D308, one source clock and coherent FILE/proof publication. A
logical-node case exercises the real first `19710` remap, metadata successor
proofs and the later D308 store replacing that proof; the retired origin cannot
make an old metadata proof current again.

A source-produced idle BE8=1 reaches the ordinary early1→3 return with no record,
lease or scheduling tail; active-child reentry remains a separate route. The
real captured child consumes its prepared receipt before initialization, with
one prefix clock; a second initializer call in that same child rejects before
any extra clock or receipt consumption. Its observer invokes the original
initializer and leaves CONTROL business execution unchanged.

The ordinary shared CPU store precomputes a matching immutable selection-cache
projection together with its loaded FILE view. Only a cache whose prior
metadata is the exact authenticated pre-store view follows that projection;
selection fields and actual clone aliases remain intact. The assignment-only
publisher commits these mirrors together. A real FOREST prepare regression and
the paired DH query/retry capture exercise this correction. The strict `47e60`
metadata identity check and pure typed-match ancestry guard remain unchanged.
Full vector-route G7, active-child early reentry and unexercised ordinary fault
boundaries remain separate gates.

A legacy adopted prepare without an authenticated CONTROL root and without
pending ordinary source bookkeeping retains its existing initializer path.
Missing prepared receipts reject for an authenticated raw ordinary root, or
while ordinary origin/binding slots remain pending. Those slots grant no
authority; they only forbid fallback to another standalone prefix. This also
covers a legitimate FOREST projection whose input CPU0 and current CPU1 make
the initial root predicate unsuitable for repeating after the source body.
The regression removes only the real pending receipt inside the actual child,
checks rejection before initialization, then restores and consumes that same
receipt.

The external VBF `36800` CPU successor completes inside the existing worker
RLock only after the real retained-selection caches and current node/local/global
CPU mirrors finish. Both the no-selection and retained-selection paths use the
engine lexical origin; the worker issues no authority and changes no persisted
CPU. A partial mirror fault cannot produce the completed successor.
