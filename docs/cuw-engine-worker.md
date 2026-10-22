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
cache. After a source-allowed prepare rebuild, the A48 cache holds the exact
engine-selected issued metadata view, including the native `D308/D30C` CPU.
`47e60` restores the authored target indices, unmatched CID and companion
vectors, and original CPU count; the following `36800` reapplies that exact
source-issued selection. No snapshot dictionary or hash-only FILE alias
participates in that transition. The logical `3ffa0` branch validates the actual `19710` predicate,
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

## Verification boundary

The no-car suite authenticates shipped PE modules and executes only the Python
port over authored CUW and replay data. It performs no OEM DLL execution,
network access, JVM work, vehicle I/O or physical device I/O. Physical
programming remains `PHYSICAL_UNCONFIRMED`.
