# Imported programming replay

`scripts.programming_replay` binds a parsed CUW, explicitly selected parameter
files, actual module bytes and a captured chronological driver recording to the
recovered Python programming algorithms. It never executes a DLL or opens a
vehicle interface. Results remain `PHYSICAL_UNCONFIRMED`.

The bytes API is:

```python
session = load_programming_replay(
    cuw_bytes, context_bytes,
    catalog_sources={"parameters.ini": parameter_bytes},
    module_files={"OriginalModule.dll": module_bytes},
    attachments={"authorized-key.bin": authorized_key_bytes},
    cancelled=lambda: False,
)
result = session.run()
```

All mapping keys are aliases, not paths. JSON cannot select or open another
file. `load_programming_files` reads only explicitly supplied regular files and
returns `(session, input_paths)`. Retain those paths for
`session.export_result(destination, input_paths=input_paths)`: atomic export
rejects source paths, symlinks and hard-link aliases of every selected input.

A session executes its captured operation and node once. A failed or uncertain
operation cannot be resumed by calling it again. Recovery is a distinct captured
native operation; it never implies permission to repeat a write.

The source-bound native VBF ProcessBefore path can construct a fresh raw
`prepare` root only from its issued, prepared request. That root copies the
authenticated current FILE digest, node, CPU index and received identifiers,
while retaining the same catalog, module bytes, attachments and chronological
trace. Its nested observations are independent, and it carries no prior stage,
selection or CONTROL target. The actual child still creates its held CONTROL
context during admission. Constructing the root does not start or execute it and
does not claim successful programming; physical behavior remains
`PHYSICAL_UNCONFIRMED`.

## Source identity

For `source="recorded_unverified"`, each supplied operation module must match the
shared registry by its exact SHA-256 and canonical name. The verified source
build selects the algorithm. Actual PE exports and version resources are read
statically. A filename, parameter-file declaration or PE version string cannot
assert a source build. Unsupported source versions fail before driver events.

The explicit `authored_synthetic` example accepts only the deterministic example
CUW and exact authored `SyntheticProgramming.dll` bytes. That minimal PE contains
no executable section or entrypoint. Its identity is reported as
`authored_fixture`; it is never represented as an original vendor module.
Modified recordings may exercise faults while those input identities remain
fixed.

## Recording

The schema is `techstream-programming-replay-v1`. Required top-level fields are
`schema`, `source`, `calibration_sha256`, `operation`, `node`, `observations` and
`events`. Operations are `get_cid`, `prepare`, `write` and `recovery`; nodes are
1 through 9. Unknown top-level fields and duplicate JSON keys are rejected.

Observations contain `current_cids`, `tester_info_hex` (32 bytes), `system_time`
(eight Windows SYSTEMTIME integers), `timeout_seconds`, `cid_mode` (1 or 2), and
`host`. Current calibration identifiers are mandatory for writing. Native block
geometry, nonce, archive data, CPU type, addresses and parameter rows come from
the imported file and catalog. Family-specific host observations represent
actual runtime state or explicit authorization attachments; they do not replace
native geometry.

Each event has exactly `kind`, `request`, `result` and `elapsed_ms`:

```json
{
  "kind": "exchange",
  "request": {"ecu": "0700", "payload_hex": "22f181"},
  "result": {"type": "bytes", "value": "62f1810143494400000000000000000000000000"},
  "elapsed_ms": 3
}
```

`exchange` sends one diagnostic request; `receive` has an empty request payload
and only receives. `raw_write` returns the accepted message count, while
`raw_read` receives one filtered native CAN payload. `action` captures individual
host controls, including connection, filter, timeout, periodic-message and wait
operations. `security` references an explicitly supplied attachment. Every
request must match the next event exactly; events cannot be searched, reordered,
reused or silently discarded. A successful run requires complete consumption.

Results use explicit `none`, `bool`, unsigned `int`, hex `bytes`, bounded `text`,
`mapping`, `sequence`, `attachment`, or `error` types. Mapping and sequence
children carry their own type tags, so nested native message bytes remain
unambiguous. Errors carry a native/vendor/M16C/host domain and numeric code;
recovery native errors may additionally carry their captured numeric `detail`.
Successful waits must account for their full elapsed duration. Elapsed callback
time contributes to the shared deadline. Native pending responses use separate
receive events and do not resend a destructive request. Cleanup remains recorded
and runs through the same driver boundary after cancellation or failure.

Authorization bytes and native histories are excluded from session reprs and
reports. Reports contain selected source hashes, operation state, bounded
calibration identifiers and event counts. Provider errors are reduced to their
type; supplied messages and buffers are not exported.

## Authored example

```python
from scripts.programming_replay import (
    create_programming_examples, load_programming_replay,
)

files = create_programming_examples()
session = load_programming_replay(
    files["authored.cuw"], files["authored-programming.json"],
    {"DEMOP5DEMO.ini": files["DEMOP5DEMO.ini"]},
    {"SyntheticProgramming.dll": files["SyntheticProgramming.dll"]},
)
assert session.run()["state"] == "writer_completed"
```

This production fixture generator imports no test helpers. Its actual native CUW
metadata resolves the same ReproStd block builder and writer used for imported
recordings. The 37-event recording includes filter, fingerprint, erase,
download, native per-call P5 timeout controls and restoration, verification, reset and finish controls.

`inspect_recording(raw)` validates recording structure without other inputs. Its
report explicitly sets `source_identity_validated=False`; it neither authenticates
a module nor claims an executable or physically validated workflow.

`probe` captures the recovered legacy `IsFinishReprogramming` export. Its module
is selected through the imported write catalog, and its CPU0 physical address is
bound by the native finish-probe adapter. `finished` records the native probe
boolean; it does not authorize resuming an uncertain write. Raw driver events and
filter acquisition/cleanup remain chronological records.

`bind_engine2026(engine)` accepts the concrete source-bound `CUWEngine2026` before
execution. It checks the actual selected2026 identity, calibration digest, node
and CPU index, and retains the engine-owned DH state privately. JSON observations
cannot supply completed progress or replace that engine state. Family execution
still requires its actual2026 catalog/address binder and recovered runner.

Concrete2026 controller composition uses `bind_runtime2026(runtime)`,
`bind_controller2026(controller)` and `run_bound2026(runtime)`. Each export keeps
one actual trace/action/clock/cancellation binding, preserves runtime resource
ownership, and returns its native output without finalizing the whole timeline.
`next_session2026(operation,node=...,cpu_index=...)` constructs another concrete
source selection for that controller; global chronology is finalized by the
outer controller. Exact engine-owned CPUType changes feed parameter selection
through validated metadata state. Unknown native export Booleans remain unknown;
a result-state label cannot manufacture `native_return`.

The controller's private CONTROL path can clone a stage only from an active,
source-issued `NativeControlExportTarget2026`. Its export name determines the
host operation; the recording has no stage override. Dispatch must consume the
common layer's immutable receipt for that exact target/export, including its
checked module, selectors, parameter-row provenance and loader preflight. This
path retains the same engine, controller, runtime and chronological trace, and
does not preselect a later row before the native helper asks for it.
For primary prepare/write helpers, the staged runner records a returned Boolean
only when the concrete family result exposes explicit `native_return` (or,
when that key is absent, explicit Boolean `native_result.returned`). The active
helper lease retains that source-derived value for typed callback unwinding.
State labels, `native_success`, and getter identifier vectors never stand in for
the helper's returned byte; retry/probe/IG-cycle exports do not replace it.
For a CONTROL CID getter, each actual `StartGetCID` return records its distinct
source-authenticated process out-byte through the common module/field whitelist
before runtime validation or teardown. The getter's identifier vector remains
separate; both the primary and alternate getter can update the helper's retained
out-byte, while only the primary getter's C++ return supplies the CID vector.
For the recovered SBR flash writer, CONTROL progress requests are emitted at the native callback sites: `notify_progress_count` observes the old count before its store, and `notify_progress_percent` observes the updated percentage. The replay adapter does not synthesize these requests from generic writer notifications. Source-captured requests are frozen into a chronological trace and replayed by a fresh ordinary strict `ProgrammingTrace`.

Captured2026 exceptions use `cpass2026` for the signed native error enum, or
`j2534_2026` with `code` for that enum and mandatory `detail` for the separate
signed driver status. Reports retain bounded native codes and sanitized cleanup
phase/domain/code records while excluding provider messages and response buffers.
Native progress request values may contain bounded finite JSON floating numbers.

Vendor getter results preserve a bounded, sanitized `native_results` entry per
address. Auxiliary assembly validity and native error codes remain associated
with that address; raw histories and provider exception messages are excluded.
Variable-address getters retain independent transmit and receive extension bytes.
Families whose native code copies two-byte addresses discard the catalog extension
according to their recovered profile. Unused image archives are not materialized
by getter or preparation exports.

An action request may record a byte value as
`{"type":"bytes_sha256","length":N,"sha256":"lowercase SHA256"}`.
Replay compares the length and digest of the actual bytes emitted by the native
algorithm. This descriptor supplies no payload and cannot replace calibration
bytes or a native metadata field. Chronology and result validation still apply.

`load_programming_recording_stream` reads the same JSON schema from an explicitly
selected binary stream. It validates the entire recording before execution and
spools events into an anonymous temporary file, with bounded values, input size,
disk use and event count. The caller retains its input stream. `trace.close()`
releases the event spool after the owning controller finalizes the timeline.
`load_programming_files` uses this importer for explicitly selected regular files.

The calibration input may also be the exact parser-issued
`NativeLargeContainer2026` from `native_large_cuw_2026`; its backing is validated
before import and only exact2026 modules are accepted. The actual engine can own
that same backing through `load_native_large`, retaining native metadata and
archive associations without a full-file byte copy. A selected large source and
a streamed recording remain subject to normal source identity and chronology
checks. Capacity/preflight evidence alone does not establish a completed transfer.

`observations.host.native_max_calls` is an explicit bounded host resource policy
(1 through 16,777,216; default 65,536). It does not select transfer geometry or
replace the capacity actually negotiated by the ECU. A previously bound runtime
keeps its caller-selected cap. Native pending timers read captured
`get_local_seconds_of_day` actions, rather than the replay machine's wall clock.
Tuple-valued primitives use the explicit `tuple` result tag; the existing
`sequence` tag retains list semantics.

A shared2026 runtime must use both captured native clock callbacks:
`local_seconds_of_day=trace.native_local_seconds_of_day` and
`local_milliseconds_of_day=trace.native_local_milliseconds_of_day`.
The latter consumes `get_local_milliseconds_of_day` with an unsigned value below
86,400,000. These clocks are separate from host cancellation and deadlines.

Native getter output flags (`native_success`) remain distinct from direct export
Booleans (`native_return`). A pointer-returning getter does not acquire a Boolean
return merely because its identifier vector is nonempty. Source-suppressed native
cleanup failures can preserve a native Boolean while the host reports incomplete
cleanup; `host_succeeded` and `host_result` retain that distinction.

Actual2026 SIL password, reset and preparation state come from the active
engine-issued transfer state before the family context is bound. JSON cannot
supply `use_new_password`, `reset_requested`, `prepare_status` or
`received_cid_count`. The SIL DCM version helper's legacy `received_cid_count`
argument represents the first native progress/status slot at context `+0x74c`;
it is not the number of identifiers returned by a previous getter.

`next_alternate_getter2026()` constructs only the alternate getter issued by the
actual selected parameter row, preserving the engine target and shared timeline.
The concrete controller's `receive_cids` owns the empty-vector fallback and final
identifier commit. A native Boolean does not replace the returned vector. Native
single-slot alternate filename/version bounds and literal version matching remain
part of the source binding.

The selected `CalculationHmacAPI.dll` dependency is authenticated by its exact
original identity and the static source-issued HMAC binding. That original has
no FileVersion resource; its reported version remains `None`. Unified SMC
security computes the recovered HMAC internally through the concrete library
lifecycle. A recording cannot supply a successful opaque key calculation.

The actual2026 `change_gateway` operation selects the native phase3 parameter
fields and requires the literal `ChangeToReprogGatewayMode` export. It has its
own source selection; ordinary preparation and finish probing do not substitute
for it. Family and controller phase support remain required by their binders.
The Ethernet writer obtains retained RKS SoftwareID from the same loaded engine;
JSON identities and per-write RKS attachments cannot replace it.

Online replay uses explicitly selected attachments:

```json
{"online2026": {"configuration": "encoded-rks.ini", "recording": "online-capture.json"}}
```

This object belongs to `observations.host`; values name supplied attachment
aliases. The recording is the strict `OnlineReplay2026` primitive transcript,
not a key or a success flag. Its engine, calibration, configuration and seed
hashes are checked by the concrete online controller. The factory retains the
same engine worker, runtime and shared trace; an unbound worker requires the
explicitly selected original `TCUWControlCommPhase.dll`. Nested capture elapsed
time advances the outer trace exactly once, including failure and cleanup.
A shared trace never reconstructs a consumed transcript from the same bytes.
A prebound online capability must own the same engine and runtime and use the
trace's `absorb_online_elapsed` clock boundary.

Alternate getter selection retains the authenticated primary parameter row
captured before invoking the getter. A native CPUType change updates live
calibration metadata without silently selecting a different alternate row.
The projected binding retains separate original-row and live-metadata provenance.

The retained body writer candidate routes require source-issued worker target
index, password state and initial-command flag. JSON cannot provide these fields.
Preparation's native retry flag likewise comes from the engine. Exposing these
source-gated routes for actual composition checks does not promote the separate
implementation/review registry to complete.

The optional `host.driver_recording: "j2534_2026"` selects the recovered typed
J2534 host state machine over captured low-level provider calls. The normal
factory requires the selected original `TCUWJ2534DeviceIF.dll` identity. Every
provider result must explicitly contain `status` and `value`; missing fields do
not imply native success. Captures can encode bounded `PASSTHRU_MSG_2026` and
`READ_BATCH_2026` records with their exact native fields. The retained device,
runtime, trace provider, cancellation and virtual clock must share object
ownership. Cleanup uses the same captured chronology after host cancellation.
This mode opens no native library, adapter, socket or vehicle.

`next_retry2026()` constructs the distinct `PrepareRetry` export from the
executed writer session's retained DLL and authenticated parameter row. It
projects current engine metadata onto that loaded row without selecting a new
catalog key. It does not authorize a retry or implement the controller's retry
query/event loop; those native source conditions must be satisfied by the
controller before invoking it.

The `change_gateway` operation also supports the recovered CUW12/CUW18 Body
export. It selects the catalog's gateway stage and invokes `gateway_only=True`.
An ordinary preparation cannot request gateway parameters through a host stage
flag. The original-module importer proof uses an explicit captured six-byte
authorization attachment; it establishes gateway dispatch and chronology, not
key derivation or a complete controller execution.

Recorded native transport issues a `J2534InterfacePair2026`: `trace.device` is
the controller view and `trace.engine_device` is the distinct engine view. Both
retain the same provider, clock and cancellation capability objects. The
factory binds this pair before worker issuance; role selection is not a JSON
option. The source controller owns native export/import transfers between
views. `native_device_action2026` preserves the SIL translation and cleanup
rules for the already authenticated view selected by the runtime.

When all three exact selected sources `Parameter.ini`, `CanIDTable.ini` and
`LogicalAddressTable.ini` exist, engine binding validates and attaches the
native frontend bundle before issuing a worker. Existing retained frontend
sources must match exactly. The two independent address tables retain their
native keys and are not parsed as family-selection tables. An incomplete set
does not manufacture a frontend bundle or a calibration type.

For `host.online2026`, engine binding preloads the selected configuration into
that engine's shared native RKS store before entering a worker phase. An
attachment whose digest matches the store's last attempted source is not
imported again by the online controller. Valid subsequent imports preserve
the native first SoftwareID/SoftwareVersion and update the other fields;
native parse failure preserves the existing configuration. Online request
construction consumes that retained engine store.

`next_finish2026()` retains the executed writer's loaded row for the distinct
`probe` operation. Construction alone does not establish that a DLL exports or
implements `IsFinishReprogramming`; native export guards and the family runner
remain mandatory. `next_ig_cycle_process2026(selected)` keeps an authenticated
prepare or write binding and its communication phase, selecting only the
actual DLL's `ProcessBeforeIGOffOnAtRetry` export. Neither helper reselects a
FlashWrite row or authorizes the surrounding controller condition.

`executed_binding2026(engine=..., controller=...)` exposes the immutable
selection captured at actual export entry. It rejects another engine object,
another controller, or a different runtime before any provider action, even
when source bytes match. It does not perform a fresh catalog lookup.

The private failed-Sonar fixture records 62 low-level SDK events and replays a
fresh canonical trace through actual CID reception/completion, prepare and a
writer failure (driver status24, CUW code7). Its Sonar DLL exports only
`StartFlashWrite`; this fixture does not establish a native `PrepareRetry`
execution or full retry-loop completion.

The classic DH raw-controller fixture now exercises a failed `4c10` writer,
the real retry query/input path, and retained `PrepareRetry` in one Execute.
Decision `1` runs the original DH flash writer and prepare writer; its fresh
ordinary strict trace consumes all 97 SDK events, with the failed writer
returning `False` and `PrepareRetry` returning `True`. The fixture first
authors primitive responses from its bounded offline SDK provider, then
replays the frozen rows from cursor zero; it is not a vehicle recording or a
full phase-1 lifecycle proof. Caller-supplied DH `export` overrides remain
rejected by the native DH binder.

`alternate_parent2026()` exposes only the exact executed primary getter retained
by `next_alternate_getter2026`. Engine continuation may use this sealed lineage
to retain working getter context across an empty-primary/alternate sequence.
It cannot be supplied through replay JSON or reused after another operation.
`catalog_sources2026` returns an immutable snapshot of raw authenticated catalog
bytes for source-bound controller selection.

The bound MMC prepare callback reads `engine.native_prepare_handshake` directly.
An authored `preparation_state` provider result cannot replace the engine's
actual callback-slot18 state.

Before the native raw helper begins, `_bind_control_prelude2026` can retain the
exact held CONTROL source, runtime and trace owners without selecting a module or
issuing a raw token. This prelude bind grants no stage or export authority. The
focused SBR integration test exercises one real `execute()` across prepare,
an empty gateway phase and flash write with the actual recovered family bodies
and one shared authored primitive recording; it asserts both source-returned
Booleans and complete trace consumption. This remains a software replay, not a
physical vehicle validation.
CONTROL stage clones derive `current_cids` from the source-issued target's
immutable identifier tuple, retaining order and duplicates; root observation JSON
cannot override those imported identifiers. Before any raw token exists, the
prelude bind verifies a supplied `Parameter.ini` against validated parser General
state and compares supplied canonical frontend files against the engine-owned
bundle when those same sources are present. It never binds frontend parameters
late while the worker is active.
