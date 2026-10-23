# CUW2026 native query and retry controller

`CUWEngine2026.bind_retry_controller()` issues one `RetryController2026` for the
engine's existing `EngineWorker2026` and `ControlCommPhase2026`. The module never
loads or executes a vendor DLL, opens hardware, or makes a network request.

Callback slot 3 dispatches the actual `3ffa0` controller. It keeps the modal bypass,
`344a0` current recovery-status calculation, `33f80` battery measurement, `3a0a0`
recovery bypass, `3a120` periodic-message stop and a real blocking query event.
The previous error kind is retained before the worker waits. Fields 398/399 read
the engine's canonical outputs. Query error counters use the configured CPU
vector; DB20 history and D33C counters share the cleanup controller's actual
backing cells, so accepting `5e950` input clears the same history later consumed by
whole-engine cleanup. Published queries
carry the source error kind, primary error, distinct PassThru error and current
file/ordered CPU selection. A query is an observation of an actual error path;
creating `RetryInput2026` does not manufacture a successful phase.

An external input pump observes `wait_for_query()` and calls the engine's public
`inform_result_of_query_retry(native_result, native_option)` with captured signed
32-bit and unsigned-byte arguments. Exactly native integer 1 selects retry;
integer 2, 0, negative and other values do not. Boolean values are rejected. The
byte remains independent and unmodified. No pending query returns 3005. Accepted
input clears the source copied error outputs and the actual CUW worker percentage
vector length, retaining its owner. It clears shared DB20 history, signals the waiting worker
and then observes native resume chronology. Callback 30 retains the actual `588d0`
raw byte; `3c720` consumes a nonzero checkpoint and records local milliseconds
within the day. Query publication, checkpoint and scope exit use the same lock
and event predicates so a wake cannot be lost. The source return branches are 0,
4005, 4012, 9999 and the concrete connection-check result; host errors retain their
exception identity instead of becoming a native retry decision. The input pump
checks its host deadline/cancellation boundary before mutating native query state.

The host replaces infinite native waits with the already-issued runtime deadline
and cancellation boundary. A monotonic host deadline also bounds waits when an
authored capture deliberately freezes its injected clock. Its short
`Event.wait` polling never calls an opaque
retry or stage-success provider. `worker_started`/`worker_stopped` are lifecycle
signals from the actual engine scope, not successful-completion flags.

The source `a44` output is an immutable notification record, independent of a
query decision. `load_notification_configuration()` decodes captured RCN.ini
bytes using the existing native nibble decoder. It retains separate Success and
Error records, signed `stol` numeric-prefix behavior, color low-byte packing,
blink cycle and byte strings. The original `4f3e0` default records are zero/empty.
Only error kinds 1/2/4/5 emit the error notification, and only 1/2 set the 398 flag.

The actual issued `GatewayStartup2026` producer joins its BE48 classification
and BE34 periodic identifier through `accept_gateway_startup()`, including partial
state before a later fault. Callers do not supply registration flags or IDs.
The query stops that actual periodic message through `StopPeriodicMsg`; its native
catch-all resumes the query while host capture failures retain their identity.
The query and concrete `5d830` connection check use the engine CFE8 view from the
actual issued `J2534InterfacePair2026`. The CONTROL view remains separate; snapshots
move only through the pair's source-issued ExportData/ImportData operations. The
connection check inspects the selected driver and all loaded
Phase6 node protocol fields. It preserves the 1.0 V low-battery boundary, the
native-only `48f80` catch, version/config probe, temporary disconnect/connect/
disconnect chronology and distinct 4003/4004/4005/4006/4012/4013 results.
The public connection check also works before the native59070 worker exists: it
uses the actual paired engine device budget and raw version/configuration/battery
primitives. The native41e60 acknowledgment is a no-op without that worker.

The `40070` battery
comparison uses `ConfigureCUWDLL`'s second double (`engine+540`), strictly greater,
with the same `33f80` primitive sequence as the worker.

Source ownership is split intentionally: engine leaf36 owns exported shared globals,
worker leaf114 owns ordered-file/CPU selection, battery exception acknowledgment and
resource lifecycle, common leaf31 owns `b3e0/3b90/4780` and callback consumers, and this
module owns the query event/input/controller state. A source59070 worker reissue
rebinds the same retry controller and preserves its global history, counters,
options and events. Worker-local `C24` survives ordinary phase scopes; source
`36800`, consumption by `3c720`, and a fresh `59070` constructor clear it.
Private source evidence stays
outside published fixtures. Authored literal tests run with:

```sh
python -m unittest discover -s tests -p test_cuw_retry.py -v
```

Authored composition checks also exercise the actual JSON/delta FILE loader,
selection of its actual issued FILE through the engine-owned metadata boundary,
captured option byte, post-wait whole-FILE reset and
retained CPU error counter. They cover mapped JSON groups and the direct SCUW
zero-map reset. Logical tests use two actual logical CPUs: option zero still
remaps to the first CPU; byte255 changes only the matching CPU to source method05
or01 and recalculates its nonzero flash size. The concrete `query_control_error()` check covers
paired reconnect, nonretry cleanup, a native reconnect fault followed by a new
query/input, and unchanged host-exception identity. These checks execute the
scoped `4780` helper; they do not substitute for the whole failed-family export.

The private `verify_failed_sonar_retry.py` and `verify_failed_dh_retry.py`
callers now use new fixtures under `runtime/no-car-119`; the older27 fixtures
remain untouched. A fresh raw phase2 `ControlCommPhase2026.execute` runs the
actual failed writer and its natural4c10→3b90 query/retry path in one live helper
context. An observer calls the original family runner and retains its concrete
report and actual issued row; it does not substitute a family result. The UI
thread supplies the real public `5e950` input after the actual query is published.

The Sonar source profile retains false `PrepareRetryFlag`; its SDK status24
produces native writer error7. The DH source profile retains true
`PrepareRetryFlag`, primary1/status24 and its authentic retained PrepareRetry
export. Input0 takes nonretry whole-engine cleanup; input1 takes the source
retry branch. DH requires one actual native PrepareRetry only for input1, while
Sonar requires none. Aggregate raw return and concrete failed/auxiliary reports
are separate. This is a bounded raw phase2 composition, not a complete phase1
prepare-to-write or vehicle lifecycle claim.

Capture records only authored SDK/clock responses; final runs use fresh ordinary
strict traces from position0 and require complete consumption. Original trace
bytes/hashes are preserved under `control-sol/retry119-before`. DH inputs0/1
consume18/97 events and invoke zero/one actual retained PrepareRetry exports.
Sonar inputs0/1 consume103/132 events and invoke no auxiliary export. The two
unchanged public retry methods pass all four decision cases. Additional actual
query input-pump OSError/InterruptedError checks retain original host exception
identity and leave native input history empty.

The migration exposed three source seams corrected by their owning leaves:
inactive pool detachment after real nonretry cleanup, removal of an internal
auxiliary routing key before strict DH binding, and authentic PrepareRetry
permission for the nested DH gateway-type setter. The latter requires the
current registered export lease and actual DH identity; it grants no ordinary
write permission. No removed `retry_failed_write`, `receive_cids` or
`run_bound_export` API is restored. Frozen implementation evidence is recorded in
`runtime/no-car-119/raw-phase2-migration-freeze.json`; independent review and the
complete retry module remain root-owned.

The private `verify_prepare_ack.py` proof replays an actual phase-1 prepare
prefix through the missing Control-module loader branch, leaving the persistent
child parked with `be8=1`. A recorded engine-view `ReadVersion` native status `7`
then executes `33e50` → `41e60`, changes `be8` to `2`, and waits on that real
child's `+1c` event. A second frozen replay delays the actual outer-tail
publisher, invokes its original implementation, and proves the external catch
waits while the child has not parked. Releasing that timing gate allows the
source tail and child unwind to produce `+1c`; the external catch then returns.
The child remains alive and parked; no retry query or input is created. These
cases do not cover a native catch during a pending query.

Full acceptance requires the independently reviewed same-engine failed-family
export → callback 3 → captured `5e950` input → callback 8 → actual retry consumer,
including post-wait multi-file reorder and nonretry whole-engine cleanup. Passing
input-validation tests alone does not certify that larger chain or vehicle use.

The shared `36800` prepare initializer clears only the source battery comparison
byte (`D548`), measured voltage (`D550`), query-valid byte (`D558`), and child
checkpoint (`C24`), in that order. It retains an existing native modal result.
The engine publishes the captured local timestamp to its canonical `D314` before
this helper; lazy retry-controller construction retains that timestamp instead
of restarting it at zero. Source `3c720` and cleanup use the same clock carrier.
These carrier checks do not establish acceptance of the whole retry controller
or the ongoing ordinary-prepare integration.

The current retry regression fixtures bind real frontend tables before cold
named FILE admission, including the actual empty DiagID row used by their
source bytes. The getter stop/reissue case binds its replay to the exact
runtime, engine and controller before `start`, so source `34cb0` publishes the
receiving state before the captured child clock fault. A generic phase-zero
reservation does not authorize `5f030`.

The original private119 helper and trace files remain immutable. The new
`retry-regressions/prepare_ack.py` fixture records a separate ordinary `36800`
entry with the actual Control module present and no selected family targets.
The real raw phase-one return is false with no family exports; this does not
claim successful prepare or programming. Its source-issued initial receipt is
consumed once by the child, and the canonical `D314` is 1000. The actual child
then parks with handshake one. A recorded engine-view `ReadVersion` status seven
produces `33e50` → `41e60` acknowledgement and handshake two, both after parking
and while the real outer tail is delayed. Fresh strict replay consumes each new
trace completely, retaining the live child and producing no retry input.
Public tests check private helper availability before importing it, so an
ordinary public checkout still collects and skips absent private evidence.
