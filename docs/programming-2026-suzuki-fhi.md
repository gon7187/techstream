# Recovered2026 Suzuki/FHI programming

The software implementation covers the six main Suzuki UDS, Suzuki USB and FHI
exports and both utility export surfaces. Every operation resolves its exact2026
protected-original/companion/inspection identity through `native_modules`.
Older12/18 modules and forged identities cannot select these operations.
All I/O uses injected CAN/J2534/platform primitives.

`bind_native_context(container, node, observed_cids, selection, identity,
attachments, observations)` validates actual CUW metadata, the canonical native
parameter selection, exact selected/utility module bytes and the engine-owned
Suzuki controller state. It derives communication addresses and archive geometry
through the shared2026 CalibrationFile and CommunicationAddress implementations.
Current CalibrationFile CPU-type mutations survive canonical binding and keyed
parameter lookup; stale selections fail before I/O. Writers require the actual
engine-owned NotificationBool backed by source-bound CUW persistence.
`execute_context(context, runtime)` executes the selected export and returns
phase state, identifiers/counts where applicable, native error fields and cleanup
results. It never reports completed programming or confirmed physical operation.

Implemented paths include:

- Suzuki prepare: functional extended session, retained tester-present resource,
  gateway authorization, DTC and communication control, programming session,
  ECU authorization and the persisted USB retry/CID comparison branch. Failed
  readback returns through its own typed native catch; its filter cleanup fault
  is suppressed and reported separately, preserving the business result.
- Suzuki write: tester information `2E F198/F199`, routines `FF00/FF01`,
  `34 0F45`, bounded `36` blocks with wrapping counters, `37`, reset and
  functional post-program session. Transfer send timeouts are computed and restored.
- Suzuki getter: `22 F189/F188/F191`, native fixed2/16/11-byte extraction,
  NUL-terminated field behavior and the native composite CID.
- USB write: actual enable/poll/routine requests, four-attempt native retries,
  deadline/regression errors, progress, notification cleanup and persisted
  state0/1/2. Nonzero persisted state returns through the native early branch;
  its skip is explicitly reported.
- FHI prepare: both ECU probes, native9/16 timeout branches, DTC/communication
  batches, sessions and authorization. Native success after a probe timeout
  explicitly reports the skipped remaining sequence.
- FHI write: source-selected area, routines0201/0202, `B7` comparison,
  `B6` writing, negotiated block limits, `37`, native progress and cleanup.
  Failure disposal follows filter cleanup: count reset callback, percent reset
  callback, then timeout restoration. A throwing callback stops that tail and
  leaves the native return unknown while retaining the initiating native error.
- Utility constructors, shallow copy/move/assignment, fixed CAN constants,
  pointer-free virtual method order, keyed wait/baud helpers, raw pending/busy
  loops, batch retries, native selective cancellation callbacks and timeout
  restoration. Host cancellation/deadlines remain separate from native callbacks.

ECU authorization uses explicit narrow `observe_authorization_key` observations:
actual seed bytes and required key length produce exact observed key bytes.
The normal Suzuki wired gateway route binds the actual source-issued CUW worker
and online controller to recorded configuration/browser primitives. Public replay
uses authenticated control-module bytes and `online2026` configuration/recording
attachments, and accounts for captured elapsed time once. Unknown observations
or missing source bindings fail before key transmission. Original secrets and
vendor key algorithms are not embedded in this implementation.

Primary native errors, J2534 statuses and native error kind remain separate;
unspecified secondary status retains the engine's previous native field. Bounds
reject malformed memory behavior, unsupported CUW geometry and excessive work.
All six main exports suppress their source-proven StopFilter exceptions without
changing the business result. Reports retain these as `suppressed_cleanup_errors`;
successful Suzuki preparation retains its periodic worker even when filter
cleanup fails. The getter retires only its exact invalidated filter compensation after a
successful disconnect. Other cleanup boundaries and host cancellation stay distinct.
USB host deadlines and interruption propagate immediately through enable, status
and final-reset loops; native errors retain their source-defined retry behavior.
Native parameter lookup preserves the caller's row, including constructor row0
(the header), a selected row and missing row-1. Suzuki utility timing keys use
global CPU0, including when current metadata selects another actual CPU row.

G2/G3 remain OPEN for final reachable CFG/EH and canonical controller review.
All six native export return shapes have independent ASM evidence: the getter
returns a pointer with a separate success out-parameter, while the five remaining
exports return their business BOOL. Unknown host/cleanup failure returns stay unknown. Private source/export mappings are recorded under
`analysis/evidence/no-car-34`; independent typed-provider and six-export canonical
integration evidence is maintained by leaf56. The private leaf34 production
factory check covers all six exports, two native writer failures, all six
suppressed-filter successes and two combined writer/filter failures through
`load_programming_replay` / `run_bound2026`, followed by serialized JSON replay
through `run`. Typed tuples and native error domains survive that round trip. Discovered Ghidra functions alone
do not certify complete reachable control flow.

Run authored synthetic controls:

```sh
python -m unittest discover -s tests -p test_programming_2026_suzuki_fhi.py -v
```

Tests contain authored bytes only. Native source and original calibration
material remain private. Physical compatibility is `PHYSICAL_UNCONFIRMED`.
