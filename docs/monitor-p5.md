# Native mixed Phase5 monitor

`scripts.monitor_p5.selected_p5_monitor_from_cache` composes the selected
native12/18 normal monitor range, dynamic-DID, DTC, RID and composite producers.
Import does not open an adapter or execute an OEM binary. The input is a concrete
`MonitorSupportCache`, selected DDB IDs, explicit observed attributes26/73,
caller-selected dynamic mode/exclusions, and native request/reply limits.
`routine_ids` is the separate selected routine list populated by native1c50;
it is not inferred from a label or from the presence of a DDB row.

The returned `SelectedP5Monitor` supplies the common source-bound monitor plan:
`definitions`, `signals`, `frame_sizes`, `commands`, `pickup_spans` and
`source_build`. Additional fields retain `mode`, literal `dtc_requests`, actual
DB213 `dtc_patterns`, ordered child `routines`, and `default_signal_slots`.
The signal table preserves the original bb40/ac10 indexed writes: ordinary
ranges first, RID items at the ordinary-count offset, and composite items at the
RID-count offset. That last native offset overwrites earlier items. Allocated
constructor-default slots are retained and must not be compacted or deduplicated.
`packing.outcome` preserves
failed clears/definitions/validation and the native disable-packet-ECU flag;
consumers must retain that state rather than inventing a successful reset.
`P5ControllerError.outcome` retains those side effects when registration fails or
a required direct fallback mode is unavailable.

The producer starts one support operation and consumes actual C8 discovery.
Native dynamic registration uses the existing source12/18 D4/D3/CA transactions,
including build12's first failed-clear abort and build18's filtered slots.
Registered groups remain first in packet order. Unmapped and dynamically
ineligible original DIDs append in selected cache order through the6960 fallback.
CA failure discards dynamic host mappings; it emits no rollback transaction.
Cancellation propagates with the actual observed transaction prefix intact.

DTC selection uses the last flags8 range, matching native6d80. DB213, DB112 and
DB111 joins select first matching records without adding a communication-settings
lookup absent from27e0. Request byte2 becomes8, while DB213 byte6 remains the
typed10B pattern. Native nonzero patterns produce `0xE0000102` in the raw event;
short zero-pattern replies `59` and `5901` retain the native zero count.
Only the last DTC signal skips the normal DID bitmap lookup in21a0. Earlier DTC
signals with no normal DID source produce the native mapping error, even when
their source DID equals the last DTC's DID. Source-ID collisions select the first
native mapping and preserve the last signal's special uncompressed offset.

RID requests/status lists use `selected_routine_monitors`. Display metadata comes
from the independent cf40/c010 DB247/249 producer, with DWORD shift-count wrapping,
native maximum/minimum field order, DB247 name at DWORD8 and alias PID`0x2134`.
Special pairs emit two requests and one logical frame sized by the parent's
selected press value. Native dc80 appends each child's payload in request order.
The host rejects a parent allocation different from the sum of child writes;
this bounds unsafe native geometry and is explicitly a host policy.
The same host bound rejects a DTC frame inconsistent with its two-byte native
count write or a signal extending outside its selected frame.

The common typed setup emits119, then10B, optional11A cleanup registration,
then11C and optional112 pickup.11A retains every successful D4 slot, including
slots whose later definition or validation failed; these are distinct from the
registered read IDs. It registers native stop cleanup and is not an immediate
rollback after registration failure. Only
the first registration receives total allocation and standard values. Existing
`p5_can_lifecycle` and `run_monitor_commands` execute device4 lifecycle and typed
VIM bytes; direct J2534 scheduling is a separate consumer. Raw timestamps retain
their source value and units. `native_monitor_buffer` and
`NativeRecorderCapture.monitor_buffer` preserve the selected frames and signal
metadata for native snapshot playback. Pass `default_signal_slots` from the plan
and `unassigned_short_name_slots=tuple(range(len(plan.signals)))` to
`native_monitor_buffer`: native P5 leaves every short-name string unassigned.
Default holes retain three zero-length strings; assigned empty name/unit strings
remain distinct from constructor defaults.

Validation: `python -m unittest discover -s tests -p test_monitor_p5.py -v`.
The authored tests parse real synthetic DDB byte containers for both source
versions, execute concrete support/registration transactions, map partial/full
dynamic results, retain DTC patterns, compose paired RID/composite packets, pass
typed VIM command/reply bytes and replay native recorder subbuffers. Faults cover
validation/clear failure, source mutation, cancellation, bad SID, unsafe paired
geometry and stop after acquisition failure. Resource and work limits are host
policies. The private source manifest binds the original static inputs and
implementation hashes; no vehicle/adapter equivalence is claimed.
