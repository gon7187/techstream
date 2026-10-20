# Native live DataMonitor

`scripts.data_monitor` is the live monitor reconstruction. Snapshot playback is
implemented separately by `scripts.snapshot`; active-test event queues remain in
`scripts.toyota_session`. No vendor executable or device is opened here.

The current implementation includes the original controller mode transition and
provider selection, selected Freeze/MultiPID range definitions, P4/P5 request
builders, phase-specific packet assembly and a bounded injected exchange cycle.
The concrete P4 selected metadata producer, neutral DMCI setup commands, P5
DID/DTC/RID event setup and dynamic DID packing are available. P4/P5 composite pickup and a selected normal P5 direct-DID branch are implemented.
The complete mixed selected P5/DTC/RID producer is supplied by `monitor_p5`.
Full provider dispatch and all version-specific controller branches still require
their separate integration evidence; these helpers alone do not constitute a
complete `DataMonitorRun` replacement.

`select_provider(category_flags, communication_protocol, attribute_3_31)` follows
KgpDataMonitorCtrl `0xb0a0`. Flags come from native EcuCategory DB `0x110`, byte
`0x48`; the communication protocol and conditional attribute are observations.
The conditional branch requires an explicit result, rather than treating missing
state as unsupported. `monitor_mode` follows the controller's command-dependent
normal/fuel/Dual mode transition.

`selected_definitions(profile, selected_ids)` preserves the first selected
Freeze definition, shared child ranges, MultiPID order and flags. MultiPID DB
`0x21a` rows are twelve bytes. The result retains the native parent/ordinal/child
links and an explicit padding ordinal where the combined bit count is not byte
aligned. It describes the pre-packing inputs; it does not infer ECU support.

`p4_monitor_requests` implements native data types 0, 1, 2, 3 and 6.
`p5_monitor_requests` constructs the original `22` plus big-endian DID requests.
`MonitorEvent.p4` / `.p5` require observed response lengths. Their `request` and
`accept(reply, timestamp_raw)` methods reproduce request order, native SID and
header handling and cycle completion. P4 retains short-response tails; P5
clears its packet storage after every completed cycle. The
completed packet timestamp comes from the final response. Native raw samples
remain separate from display conversion.

`exchange_cycle` takes an injected diagnostic payload exchange, selected ECU
identity and explicit native millisecond tick provider. It checks cancellation
and its host deadline before and after I/O, and caps exchanges. The injected
exchange must enforce its own blocking I/O timeout. Selected transport setup and
cleanup remain caller-owned at this boundary.

`dmci_id_map_fields` returns the five DWORD fields of native command `0x111`.
Its zero-third-field substitution belongs to the DMCI wrapper; the direct Dual
J2534 path stores the supplied fields unchanged. Remaining field semantics are
retained explicitly until their native consumers establish them.


`pack_p4` requires the actual category flags and observed support bytes. Native
phase 4 counts nonzero support bytes in the full response; phase 6 retains the
whole observed byte list. `p4_signal_layouts` reproduces their different bit
position adjustments. `selected_p4_monitor` joins the selected Freeze, PhyData,
Unit and PatDisp records into named `MonitorSignalMetadata` fields, the generated
frame sizes and `MonitorSetup`. Composite groups append native parent/ordinal
bit-copy spans and byte padding. The raw flag-4 LSB branch requires observations
when DB227 contains a matching definition; missing observations are errors.

`MonitorCommand` carries native command IDs and core-free primitive fields.
`p4_setup_commands` creates native `109` or `10a` setup. `p5_setup_commands`
creates `119`, `10b` and `11c` setup, with zero length and no repeated standards
after the initial buffer registration. The recorder serializer supplies its
proven native core versions. These commands are distinct from diagnostic PDUs.

`P5MonitorEvent` captures a mixed cycle of DID payloads, DTC counts and selected
routine status bytes. `RoutineMonitor.check_status` preserves the original
ordered WORD status matching and its one-byte comparison path. `pack_dynamic_dids`
retains whole source runs, the native nonadjacent interchange ordering (including reordered ties) and request/reply budgets;
unassigned sources remain explicit. `clear_dynamic_requests` patches only bytes
2 and 3 of the first selected D4 template.

`MonitorProvider` exposes separate low-level send and receive operations.
`legacy_initialize` preserves the actual NULL send and NULL receive calls from
the KWP/Fuel stop-initialize branch, including their statuses. A NULL operation
is represented by `None`/`buffer=False`, never by an empty diagnostic payload.


`selected_p5_definitions` reads the original DB23E64 monitor rows, with word-sized
DID and DWORD flags. `selected_p5_signal_metadata` uses their actual field layout,
including the explicit observed alias PID from module WORD1D4. The
`selected_p5_polling_monitor` branch joins selected rows and observed enabled-DID
cache IDs into native mode20 registration. It does not infer support. This
explicit direct-DID branch rejects DTC descriptors; it does not silently replace
a requested dynamic plan. Native12 pattern rows use family WORD4 and match WORD10;
native18 rows use family WORD12 and match DWORD4. Both resolve label DWORD0 and
emit unit ID WORD6.

`monitor_composite_layouts` returns generated layouts, frame sizes and source
spans. `pickup_packet` reproduces native P4 timestamp-offset/sentinel behavior,
fixed-source-byte reloads and mutable overlap; P5 uses its separate zero-fill
sentinel and normal byte progression. These original differences have authored
regressions.

`run_monitor_commands` accepts a `MonitorSetup` and the recorder module's concrete
`NativeVimClient`. It prevalidates all setup/start/stop fields, exchanges actual
ComTol DMCI commands, polls native GetMonitorData, and assembles fragmented raw
packet buffers. The result preserves raw timestamps. Packet count, aggregate
bytes, exchanges and deadline are bounded; unexpected interfaces and extra
packets fail explicitly. Stop cleanup has a separate bounded deadline and also
runs after read failure or cancellation. The interface must already be opened
with its selected addressing; this API does not invent interface capability.


`selected_p4_connection` binds the actual selected ProtInfo and CommInfoCan rows
to observed bus and diagnostic-mode bytes. `p4_monitor_address` preserves native
DWORD arithmetic and all supported bus subtype branches. Its `parameter_word`
is the native negative count (ProtInfo WORD18, zero replaced by100).
`p4_can_lifecycle` and `selected_p4_iso_lifecycle` add actual native interface
creation, DM interface creation, IDMap, negative-count configuration and the
conditional interrupt timing before monitor setup. Their stop plan deletes the
DM and diagnostic interfaces after stopping. These are the native device4 DMCI
branches; direct J2534 initialization has a different contract. ISO preserves
all23 selected SCONFIG pairs and requires observed initialization mode1/2 and
the original command DWORDC0 parameter. CAN accepts the original500000-baud
selection. `run_monitor_commands` checks the additional native SetNegCount result
boolean and charges aggregate fields/bytes before materializing aliased command
lists.

`selected_p4_from_exchange` feeds the shared `MonitorSupportCache.support_bits(1)`
raw stream producer into the selected P4 plan. Support queries carry selected
frame/timer metadata and bound source identity; no support bitmap is synthesized.
An independent authored serialized-DDB plus raw support stream integration has
also been exercised by the support-module owner.

P5 source build is explicit (`source_build=12` or `18`), independently of database
format. `selected_dynamic_slots` reproduces build12's selected DB251 intersection
with an observed enabled-DID cache. Build18 may instead use the actual selected
114/115 exchanges for its flagged discovery branch. Invalid first discovery
results stop before the second exchange. `p5_dynamic_sources` constructs native
selected byte runs, keeps whole-byte dynamic limits and reports ineligible DID
IDs explicitly. `register_dynamic_dids` executes the native12/18 D4 clear, D3
definition and CA validation transactions using those actual selected templates.
A failed D3 retries the same sources in the next cleared slot. A failed CA
discards the host mapping without disabling packet mode; it sends no invented
rollback. Build12 aborts on its first failed clear and disables packet mode.
Build18 filters failed clears and disables packet mode only if none succeeded. Native status failures are recorded separately
from host transport failures, cancellation and deadlines, which propagate.
`p5_dynamic_layouts` reproduces the selected-byte compaction and packed-source
offsets for complete eligible plans. The complete mixed selected12/18 producer,
including partial and ineligible-source direct-DID fallback, lives in
`scripts.monitor_p5`; its independent review remains separate from these helpers.

`selected_p5_polling_from_cache` binds the explicit direct-DID branch to the
shared concrete support cache. It starts one logical operation, consumes actual
C8/CA DID discovery and delegates matching LSB branches to `SignalLSB` with the
same source build and source identity. Native live metadata retains the changed
coefficients and then performs its original later threshold overwrite. The
different freeze-frame consumer retains the LSB threshold and lives separately.

`selected_p5_dynamic_from_cache` connects the native18 complete eligible path:
actual support discovery, selected dynamic slots, D4/D3/CA registration, compacted
signal layouts, native metadata and `119`/optional `112` setup. Its
`DynamicRegistrationError.outcome` preserves failed/partial registration status
and the disable-packet-ECU side effect for the caller's unfinished fallback.

`selected_p5_can_connection` and `p5_can_lifecycle` expose the proven native12/18
single-target device4 CAN constructor. This uses `118` (CreatePhase5Interface),
`107` phase enum3, observed routine-info mapping through `11e`, address maps,
negative count180000 and the selected monitor setup. The live path can add the
native second address map from ProtInfo WORD6/WORD20; the recorder path omits it.
The authored serialized-DDB regression runs support discovery through dynamic
setup, metadata, actual ComTol constructor/start/GetMonitorData/stop/delete and
preserves the captured raw timestamp. This verifies that positive branch; it
uses `selected_normal_monitor_from_cache` to reach the mixed selected P5 producer.
The separate `scripts.monitor_poll` module owns direct J2534 scheduling. Its
complete integration and independent review remain open.

Selected range definitions and connection records retain the shared source
identity (ECU database, management database, category bytes and exceptions).
P4 CAN/ISO and P5 CAN lifecycles require a nonempty matching identity before
producing commands. Equal category/request numbers alone cannot bind plans from
different selected databases. Structural authored metadata inputs can still be
used by pure packing helpers; they do not acquire an implicit I/O identity.

Dynamic ordering follows the original nonadjacent interchange sort, including
the case where a later smaller item reverses earlier equal keys. Unordered
inputs exceeding6,400,000 comparisons are rejected before the quadratic loop;
this is an explicit host resource policy. Already ordered lists need no swaps.


`SelectedP4Monitor.source_build` and P5 plans retain the explicit application
build. Concrete cache/exchange factories set this field; a pure authored P4
packing call may leave it unbound. A direct runtime must require an actual12/18
build and must not derive it from the DDB format.

`DynamicOutcome.clear_ids` is the native retained list of all successfully
D4-cleared slots, including slots whose later D3 definition failed or was never
used. It is distinct from registered read IDs. Build12's failed-clear branch
resets this list. `p5_setup_commands(clear_ids=...)` emits command`11A` with
little-endian WORD identifiers after DID/DTC setup and before RID setup. Direct
polling and Dual runtimes consume that list for their actual native cleanup.
A truly empty original DID source list returns`90051019` after successful D4
clears; a nonempty list with no eligible runs follows the different native
failure path. `register_dynamic_dids(source_rows_present=...)` preserves this
explicit distinction when the caller has already separated ineligible rows.

`selected_dual_target` binds a selected normal plan to an actual Dual target.
It verifies the selected source identity, explicit application build and setup
request address, then derives native command/category/protocol/address/entry
fields from the selected connection. Driver timing, retry and IDMap observations
remain explicit inputs. The actual control/backend execution belongs to
`scripts.monitor_dual` and `scripts.frame_transport`; a target alone is no claim
of a completed capture.


For raw phase9 CAN, `selected_normal_monitor_from_cache` delegates to the
separate `monitor_packet_a8.selected_packet_a8_from_cache` producer. The caller
supplies the native ECU key explicitly; the existing support cache and deadline
are retained. This path uses its own FUN3360 packing and packet grammar, rather
than the normal P4 packer. The authored12/18 router regression checks the actual
`210C` support transaction and resulting `A1010CFF` setup descriptor. The distinct
`DM_ActVariable_DT` route delegates its own selected factory when Attribute(3,31)
is explicitly true; it does not call the normal P4 factory. Its full Run and
stop/controller integration remain separately open.


Normal metadata creates a fresh LSB helper for each signal, matching the native
local constructor/InitInstance/Change/destructor lifetime in a3d0/c8d0. The shared
ECU support/response cache survives; helper-local discovery results do not leak
from an earlier metadata invocation. The native P5 runtime disable byte is
compared to exactly1; other byte values are not treated as a bit mask.


`P4MonitorPlan` describes the actual selected definitions, packing and commands
consumed by the common CAN/ISO constructor. It permits the source-proven variable
provider to use that shared constructor without pretending its plan is a normal
P4 provider. This contract does not merge the providers' packing or runtime rules.


`selected_legacy_check_target` binds a retained `NativeCommunication` to the
legacy check controller: transaction and stream reference that same object,
packet discovery uses its concrete typed adapter and source identity, and native
packet ECU/protocol are the selected category and bus. This binder performs no
channel open/close and preserves the communication's budget and cancellation.

`runtime/no-car-25/verify_normal_pipeline.py` exercises original selected12/18
NA category60 and372 records with authored backend exchanges. Ten normal cases
and ten Dual cases include direct, dynamic and RID combinations. The actual
selected plans feed their concrete worker, native capture serialization, DM
reparse and `monitor_samples` display conversion. Dual cases use one shared
channel and assert exactly one connect/disconnect. DD/D1/D2 recovery requests
come from the original selected command cache. The normal P5 lower class is the
actual selected PSA class for category flags20 on CAN, including its absent
normal tester frame. These checks do not establish physical adapter/vehicle
support, exhaust all categories or verify the rendered desktop.


`selected_monitor_buffer` is the concrete selected P4/P5 metadata export
consumer. It obtains the native ECU ID from the selected setup command. For the
mixed P5 producer it preserves `default_signal_slots` and every unassigned
short-name slot explicitly; it does not infer constructor state from empty text.
The both-build composite/paired-RID/default-hole regression exports and reparses
native DM, retaining zero-length constructor strings and RID metadata. The
original normal/Dual integration above calls this production consumer.


`selected_normal_monitor_worker` is the production normal runtime dispatcher.
It sends an A8 ModeA1 plan to the distinct PacketDMP4 worker; A8 pair plans and
normal P4/P5 plans use their actual polling constructor. Variable plans require
their separate selected runtime. Normal P4 may carry a typed
`NormalOscilloscopeSelection`; the source-selected category999 setup then enables
the native combined read path. Four additional original12JP/18NA pair/packet
checks serialize and reopen both the data and instrument captures. Build12 NA
has no selected OSC system, so that check uses its actual JP catalog throughout.

`selected_variable_monitor_runtime` joins the concrete retained communication
Check targets, native CheckStart allocation, controller-category child selection,
actual selected connections and per-slot metadata into `VariableMonitorRuntime`.
The command ECU selects the controller flags from the original category table;
targets retain their separate Check flags. Standards, names and encoding are
explicit caller inputs. The factory closes its support channels before returning
the runtime and preserves primary exceptions if cleanup also fails. Full joined
integration is tracked separately from the accepted normal/Dual checks above.

The joined variable factory has an independent authored native-backend positive
check under leaf100. `runtime/no-car-25/verify_variable_join.py` also verifies the
complete full-support Check/plan/acquisition/native-DM/display path and native
read-fault/host-cancellation cleanup. Partial ANY-support geometry remains
source-sensitive: a one-byte retained packet can still have a two-byte signal
layout, which the display adapter rejects rather than reading outside its data.
That narrower case is tracked for source review, not silently expanded.


`SelectedMonitorSession` represents the selected application's shared state,
including the mutable `CShareData` key1B packet-disable list and the explicit
key1E interface observation. Keep one instance across that session's workers
and subsequent CheckStart calls. It is bound to management source/version,
vehicle, exceptions and application build; source changes fail before access.
Native Add searches before appending, so repeated errors retain one category;
raw seeded observations are preserved. Reads and updates share one lock.

Normal/A8 and variable factories accept `monitor_session` and bind its callback
to their actual direct worker. The worker's native packet-class error policy
controls updates; BASE errors and `E00001CC` do not append. The legacy controller
and `check_legacy_monitor` consume the same live state on each CheckStart. The
both-build regression drives an actual typed J2534 A2 read failure through the
legacy packet worker (`E0000104`), then verifies the next check changes excluded
mask0/packet-mode1 to mask3/pair-mode10 without recreating session state.

The partial ANY-support geometry above was independently confirmed in the native
DCF0 range getter: it checks the first selected byte and adjusts both bounds by
the same preceding-byte offset, retaining an end bit beyond a compacted frame.
The safe display rejection preserves that original quirk without inventing bits.

Packet discovery uses that same session too:
`selected_legacy_check_target(..., monitor_session=session)` binds the retained
communication's packet cache to the shared Add callback. The separate A3-send
failure path updates key1B before its native drain finishes. An authored typed
12/18 regression retains the first check's fixed-packet result, then verifies
that a fresh CheckStart sees the new disabled entry and selects pair mode.

`selected_legacy_monitor_runtime` prepares an actual source-selected P3/DK
controller, queue and initial command9/56/87 without I/O. It selects the provider
from the actual command ECU communication. An explicit empty `primary` is
required when that ECU is absent from the selected target list. Native category
registration retains its NULL first slot, overwrites matching categories without
moving them, and preserves unsupported source faults. Callers choose cooperative
`run_one`/`poll` or threaded `run(queue)` for that prepared controller.

Run87 requires actual vehicle, system and trigger metadata. The production
`complete_selected_legacy_recording` consumer runs an unstarted cooperative87 or
consumes an already-finished threaded87. It calls the native outer recording
metadata path after group12/finish: conditional trigger7 check-mode followed by
unconditional selected VIN. Support communications remain live until that path
finishes; cleanup then releases the controller and all selected support channels.
Host faults and cancellation retain their identity, with cleanup errors attached
as notes. DK87 retains native `90050405`; a NULL Century event retains its source
fault. These paths do not fabricate an empty recording.

The variable factory also accepts actual `NativeVimClient` operations with
`connected_device=4`. The default device8 route is unchanged. The actual command
ECU selects controller flags and connection; its registered slot comes first,
while each original Check allocation, name and standards stay with its selected
target. ISO construction selects the first actual controller CommInfoIso row and
requires explicit initialization/C0 observations. Device4 acquisition requests
category keys, then exports the same native recorder buffers as device8.
`runtime/no-car-25/verify_variable_join.py` checks both builds/devices with real
selected support communication and primitive backend/VIM replies, native DM
roundtrip/display, native failure and cancellation. An absent variable controller
uses the typed `VariableNullController`: an actual management-only
`ProtocolProfile`, selected connection and mode80, with no producer/buffer.
Device4 retains its first IDMap before real child setup and polls only actual
category buffers. Device8 preserves the native missing-entry-event error
`E0000102`; it never substitutes a real child's plan for the NULL slot.


Management-only primary contexts use canonical `ProtocolProfile` throughout
session/connection identity. Their absent ECU hash remains `None`; allocated
signal producers still require a bound `VehicleProfile`. Variable registration
deduplicates categories before constructing children, preserving the final
selected target's measured allocation and display metadata in the original
physical slot order. The joined variable check now includes 24 cases, including
management-only NULL primaries and repeated-category overwrite.

Legacy Run87 also retains a management-only command primary absent from the
selected list. Its NULL buffer stays at native slot0; the first original
selected buffer at slot1 supplies recording metadata and VIN. Both builds and
observed4/8 paths verify that only the real selected support channel opens,
including trigger1/7. The primary support communication remains unopened and is
released after recording finalization.

Recording completion accepts only the exact controller/message pair returned by
the selected factory. A foreign prepared message fails before any I/O or resource
ownership is taken; it cannot cause cleanup of another recording's channels.
