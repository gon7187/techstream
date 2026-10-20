# Legacy monitor recovery

`scripts/monitor_legacy.py` ports cached native normal-monitor producers and
low-level event machines. The four-family acceptance gate remains open. All
wire tests use authored observations: no adapter, vehicle, DLL execution or
live protocol support observation was used.

## Concrete paths

* P3 `39e0`, `3490`, `3cf0`, `2fc0`: ascending A1/01 PID packing with FF
  fillers, fixed cached packet packing, ordered pair descriptors and automatic
  mode1 → mode2 → pair fallback with original attempt status values.
* `selected_phase3_monitor`: actual selected Freeze/DB206 rows, optional missing
  composite children, MultiPID bit pickup and DB213 auxiliary retrieval. Native
  `2160` selects the first DB112/DB111 send frame; `dea0` emits actual
  109/10A/10B setup and 112 pickup bytes, with 10C start and 10E stop commands.
* `selected_phase3_from_exchange`: leaf52 `MonitorSupportCache` performs actual
  selected support queries. Fixed packets are fetched lazily through concrete
  `PacketFrameCache` A2/04 → E2 → A3 transactions only after mode1 fails. Native
  frame sequence 0x11 is preserved as 0x11 in metadata and frame tables.
  Cache-query faults retain their original native status before pair fallback.
  Both exchange adapters expose the typed support stream and observed bus ID
  for timeout → NULL InitEcu(flags1/1) → next support query. Packet caches must
  match the selected support source identity, rather than their own saved token.
* P3 `6770/6570/68d0/6950/63a0/6220`: inclusive A1 setup retries, literal source
  checks, E2 fragments, initial/due A2 scheduling and A3/E3 shutdown with the
  native 2000ms window and an additional bounded receive count.
* `Phase3PacketGenerator`: DatMonCommon `47c0/4890/4900/4aa0` phase0 fragment
  assembly, missing-frame complement from an explicitly observed previous
  packet, native overflow discard and the phase1 single-block timestamp/cache
  complement. Zero-length fragments do not advance the native frame ordinal. Unknown initial heap bytes are never
  invented. `run_phase3_stream` joins setup, scheduler, receive and packet
  assembly with deadline/call budgets and independent A3/E3 cleanup after
  cancellation or failure. This is separate from DRS packet capture.
* `selected_dk_monitor` / `selected_dk_from_exchange`: actual DK category7
  Freeze metadata and enabled PID support → mode200 → direct 2C event.
  DataListIF `6360/67a0/6810/7650` emits literal requests and packets, skips the
  first reply byte without an invented service check, counts leading nonzero
  DTC bytes and preserves shared retry/error behavior. DK2160 selected DB213
  auxiliary retrieval emits literal13 requests and preserves the selected packet
  capacity, including trailing zero bytes beyond the one-byte DTC count. Native
  `4870/4f50` DB206 fallback requires Freeze BYTE77 exactly1.
* `phase3_interface_lifecycle` / `run_phase3_dmci`: actual selected ISO23-pair
  constructor100, VPW102 or PWM103, P3 create-DM107 with phase0, optional IDMap111
  and negative-count114, then selected setup/start/GetMonitorData and
  stop/delete108/104. Device4 and device8 with explicit recording state use
  this native route; device8 without recording selects the direct workers. An authored selected DDB reaches actual ComTol bytes and a
  complete native timestamp/payload packet before cleanup.
* `phase3_constructor_route` / `selected_legacy_j2534_frames`: actual device,
  recorder, interface count and mode decisions select base/Century/Packet/DKKwp
  direct workers. DK requires observed device8. Selected request PDUs pass
  through leaf43 GetCommFrame into concrete headers/configs/filters.
* `selected_legacy_monitor`: native `select_provider` dispatch, including phase9
  protocol2/8 selecting P4, delegates actual PSA work to leaf44
  `scripts.monitor_psa` and DLC12 work to leaf45 `scripts.monitor_dlc12`.
  Required observed support, protocol, mode35 and device inputs remain explicit.
  P3/DK category68 delegates the concrete instrument producer from leaf62,
  including actual calibration observations and the original false sampler
  stubs; calibration is not fabricated continuous sampling.
* Frozen DLC12 helpers retained for leaf45: `pack_dlc12_ranges` (`2770/29e0`,
  native rolling end-BYTE truncation), `dlc12_setup_commands` (`74a0` datatype
  priority) and `dlc12_interface_commands` (`7130`, selected function6B request
  and mask → 105/106). Leaf45 owns full selected producer and lifecycle.
* PSA `LegacyMonitorEvent` retains shared literal 21 requests, first matching
  optional suffix, 61 header check, short-reply zero fill and cycle clear for
  leaf44's concrete selected producer.

Boundary checks reject malformed observations before event state changes.
Cancellation is checked around DK driver calls; synchronous drivers must honor
the supplied timeout. Additional receive budgets bound native loops even when
an authored clock or injected driver does not advance.

## Remaining acceptance scope

`leaf-41:G2/G3` remain open pending all of the following:

* Independent complete exported `Run` source/caller review remains open. The
  current `LegacyMonitorController` candidate implements the actual external
  queue, write/finish events and command/acquisition thread boundaries. The
  synchronous helpers alone remain insufficient evidence for exported Run.
* Final independent review of P3/DK `check_legacy_monitor`: native4a50/5b90
  single/multi policy, global command ECU ShareData1e/1b joins, selected support
  transactions, lazy fixed-packet cache, voltage measurement and allocation.
  The typed target API carries actual global observations explicitly; no sampler
  success or dynamic support is inferred.

* Final leaf76 base/Century/Packet/DKKwp branch review after concrete selected
  caller integration, including mixed/physical Century and Packet stop behavior.
* Final consumer review of leaf44 PSA, leaf45 DLC12 and leaf52 support caches,
  including low-level primitive frame construction by leaf43.
* Independent reconciliation of the complete original12/18 audit retained in
  `analysis/evidence/no-car-41/version-review.md`; all normal P3/DK code regions
  and shared ring exports are covered, with meaningful native deltas preserved.
* Independent native/original-definition corpus review and the resulting fixes.

The low-level GetCommFrame → PASSTHRU/config/filter producer belongs to leaf43
`scripts.frame_transport.get_comm_frame`. It produces typed message/config/filter
fields; this module does not treat opaque callbacks as evidence of that logic.

DK a650 copies each selected Freeze descriptor directly, including bit16. It
does not perform P3 b620 DB21A expansion. An authored regression rejects any
unexpected DB21A query. Leaf1 checked default original overlays:15 selected DK
Freeze rows in each build and no bit16 rows; this corpus observation is not a
claim about every possible exception combination.

Selected P3 and DK plans carry the central full source identity (database,
management, category bytes and exception IDs). DMCI setup and direct primitive
frame production validate that identity before issuing any commands. Matching
database hashes alone do not authorize reuse across different selections.

`LegacyNativeProvider` binds the literal shared send/receive contract to recovered
`NativeFrameOperations`, including NULL initialization and output-buffer checks.
`run_dk_native` validates the full selected identity and lower FramePlan, opens
and configures the actual channel, polls bounded DK events, and disconnects on
success, driver fault or cancellation. Native `SetSndRcvTimeout` uses first
selected functionA7 settings with exact1000/200 fallback. The synchronous host
lifecycle preserves start/stop ordering without emulating Windows threads.

`selected_phase3_native_worker` binds selected source/frame/address metadata to
the recovered leaf76 worker. Native phase0, functionA7 timers, attempts from
command10A and first-target diagnostic DWORD8/ProtInfo WORD8 remain literal.
Authored original12 and18 DDB layouts reach FAST_INIT, actual application writes,
reads, capture packets and disconnect. Century multi-system orchestration uses `selected_phase3_century_worker` with
exactly two selected targets and concrete Century functional transport. Its
full mixed/physical/stop branches still require the leaf76 independent review.

Century registers each default ECU source independently of its mapped response
ID. Shared functionA7 timers, command10A attempts and functional parameter8 are
validated from actual selected records/commands. Two authored selected profiles
produce literal functional C2 framing and independent capture packets.

P3 CAN phase0 retains the native response-ID low-byte comparison although the
lower CAN inverse returns the full native WORD source. An authored7E8 response
stays unmatched againstE8 and terminates by the host bound with an empty capture;
the implementation does not rewrite IDs to manufacture successful acquisition.

Capture budgets include the four-byte timestamp before each payload. Fixed
packet geometry is checked before interface creation, with runtime charging
before retaining packets. The shared limit is32MiB.

The independent original-declaration audit in
`analysis/evidence/no-car-1/p3-declared-buses-corpus.json` found no default
P3-family CAN declarations in either original build across the three regions.
That count excludes runtime exception combinations and does not prove that a
live CAN path is unreachable. The latent native source-comparison behavior
therefore remains implemented and bounded.

`SelectedMonitorCapture` retains the selected plan beside its native capture.
`run_phase3_native`, `run_dk_native_capture` and `run_phase3_century_capture` bind
results directly; `.monitor_buffer` builds actual DRS frame/signal/selected-ID
tables using explicit allocation, name and encoding. SelectedPhase3Monitor also
retains `.native_packing` after native auxiliary packing and before composite metadata changes, so the
measurement getter counts the actual native mode frames.

The normal CheckStart caller can obtain each `LegacyCheckTarget` through
`data_monitor.selected_legacy_check_target(communication, selected_ids,
observed_functions)`. The factory retains the concrete `NativeCommunication`
transaction, stream and same-channel packet cache. Authored original12/18 schema
fixtures now reach that factory, actual KWP FAST_INIT/write/read, support replies,
P3/DK CheckStart multi allocation and disconnect. The P3 mode2 case additionally
reaches A2/04, two E2 observations and A3 on the retained channel; lower receive
fault and cancellation after an application write both reach caller cleanup.


`LegacyMonitorController` is the current exported Run candidate. It owns the
concrete manual-reset command/finish events, queue dispatcher, acquisition and
command threads, and selected P3/DK setup/stop. Authored source-free original12
and18 schemas reach real NativeCommunication, direct KWP and serialized ComTol
monitor packets, resource cleanup and native DM serialization. Native callback
failure permits a later queue restart; finish notification precedes buffer error
publication. Host cancellation and exceptions preserve their original identity.
The two-target P3 route reaches actual Century functional frames and independent
buffers; the DK route preserves its source single-event destination overwrite.
DK commands87 and96 retain the source unsupported90050405 response.

The candidate accepts the concrete `SelectedMonitorSession` shared with the
normal caller. CheckStart and each new Run start take live CShareData1B snapshots;
packet errors append through the worker callback to that same retained session.
The list is never reconstructed from a worker-local flag.

Run scope remains open for remaining control-protocol source reconciliation,
actual normal UI caller integration and independent complete source review.
The current public checks cover real DK completion events/waits and concrete
Run87 settings/stop writer chronology; those are no longer merely synchronous
artifact helpers.

Single active-only Run targets accept empty selected IDs and preserve the native
absent buffer: P3 mode80 and DK mode400. They construct connection metadata with
an empty descriptor and issue no early primitive calls; actual active/system
registration enables the worker. They cannot manufacture a DM capture. DMCI
polling identifies actual allocated buffers by ECU/category (+468), independently
of their wire request addresses.

Century retains absent DM registrations as actual `None` entries. An all-active
list remains configured; its active/system registration succeeds before the
acquisition thread encounters the recovered native NULL-DM boundary. Mixed
active/data start reaches that boundary during start. `NativeMonitorSourceFault`
preserves this host-visible boundary without inventing a native DWORD or a fake
DM event. A third Century registration returns the native outerA0050425 setup
failure. Distinct authored channel handles verify each acquired resource is
released once.

`selected_phase3_recording` produces native DRS group11 setup/start and
12 stop/dispose from a retained target. `LegacyDrsWriter` additionally executes
FileManager's concrete WriteStart/WriteEnd seek/length-patch chronology under
Run87: group11 closes, group12 contains stop/dispose, group12 closes, mode clears,
then the command finish event signals. Native failures still attempt cleanup;
host writer faults retain their identity. The first original selected buffer,
not every registered monitor buffer, supplies native serial-mode1 metadata.

After finish, `controller.recording_file()` compiles outer CreateDrs check-mode
records only for trigger7, and unconditionally compiles the selected VIN group27
through the retained communication/cache/driver/diagnostic mode. Keep that
communication alive until this call returns. Missing functions27..39 preserve
native C0040101 rather than manufacturing an empty successful group. Public tests
exercise generated group27 through the native DRS consumer, including read fault
and cancellation after connect with exact channel release. FileManager framing
is sourced for both builds. Leaf6 independently verified original12 outer call
order and normalized CheckMode1e40/VIN3190 instructions against original18
1e30/3180, with no field/list/order delta. Leaf6 also verified37 selected group21..27 and primitive serializer reachable
control-flow functions across12/18, following both conditional arms and early
returns. Dynamic CCmdReader/Writer ABI and lower packet layouts retain their
separate owners' proofs; this is no claim about the entire recorder.

Native multi registration first inserts the command ECU with an absent buffer.
`LegacyControlMessage(primary=...)` carries that actual selected ECU independently
of its selected list; omit it only when the command ECU is the first selected
ECU. Register8320 searches by ECU category, overwrites an existing matching slot
without reordering, and permits three total slots. An absent command ECU therefore
remains the first real placeholder. This affects Century registration and may
reach the recovered NULL-DM source fault. Tests use different native categories
for different ECUs; changing only wire addresses never creates extra native slots.

DK events174/178/17c/180 start signalled. Data start clears stopped/data/failed;
active start waits stopped up to30000ms, posts C0050503 on timeout, and continues.
Active/data stop waits its completion up to10000ms and posts C0050504 on timeout.
The queue retains a pending command during these cooperative waits, acquisition
continues, and finish remains clear until completion. SDK faults signal
active/data/failed before outer error handling; cancellation and worker exit
finish pending commands and release channels. Explicit host Limits still bound
these native waits; a default10-second host operation cannot exercise a full
native30-second timeout.

The source P3 active interpreter's low5==4 DID branch now obtains real function14
support chunks from the retained cache before interpreting the selected active
record. Its exported VPW constructor path is tested with actual typed SDK support
traffic and serialized DMCI active bytes for both builds. This is a latent module
branch: the normal phase4 provider selects P4/ActVariable, and P3 ISO rejects
phase4 with C0050003. These checks do not claim a normal P3 phase4 UI route.

Empty targets and the command primary can retain a real management-only
`ProtocolProfile`, including its canonical `None` ECU-database identity. They
need no fabricated ECU resource. Allocated signal metadata and active-record
queries still require an actual `VehicleProfile`; system96 uses management
frames and can run on an empty management-only target. Current owned verification:83 public source-free unittest methods,
Ruff clean, Pyright zero errors. Private original PE checks remain separate.

Original primary and all selected inputs are validated before category deduplication. Mixed builds or a foreign primary cannot disappear when a later matching category overwrites its slot; the readonly review80 counterexample now has an actual typed-communication regression. Duplicate category inputs must also retain the same complete selected source identity.

Run87 retains the first original selected target object. If a later distinct target overwrites that same category, outer serialization raises `UnsupportedRecorderOperation` before VIN I/O; it never substitutes latest-slot metadata for the original buffer pointer. Repeating the exact same target object remains supported. Recovery of serialization of the original overwritten/unpacked buffer remains an explicit open branch, with no invented native DWORD.

P3 active11 retains the interface signal WORD set by native6fa0. CC/CD callback
notifications use it as602 lparam, including after active stop12 or system96;
full interface disposal clears it. A literal serialized13-byte DMCI error record
verifies this binding, separately from the pure DWORD notification mapper.

Mixed-provider multi admission remains open. Private original management inventories
show non-P3 categories with function0F, so absence of that function cannot justify
excluding them. The exported CommandAPI18 `StartMultiMonDesModeAPI` copies every
input ECU/buffer entry into the command list without a provider check in its loop;
ordinary UI admission and the resulting outer primary flags still need tracing.
Current guards are not evidence that native mixed-provider lists are impossible.

Exported mixed-family DMCI multi commands retain one constructor owned by the
primary ECU. Secondary systems emit only address/system setup111/114 and their
selected monitor setup; they do not rerun primary ISO phase validation. Active11
uses the outer primary category flags for service/DID interpretation while
reading records from the addressed ECU. Both12/18 public regressions cover a
phase3 primary and empty phase4 secondary: one actual create, literal active
DMCI bytes, and no spurious function14 SDK support query. Direct J2534
cross-provider constructor/registration admission remains open. This exported
API proof does not assert that ordinary UI can construct arbitrary mixed lists.
