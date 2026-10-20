# Selected PSA monitoring

`scripts.monitor_psa` reads selected `VehicleProfile` records and constructs native
monitor metadata, typed DMCI commands, and the PSA polling state. It opens no
network, adapter, or browser. Every communication boundary requires an explicit
primitive provider or raw byte exchange.

`selected_psa_from_transaction` obtains Mode35 and ValidIdExt data through the
shared `MonitorSupportCache`, preserving the complete typed `SupportQuery` with
selected CommFrame, timer/settings record, native parameter, and source identity.
It then calls `selected_psa_monitor`. `selected_psa_from_exchange` is a compatibility
adapter for a caller that has already bound those transport settings; a two-argument
raw byte exchange alone does not prove that binding. `selected_psa_monitor` also accepts explicit support observations for offline
inspection. Boolean function observations
must include every capability query reached by native PSA01890; absence is an
error. The detailed function2/70 observation is explicit. Common support entrypoints
accept `source_build=12|18` (default18), independently of the selected DDB format;
callers select the native Common algorithm build explicitly when using12. There is no assumed
availability, login, automatic adapter contact, or default SLD request.

The resulting `SelectedPSAMonitor` contains `definitions`, `packing`, `signals`,
`frame_sizes`, `commands`, `addition_frames`, and an immutable complete profile
`source_identity`. The full ComTol join checks ECU/management hashes, exact
category bytes, category identity, and exceptions before constructing commands. Its `event()` creates the native
DataListIF PSA DataMonType1 event. `psa_monitor_cycle` runs one complete packet
through `MonitorProvider.send/receive`, with an aggregate call budget, deadline,
and cancellation checks before and after each primitive. A foreign response
address continues receiving without resending. Native hard negative statuses and
retry exhaustion preserve the native callback code and bounded detail byte.

The basic setup requires an explicitly preconfigured `interface_id`.
`psa_comtol_commands(profile, selected, bus_id)` adds the actual native ComTol
interface lifecycle: source-selected CAN500000 baudrate, CreatePSA0x115,
CreateDM0x107 phase2, IDMap0x111, and DeleteDM0x108/DeleteDiag0x104 cleanup.
`psa_comtol_identity` derives the request and peer identities from selected
ProtInfo and the exact bus4A/5A address transformations; mismatched setup identity
is rejected. These operations still require an explicit byte-exchange client. The command plan
contains SetPSADataMonitor0x10A, optional SetAdditionFrameSnd0x117, start0x10C,
and stop0x10E. The basic plan leaves interface creation/deletion to the caller; the full ComTol
plan includes those commands. Neutral commands
feed `NativeDmciCommand.from_neutral` and `NativeVimClient.dmci`. The actual wire
commands are 0x167F, 0x277F, 0x187F, and 0x1A7F. Selected metadata feeds
`native_monitor_buffer(profile.category, plan.signals, plan.frame_sizes,
plan.definitions.selected_ids, ...)`; allocation, phase, name, and text encoding
are explicit caller values.

Native PSA mode1/mode2 builders are error stubs. Mode0x100 is rejected by setup;
the direct J2534 PSA event admits mode0x20 only. Mode0x10 can produce native setup
commands, but `event()` rejects it with E0000102. Dynamic Mode35 position overrides
follow Freeze flagBYTE78 and modeBYTE77. Selected trigger records supply SLD
frames through table19, FuncCommFrame, CommFrame, and variable data. Additional
options use the first selected table55 PID match and actual raw CommFrame bytes.
Repeated frame keys use the first descriptor, as native16e0 does.

Malformed descriptors with absent or unequal ID/length arrays are rejected before
I/O. Native code could otherwise read zero-filled or uninitialized descriptor
slots; this implementation does not fabricate a successful pair. Input item,
PID, option, receive, and frame bounds remain explicit host limits.

The public tests create fresh authored DDBs and traverse actual profile parsing,
selected metadata, Mode21 encoding, DMCI byte exchange, and polling packets. They
do not require proprietary input or use mocked native business operations.

## Evidence and remaining acceptance work

Private `analysis/evidence/no-car-44/native-version-audit.json` binds the original
12/18 module identities and static instruction ranges. Normalized differences are
a review aid, not a proof of equivalence: imported names and referenced data
addresses are normalized, while error constants and external code RVAs remain.
The real PatDisp12/18 field delta is implemented in shared metadata selection.
`schema-review.json` independently confirms consumed table3/6/55/19 overlay
geometry in both versions.

`check_psa_measurement` binds CheckDataMonitor eligibility to selected protocol,
Freeze rows, and the actual shared support producer. `check_psa_multi` implements
the native up-to-three-target exclusion-mask choice and proportional allocation,
with an aggregate deadline and exchange budget across targets. Voltage33a0 checks
exactly one selected Freeze geometry and supplies its native fixed descriptor.
These checks calculate eligibility and geometry; they do not create an adapter.

The authored integration test serializes the complete selected ComTol plan into
a native DRS, captures three real decoded monitor packets with
`NativeMonitorRecorder`, and injects faults at each setup/start/read/stop stage.
Cleanup attempts stop, DeleteDM, and DeleteDiag in order while preserving the
primary exception.

`PSAJ2534Monitor` binds the full selected context, request/receive identities and
worker timers. Construction performs setup; `start()`, `poll()` and `stop()` retain
the native event-signal transitions. After stop, `setup()` is required before a
new start because native stop clears the setup notification. Calls into caller
clock, cancellation or provider code occur outside the state lock; overlapping
polls fail immediately. The complete source context is checked around caller
callbacks and primitives; a management reload fails before the next operation.
Stop is observed at native request-ready boundaries, while an ongoing retry or
receive continues to that boundary. `PSAMonitorStopped` reports a stopped partial
packet without inventing a complete one. Cancellation/error prevents polling
until explicit reset.

`psa_j2534_frame_plan` implements the distinct lowA normal-CAN constructor/header
path, rather than routing it through ordinary `get_comm_frame`. The plan preserves
Open protocol0x1000C, flags0 and separately baud0; outgoing PASSTHRU_MSG uses
ProtocolID6 and TxFlags0. Native1A/4A/5A receive filters retain their exact address
subtractions, and bus2A retains its fifth header byte. Shared `translate_configs`
performs the observed API-version mapping. `decode_psa_j2534_message` strips the
actual four/five-byte header and returns its literal receive address. Both12/18
authored profiles run through this packet path and the monitor lifecycle.

`PSAController` implements the cooperative native command queue for both
ComTol and J2534. Supply exactly one concrete `NativeVimClient` or explicit
J2534 `backend` with observed `driver` and `native_build`. Its command IDs are9 (single Run), A (stop), B (active start), C (active
stop), and38 (multi Run). Other IDs return90050405. `PSARunTarget` supplies actual
profile/signal inputs and a typed support transaction; the controller constructs
the selected metadata and native commands itself. Multi Run registers at most
three category slots. Registration replaces a matching category before any
support producer executes; the last signal list wins and the original slot
position stays fixed. Targets must share
management, exceptions and vehicle-selection context. An explicit `primary`
permits the native zero-system active-only branch. Empty selected lists produce
mode80 without querying support or manufacturing monitor metadata.

Command completion precedes error propagation. Native wait results distinguish
queue, shutdown, timeout and wait failure. Callback reentry fails immediately;
no caller callback runs under a state lock. The actual VIM byte boundary checks
source context after internal client clock/cancellation callbacks. Primitive and
byte budgets cover support, setup and polling. Cleanup has a fresh bounded
budget, attempts every stop/delete command, and preserves the primary failure.
Disposal clears the three native registrations.

`selected_psa_active_operation` selects ActTest or ActTstVariableDrive records,
Pattern, optional CommMode and actual CommFrame bytes. The required
`variable_drive` boolean represents the observed native function3/31 result.
The variable-drive interpreter discovers Mode35 data through the shared support
cache for opcode13 hex; unsupported identifiers and invalid opcodes retain native
failures. Its10F command contains the entire service byte and payload. The
optional phase is the actual global primary protocol phase. `psa_notifications`
implements the native callback-to-window-message table without posting events.

The voltage helpers reuse the same recovered nADMonitor stubs and calibration
algorithm as DLC12. Start/stop return the shipped failure codes; there is no
invented voltage sampler. The selected PSA Run producer rejects nonempty voltage
category68 with C0050004.

`PSAJ2534Provider` joins the actual lowA frame plan to concrete
`NativeFrameOperations` driver primitives. Construction opens nothing; callers
explicitly open and close its channel. `prepare()` models local native allocation
without connecting; the Run controller uses it so the first worker send opens
the retained channel. Native build, observed driver and first
request are required. The authored tests match every primitive and field in the
connect/config/filter/startup/send/receive/disposal chronology for12 and18, and
inject faults at each important stage. Driver operations have no default success
result.

The driver8 Run join preserves the native single shared interface. Transport
uses the first/global category and bus for its entire lifetime; metadata and
packets use the last nonempty monitor setup. Every registered slot updates the
shared IDMap, including an empty mode80 slot. Thus a final empty slot may change
the expected reply peer without replacing the monitor event or primary channel.
The authored literal test covers that distinct peer and rejects the earlier
primary-peer packet. No channel or business result is supplied by default.

Mode80 active tests use the recovered `LegacyActiveQueue("psa")`, including
control/reply validation, repeated requests, the next scheduler turn, and the
50ms stop guard. The native interface rejects active start while a monitor
event exists. It also rejects a second normal start while the active worker is
outstanding; control11 requests stop or emit the already-stopped notification.
The retained worker uses actual `SendIntExt` and `ReceiveExt` through
`NativeCommunication` and concrete `NativeFrameOperations`. Active faults have
no monitor retry; foreign addresses remain in receive state. Stop/disposal
attempts the pending repeated-active stop under a separate bounded cleanup
budget and releases the channel while preserving the primary failure.
Confirmed host cancellation/deadline observations cross the typed lower boundary
as explicit `J2534Result.host_boundary` values. After-call observations preserve
actual result counts; the lower layer validates those counts and ownership
before permitting deferred cleanup. Backend exceptions and invalid counts remain
uncertain faults and poison the channel. The controller owns this deferred lease
and restores it on disposal. Pending repeated-active stop gets fresh primitive
and time budgets, using the last confirmed channel clock plus real monotonic
elapsed time when the acquisition clock fails. No failed clock reading becomes
a successful acquisition observation. Tests cancel after the confirmed repeat
write, exhaust the acquisition budget, fail the acquisition clock, and fail the
pending stop itself; each case preserves the primary error and releases resources.

One absolute polling deadline reaches the actual primitive exchange after all
clock/cancellation callbacks. Lower deadlines are clipped to that parent bound;
a terminal reply completed after the deadline cannot advance queue state,
emit an active success callback, or publish a monitor packet. Fault tests cover
channel setup, startup, monitor receive, callback-consumed time, late replies,
empty mode80 cancellation, and exact filter/disconnect cleanup.

The private PSA worker index binds active-event and interface exports from both
original12/18 DataListIF modules. The producer and wrapper audit separately binds
both original DataMonitorPSA modules. Whole PSA G2/G3 remains open pending
independent review of this expanded Run/controller/scheduler/typed transport
scope. No physical hardware behavior is claimed.
