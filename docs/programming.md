# Calibration inspection and offline programming

`python -m unittest discover -s tests -p 'test_calibration.py' -v` and
`python -m unittest discover -s tests -p 'test_programming.py' -v` exercise authored
fixtures and injected faults. Importing these modules does not open a device.

```python
from scripts.calibration import inspect_calibration
from scripts.programming import ProgramPlan, Programmer, SimulatorBackend

report = inspect_calibration(calibration_bytes)
plan = ProgramPlan("synthetic-ECU", "old", "new", (b"authored block",))
backend = SimulatorBackend("synthetic-ECU", "old")
result = Programmer(backend).run(plan)
```

The first API inspects supplied bytes only. The second example programs an
in-memory fake only. A CUW or S-record inspection never creates a programming
plan, approves compatibility, or authorizes vehicle writes.

## Recovered file behavior

The retained Techstream 18 nested CUW installer was statically extracted without
executing its Windows code. Its actual CUW engine establishes:

- The CUW identifier is the 13 bytes `00 43 41 4c 49 42 52 41 54 49 4f 4e 00`.
  Supported outer versions are 1, 3–9, 101–103.
- A big-endian CRC32 and total file length follow the version. CRC32 covers the
  total-length field and everything after it. Each archived record has a
  big-endian 16-bit header length, header bytes, big-endian 32-bit data length,
  big-endian CRC32, then data. Record CRC32 covers its data.
- Attached information uses INI section/key lookups, including `[Format] Version`,
  vehicle counts, CPU type, new calibration IDs, logical blocks and download
  parameters. Metadata version 9 uses a two-byte count; other observed metadata
  versions use a one-byte count. If metadata cannot be interpreted, the inspector
  accepts only an unambiguous checksummed framing interpretation and reports
  metadata as unavailable. CPU and optional auxiliary images remain distinct
  records. Record counts alone do not prove their semantic relationship.
- The native S-record reader supports S0/S1/S2/S3/S5/S7/S8/S9 and verifies byte
  counts, additive complement checksums and declared S5 counts. The host reader
  additionally requires a matching terminator and rejects overlapping addresses,
  mixed address widths and records after termination.
- `crc16` implements the native reflected CRC16 with polynomial 0x8408,
  initial value 0xffff and final complement (the `123456789` check is 0x906e).

`parse_cuw` retains opaque attached data and image records in memory; its report
includes hashes, lengths and header bytes, rather than image contents.
`inspect_attached_metadata` exposes an allowlist of structural fields and omits
security/key fields. Parsing limits are 64 MiB per file, 4096 records, 1 MiB for
INI metadata and bounded section/key/value lengths. Duplicate INI definitions
are rejected. These bounds and extra S-record restrictions are host policies.

`inspect_recovery_info` decodes the native two-character nibble representation
and reads the observed `[RecoveryInfo]` field names,
including one-based CID entries, CPU index, Writing and WritingEndBlock. It does
not open the saved path, certify the saved identities against a vehicle, or turn native
recovery information into an authorized resume checkpoint.

## Injected lifecycle and recovery

`Programmer` requires a supplied backend with `execute(phase, index, plan, timeout)`
and `reconcile(plan, checkpoint, timeout)`. Its authored phases are preflight,
prepare, erase, transfer each block, verify, finish. This order is a simulation
contract; Toyota's family-specific wire requests are not generated.

Plans bind the exact ECU, current and target IDs, block ordering, lengths and
bytes with SHA-256. A checkpoint contains that digest, the next operation, and
whether the operation may have completed without a trusted acknowledgement.
Failures after erase is attempted require recovery. Cancellation is checked
between calls; an already-running backend call must enforce its supplied time
budget. The host also rejects responses arriving after its overall deadline.
It cannot interrupt an uncooperative backend call.

Recovery never blindly replays an uncertain erase or block. The backend must
independently prove whether the uncertain operation completed; only the same
operation or its immediate successor is accepted. The simulator proves the plan,
identity, complete ordered journal and block readback. A new simulator, changed
image, changed identity, forged checkpoint or stale journal is rejected. Recovery
uses the same live fake; persistence is a caller responsibility.

## Coverage boundary

Native wire parity remains incomplete software work. The extracted engine has
separate CAN, SIL, P4/P5, unified, Ethernet, supplier-specific prepare/write/CID
modules, whole/delta/compressed download paths and native recovery
storage. The 2026 engine adds further P6 and supplier-specific paths and uses
split code/companion files. Export names and successful simulator tests do not
establish their complete protocol semantics.

The current inspector validates framing, checksums and a structural metadata
subset. It does not verify signatures, authorization, target hardware IDs,
per-CPU layout, erase ranges, compression/delta semantics or firmware suitability.
Native recovery representation and integrity and all family-specific request/response/retry/status
rules are still software unknowns, not claims blocked only by a missing car.
Physical ECU voltage behavior, timing, power-loss recovery and real adapter
compatibility additionally remain `PHYSICAL_UNCONFIRMED`.

## Recovered ReproStd transfer fragment

`reprostd_download_request(address, size, selector=1)` and
`reprostd_transfer(exchange, ecu, address, data, ...)` implement the bounded native
CUW18 ReproStd download/transfer/exit fragment against an explicitly supplied
`exchange(ecu, request) -> response` fake or replay. There is no transport factory.

The native request is `34 selector 44 address[4] size[4]`, with big-endian address
and size. Observed selectors are 01 (whole/routine), 21 (delta), and 11 (compressed).
The positive 74 response carries its maximum complete message length, capped by
the native implementation at 4095. Two bytes are reserved for the 36 service and
sequence counter. Sequence starts at 1, wraps from 255 to 0, and advances only
following the matching `76 counter`. The fragment ends with 37/77.

The host rejects missing declared length bytes and bounds the fragment to65536
transfer operations. Native length widths1–15, low-nibble bits and optional
positive response parameters are preserved. Wrong acknowledgements, unhandled negative replies,
late replies, exceptions and cancellation stop immediately without retry; after
any exchange attempt, uncertainty requires recovery. Cancellation is checked
between exchanges; the injected exchange must bound its own blocking I/O.
The returned `fragment_completed` state retains `programming_completed: false`.
Preparation, erase, authorization, security, post-write verification and native
recovery are separate contracts. This fragment does not interpret a delta or
compressed payload or establish that the ECU supports it.

Matched `7f <requested-service> 78` response-pending messages are supported with an
explicit `receive(ecu) -> bytes` callback. The request is sent once; subsequent
responses are read without retransmission, matching the native utility. Pending
receives obey cancellation/deadline checks and a host limit of 4096 messages.
Without a receive callback, pending is an explicit failure requiring recovery.
The native optional tester-present-on-pending-timeout action is not emitted by
this fragment; it stops and reports uncertainty.

`reprostd_routine_request(operation, address, size, checksum=..., signature=...)`
returns a request and expected positive response prefix for the native ReproStd
`routine_check`, `erase` and `verify` fragments. Their routine IDs are 10f5,
ff00 and 10f6, with `31 01`, address/size format 44 and `71 01` response prefixes.
Erase has no checksum/signature fields. The other routines require the caller's
original 16- or 256-byte signature, with its two-byte length; checksum is four
provided bytes or the native absent-checksum marker. No signature, password,
seed/key or authentication material is generated. Builders do not transmit.

`reprostd_fingerprint_requests(slot, nonce, tester_info, system_time)`
returns the three recovered pre-block `2e` requests with their `6e` response
prefixes. The caller supplies the resolved native slot 1–16, the original 16-byte nonce, a
32-byte tester field and eight Windows SYSTEMTIME integers. The native tester
record appends 32 zero bytes. The slot-specific DID tables and SYSTEMTIME byte
order were traced through static constructors and the actual writer body.
No current timestamp, tester identity or nonce is invented. Selecting
that slot from a complete calibration/vehicle context remains separate work.


`reprostd_security(exchange, ecu, key_provider, ...)` replays the recovered
27/01 → supplied key → 27/02 fragment. An explicit provider receives the first
16 seed bytes and must return16 authorized key bytes. The module calculates no
key and reports no seed/key values. A missing provider fails before any exchange.

`ReproStdPrepareContext` supplies resolved wake-up and emissions-related delay,
gateway kind/IDs, optional charge-bus control and addressing mode.
`reprostd_prepare_actions(context)` returns the native ordered preparation plan;
`reprostd_prepare(action, exchange, ecu, context, key_provider, ...)` runs it
against explicit fakes/replay callbacks. The platform `action(entry, seconds)`
handles raw J2534 packets, periodic messages, waits, filters, gateway operations
and ignition control. Waits are injected; this module never sleeps or opens I/O.
The central gateway kind must be resolved before execution. Gateway authorization
routines are explicit dependencies; their names do not imply implemented keys.
Session10/02 requires a50/02 response with at least six bytes, then security
follows. Every platform action and session/security exchange has fault injection.
Native delays are additionally bounded by host policy to120000 ms.

`ReproStdSegment` holds resolved image bytes, address and original signature/
checksum. `ReproStdLogicalBlock` supplies method, original nonce and tester/time fingerprint fields, image and
optional routine package. `reprostd_write(action, exchange, ecu, blocks, ...)`
follows the recovered ReproStd block order: fingerprints, optional routine
package download/check, whole/compressed erase, image download and verify.
Delta skips erase; an explicitly absent delta image skips image transfer/verify.
Whole, delta and compressed payload selectors are01,21 and11; routine package
uses01. The host forwards the supplied delta/compressed payload without inventing
a delta reconstruction or decompression algorithm. Native writer does the same.
Transport timeout save/configure/restore are explicit injected actions; configure
uses the recovered CAN frame-size formula. Final hard reset and broadcast
return-to-default-session packets follow successful blocks. Charge-bus finishing
is conditional on supplied context. Uncertainty interrupts immediately, preserving
the logical block/phase; no automatic retry, rollback or resume is authorized.

Preparation/writer completion describes only execution against supplied callbacks.
It retains `programming_completed: false` and `PHYSICAL_UNCONFIRMED`. Generic
`Programmer` checkpoints belong to the authored simulator and cannot authorize
resumption of a native interrupted write. Family dispatch/metadata selection is
provided separately by `scripts.calibration_catalog`; selecting a library is not
proof that all its operations have been reconstructed.

The distinct CUW18 Unified writer is exposed as `UnifiedArea`, `UnifiedProgram`
and `unified_write(action, exchange, ecu, program, ...)`. Its caller supplies
resolved stub/routine/image areas, separate erase geometry, five-byte offset,
original calibration key/nonce, security-property byte and CPU boundary. No key,
nonce or image is generated or included in reports. Pure builders are
`unified_fingerprint_requests`, `unified_download_request` and
`unified_routine_request`.

Unified writes DIDs0203(offset),0201(key),0202(nonce). Download uses
`34 encryption-bit 46 memory-type absolute-address[5] size[4]`, with memory-type1
for stub/routine and0 for image. The encryption bit comes from original security
property bit3; no encryption operation is inferred. Routines use format45 and
IDs10f0(stub check),ff00(erase),10f1(routine check),10f2(image verify).
Five-byte addresses add the supplied offset with carry; overflow is rejected.
Transfer counters/exit use the same independently recovered36/37 framing.
Stub download/check precedes erase, routine download/check and image download/
verify. Only the final CPU in a node resets, stops periodic messages and sends
the two default-session broadcasts. Native50ms wake-up increments are injected;
the host rejects delays not divisible by50 because native decrement-to-zero
would not terminate. Full action/exchange interruption tests cover both CPU
boundary branches. Metadata-to-program selection remains a separate binding step.

Across these runners, host limits cap retained positive response bytes at1MiB
and exchanges at65536, including receive-only response-pending traffic. These
are explicit host bounds, not inferred vehicle limitations.


`UnifiedPrepareContext`, `unified_prepare_actions` and `unified_prepare` expose
Unified preparation separately from ReproStd: software ID22f181, communication
control2881, programming session1002 and security2701 with the supplied
sixteen-byte ECU authorization field. The observed context flag is deliberately
named `native_flag_724`: its semantic name has not been proven. It permits only
the recovered native software-ID exception branch; host cancellation and deadline
failures still stop execution. No authorization response is calculated.
`unified_write(..., each_area=True)` follows the distinct EachArea writer and
rejects mismatched stub/routine/image/erase area counts before callbacks.

`NativeProgrammingChannel` is the shared bounded UDS seam. Its exchange callback
receives `(ecu, request_bytes)`; an optional receive callback receives `(ecu)`
for receive-only NRC78 handling. Matched positive prefixes permit extra native
response parameters. `NativeNegativeResponse` identifies an explicit ECU NRC;
`NativeTransportError(code)` identifies an explicitly supplied native utility
error. A generic Python timeout is never converted to a native timeout code.
Cancellation/deadline checks run after callback success and callback exceptions,
so a callback cannot hide an expired operation by raising a different error.
CAN messages are bounded to4095 bytes, Ethernet UDS to4116. Native old-CAN NRC21
and pending-count behavior is implemented separately in `programming_vendor`.
The shared P5 channel is not silently substituted for that older policy.

`native_data_request` and `decode_native_data` recover the common slave-CID,
P4/P5 assembly, serial and CBEST request/response codecs. Pure decoders do not
suppress communication failures; family runners must apply their own recovered
optional-helper failure policy.

`ethernet_request`, `ethernet_block_size`, `NativeEthernetChannel` and
`ethernet_write` expose the separate CUW18 Ethernet writer. The exchange callback
receives the complete diagnostic TCP frame; receive callbacks return the native
J2534 result `source[2] + target[2] + UDS`, with its TCP header already removed.
The writer filters the supplied logical target and tester0e80. It supports the
native whole-image path; delta/compressed contexts are rejected before I/O.
Only native utility errors9/16 during a transfer block permit the recovered two
retransmissions with the same counter. An arbitrary transport exception stops.
ESW1 target0103 has the recovered finish/reprepare/default-session sequence.
Routing/discovery preparation belongs to the explicitly injected host lifecycle;
no socket is opened by the channel. `programming_cid.ethernet_diagnostic_lifecycle`
provides the independently reconstructed low-level routing lifecycle.

Download timeout restoration runs in `finally`, including interrupted transfers.
Ethernet writer interruption attempts only the recovered periodic/diagnostic
cleanup and records cleanup failure types; it does not invent a reset or resume.
The generic simulator checkpoint remains separate from native recovery state.

`bind_native_logical_records(container)` binds the recovered CUW18 spec03/04
logical-block schema to archived records. It scans existing logical slots1–16,
retains the original nonce and area signatures, and groups CPU indexes by NewCID.
It requires every node to use this schema. The native archive order follows
present Length fields: whole image, whole routine (metadata206 only), delta image,
delta routine, compressed image and compressed routine. The declared archive
count must match exactly. Metadata206 uses raw binary area records whose byte length must match metadata.
Earlier metadata uses the recovered S-record materialization for whole images
and delta/compressed routine packages; delta/compressed images remain binary.
The ordinary CPU/file schema uses the separate `bind_native_cpu_records` binder.

`native_reprostd_blocks(container, node, observed_cids, tester_info, system_time)`
then builds the actual `ReproStdLogicalBlock` inputs consumed by the native writer
runners. Target CID lists are combined per NewCID/CPU, matching the native reader;
every selected CPU requires an explicitly supplied matching CID observation.
Original ReproMethod codes01/05,07/08 and09/0A select whole, delta and compressed
image/package variants. Spec03 uses original CMAC16; spec04 uses original
DigitalSignature256. A missing required package/signature or mismatched geometry
fails before any I/O. Before206, a whole routine package shares the whole image archive and its
metadata selects a separate area from those original S-records. The caller still supplies the observed node/address association,
tester identity and clock fields. Matching a CID does not establish that complete
vehicle association or authorize a real write.

The16-byte fingerprint field is named `nonce`; native metadata tracing proved
that it is the logical block Nonce, rather than NewCID. The old provisional
`calibration_id` name has been removed. Native nonce/key/payload fields are omitted
from dataclass representations and reports.

For exact caller-specific P5 pending policy, `NativeProgrammingChannel` accepts
`pending_response_timeout_seconds`. The timer starts on the first NRC78 and expires
when elapsed seconds meet that explicit limit; zero rejects the first pending
response. Omitting the limit leaves the outer host deadline in force. Initial,
pending-read and restoration J2534 timeout configuration remains an explicit
provider responsibility.

`ethernet_prepare_actions(target, gateway_target=..., wakeup_ms=...)` and
`ethernet_prepare(...)` now expose the native Ethernet preparation sequence:
routing preparation, functional sessions/DTC/communication control, explicit
periodic timing, target programming session and target security. An ESW1 first
gateway additionally uses2721, a supplied256-byte authorization response,2722,
and routines31011011/31031011. The two authorization providers are explicit;
no service key or response is generated. The host `prepare_diag_comm` action
must establish the actual routing lifecycle and retain its resource ownership
across preparation and writing. The runner does not silently treat routing as
established. Native optional ESW1 exception overrides are not inferred from
ordinary Python errors; uncertain exceptions stop the host runner.


`materialize_native_srecord_area` follows the recovered native MakeSendData
selection: the first S1 record is a header, later S1 and all S2/S3 records at or
after the selected address contribute complete payloads in file order. No holes
are padded and no bytes are generated. The host rejects incomplete areas and
record copies that would overrun the declared buffer. Native materialization validates checksums, lengths and bounded termination while
preserving native mixed S1/S2/S3 records and original copy order. The standalone
public S-record inspector retains its stricter uniform-width/nonoverlap policy.


`bind_native_cpu_records` retains original CPU, node, vehicle and area-header
maps and binds their exact embedded image/FlashCode/file record order. It does
not substitute operator geometry. `native_selection_metadata` supplies the
source strings for catalog selection; metadata2/3 historical ECU/CPU names use the recovered native name-to-ID tables,
including the MPC565/SIL compatibility remapping. Metadata1 uses the native caller constructor contact SIL, Vehicle.ECUType
and the first LocationID system word for its original kind lookup. Modern logical rows have the native
empty CPU-type selection string.

`native_unified_program(container, cpu_index, observed_cids,
extended_addressing=...)` builds Unified writer input from the original CPU
OffsetAddress5, SeedKey16, Nonce16, SecurityProperty2 and CPUImage/WriteRoutine/
EraseRoutine headers. All area bytes come from the selected CPU archive using
native MakeSendData. It rejects a target-CID mismatch before any provider call.
The final CPU boundary and wake delay come from the file. FlashCode is not
substituted for an area in that CPU archive.

`native_reprostd_prepare_context`, `native_unified_prepare_context` and
`native_ethernet_prepare_inputs` bind native node IDs, gateways and timing units.
Gateway classification, actual extended addressing and caller flag724 remain
explicit runtime observations. CAN preparation performs the recovered BS0 and
flow-control-filter cleanup even after an uncertain BS enable or interruption;
cleanup receives a fresh bounded budget and records failure without leaking
provider messages.

Unified preparation and writing accept explicit `native_build=12` or18. Build12
uses the recovered older preparation order, always includes the central gateway
in keepalives, has no build18 emissions/gateway/cancel-IG-off additions, and uses
180 seconds for NRC78 elapsed policy. Both builds preserve the caller flag that
permits the native software-ID read exception. Build12 download responses require
7420 and a fixed two-byte capacity; build18 uses the LFID-width nibble. The host
rejects capacities below three in both policies to prevent nonprogress, including
build12's unsafe native case. EachArea is build18 only. No2026 build is aliased to
either policy.

`native_recovery` implements the native ControlCommPhase recovery subflow over
explicit callback, reconnect, PrepareRetry, address-selection and IsFinished
providers. `NativeRecoveryState` retains proven pointer-field offset names rather
than speculative meanings. Callback slot results explicitly update those fields;
no user choice or driver result defaults to success. Build12 and18 have distinct
cancel-IG-off and failed-retry error policies. Both reread the confirmation flags.
A positive native completion probe is required for `recovery_completed`; declining
a reconnect leaves `recovery_required`. A successful prepare retry alone does not
certify completion. Reconnect errors carrying both native fields use
`NativeRecoveryTransportError(code, detail)` and follow the native catch path.
Unknown host exceptions remain uncertain. The native disconnect catch-all is
bounded to typed driver errors at this injected host boundary. This subflow is
separate from simulator checkpoints. The outer and inner caller controllers
compose it explicitly; the internal executable GUI recovery algorithms have
their own source binding.


`native_unified_pending_timeout` binds the native18 CPU P4ServerMaxTime decimal
minutes to seconds, including the source default03 and explicit zero; build12
always uses180 seconds. Native pending elapsed policy compares whole seconds.
An explicitly supplied `pending_timeout_write` provider implements final-true
P5 expiry behavior by writing SID3e without waiting for a response. Unified
preparation/writing expose this as `write_diagnostic`; ordinary host deadline or
cancellation never emits it. `NativePendingTimeout` distinguishes that native
exception from a host deadline, preserving optional software-ID read behavior.

A channel can explicitly raise its response budget up to128MiB for bounded
native readback workflows. With `retain_payload_history=False`, history retains
response hashes and lengths while the actual validated response is returned to
the decoder. The default response budget remains1MiB.

`native_execute` ports the native outer ControlCommPhase.Execute phase dispatch.
Its explicit source-bound phase provider returns `NativeExecuteStep` with the
observed native success, phase and CPU fields. A successful prepare can enter
write in the same invocation. Legacy CPU looping and the next-CPU IG-off break
follow their original catalog/caller flags. `native_modern_phase` supplies the recovered modern prepare/write inner
transitions and node CPU loop. A logical-node writer is invoked once and retains
the native caller CPU pointer; ordinary CPU writers advance through that node.
Recovery failure requires the actual native pointer state rather than an opaque
success snapshot. Saved recovery fields have a separate explicit import contract.
A single module export replay is distinct from this caller controller.

`native_legacy_phase` supplies the recovered ordinary prepare/gateway/write inner
controller. The preparation callback18 remains a numeric enum: the caller tests
only whether it equals2. Gateway dispatch preserves the actual seventh bool*
output; the returned BOOL is adopted only when `gateway_result_valid` is true.
The writer's own CPU bound and the outer Execute CPU bound use their respective
native flag branches. Failed writes enter recovery, then follow the original
active/error/IG-off flags before another attempt. A host deadline, cancellation
and bounded retry count constrain the native loop.

`bind_native_saved_recovery` binds supplied RecoveryInfo bytes to an already
parsed CUW, the explicitly supplied original source-path label, an actual device
list and a valid CPU index. It uses exact path/device comparisons and the first
matching device, without opening a saved path. `NativeSavedRecovery` preserves
`Writing`, `WritingEndBlock` and `UseNewSoftwarePassword` as separate booleans.
`WritingEndBlock` is not a transfer-block number. The INI contains no source hash
or ECU-state attestation; importing it does not authorize a resume or construct a
simulator checkpoint. The remaining GUI recovery-method dispatch is tracked
separately from the implemented ControlCommPhase recovery controller.

The modern CAN runners accept a `channel_factory` with the six positional
`NativeProgrammingChannel` constructor arguments and its keyword policies.
This permits the recovered `VendorP5Channel` to provide native J2534 timeout
save/restore and receive-only driver retries. Modern P5 calls use native minimum
5530ms; Unified18 CPU timing and each ReproStd logical block bind their own
P4ServerMaxTime, while the reset request uses180 seconds. Host deadlines remain
independent. A positive-prefix mismatch raises `NativeUnexpectedResponse`, a
`NativeDiagnosticError`; invalid provider values and host resource limits remain
host validation failures. Optional native software-ID reads suppress only typed
native failures, never arbitrary host exceptions.

The imported Unified builders require populated node metadata from format101 or
later. A pre101 legacy CPU's `node_values` view represents Vehicle fields for
legacy adapters; it must not be used as Unified Node0. The native reader has a
separate node array and the older metadata branch does not populate its modern
node fields. Such an input is rejected before programming providers run.

`native_cid_phase` implements the GetCID caller's vector copy and seventh BOOL*
return. `NativeCIDExportResult` separates that actual BOOL from compatibility:
the modern getters finish normally with true in both builds, even when the
compatibility decision is false or an allowed timeout leaves no IDs. The caller
does not advance phase0 or the CPU index. Existing CID values and flag734 are
explicit inputs and are preserved when the native caller does not overwrite
them. Actual source-typed `native_cuw_code` failures update608/734/5f8; host
cancellation/deadline never manufactures a native code. The original fixed CID
context is bounded to32 strings of31 ASCII bytes before copying.

CUW18 Unified and ReproStd preparation resolve an initially unknown fixed gateway at the original ordered point: after setting previous-send time and wake delay, before authorization and broadcast actions. The injected `judge_reprogramming_gateway` action must run the recovered common helper and return native enum 1 or 2; the remaining actions are selected from that actual result. ReproStd additionally requires the first native gateway mode to be exactly `01` or `02`. Unified uses the original case-sensitive `GatewayDiagID` text comparison against `07505F`; its authorization and mode branches in both builds preserve this comparison. CUW12 never emits the CUW18 classification probe. Imported builders preserve original gateway strings. Failure results retain bounded native domain/code metadata and observed errors through bounded exception chains, including a native failure observed at the same callback boundary as host cancellation. Diagnostic buffers and provider messages are excluded.

The shared metadata reader admits original CUW12 format102 as the native
node/CPU schema. Node counts, CPU rows, image geometry and archive order use
the same bounded CPU binder as format101. The node specification string does not switch102 to a logical schema.
This is distinct from CUW18 logical format103: format102 is explicitly rejected by the logical-block binder.
Original executable dispatch still checks its own exact build admission table
and executable SHA; the CUW18 path rejects102. CUW2026 uses its independent
metadata parser and source descriptors.
