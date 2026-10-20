# Toyota selected-command sessions

`ToyotaSession` executes selected `CommandSpec` objects through injected
`exchange(ecu: str, request: bytes) -> bytes`. Construction/import opens nothing.
An empty request means **receive only**, not a repeated transmission; a transport
adapter must implement that distinction. Replay adapters can raise `NativeStatus`
with the original uint32 status. Raw negative replies remain bytes and are checked
against the selected command contract; they are never converted into guessed UDS
pending/retry semantics.

```python
from scripts.toyota import CommandFrame
from scripts.toyota_session import CommandSpec, ToyotaSession

# Authored synthetic descriptor/response, not a vehicle command recommendation.
session = ToyotaSession(
    lambda ecu, request: bytes.fromhex("58 01 02 00 00"),
    "synthetic-ecu",
    {"dtc": CommandSpec(CommandFrame(bytes.fromhex("18")))},
)
assert session.dtcs("dtc") == [0x0102]
```

Selected profile `frame_records(function_id)` resolves the database join upstream.
Convert each returned `.frame` to `CommandSpec`, retain its `.provenance`, and use
`sequence` for functions with multiple descriptors. Do not choose an arbitrary
first ECU or interpret function IDs as service bytes. `payload_offset` is an
explicit selected response boundary; `check="p5_active"` applies the original Phase5 active reply checks.
`extended=True` uses the native uint16
receive bound rather than the ordinary byte bound. Mask/SID/raw validation modes
are explicit because native command consumers do not all apply the same check.

| Operation | Executed behavior |
| --- | --- |
| `execute`, `sequence` | Selected descriptor transmission and validation; all sequence dependencies checked before transmission |
| `dtcs` | KWP receive-only continuation, zero termination, duplicate elimination, ComSet retry count, exact three-status masking and direct-return exception |
| `dtcs_can` | Counted CAN DTC16, 4096-byte extended receive-until-timeout, and DK count-matched timeout variant |
| `dtcs_psa`, `dtcs_psa_add_ht`, `dtcs_psa_audio`, `parse_psa_dtcs`, `dtcs_dk_iso`, `format_dtc` | Native PSA triples/NoStatus pairs, AddHt stride5, Audio type-nibble/overflow behavior, DK ISO9141 byte codes and native fallback labels |
| `dtcs_p5`, `parse_p5_dtcs`, `StatusRule` | P5 three-byte prefix and DTC24/status groups; selected DB 0x242 mask/expected mapping; duplicate type/status OR |
| `dtc_information` | Selected diagnostic/detail field copies, supplied signature/name, mandatory nonzero highlighting references and DB 0x230 signal fields |
| `data_list`, `scale_signal` | Selected byte/word PID request patch; explicit response payload boundary; native signal bit extraction, numeric conversion and display precision |
| `freeze_support`, `DtcFreeze`, `associate_freeze` | SupFreeze row execution, exact response-mask DTC extraction, minimum frame-number association, history/timestamp cross-list exclusion |
| `ffd_type`, `ffd_existence_flag`, `compare_timestamp`, `order_freeze_samples` | Native P5 FFD record classification, existence flags and type-group/timestamp/odometer ordering for extracted samples |
| `freeze_p3`, `freeze_p5` | Native selected-template patch/exchange/extraction |
| `vin`, `vin_multi` | CAN first result and count-based non-CAN receive aggregation; native three-prefix strip and positional zero handling |
| `poll`, `health_check` | Bounded refreshes and per-ECU result/error/provenance reports; cancellation propagates |
| `active_request_p3`, `active_request_p4`, `active_request_dk`, `active_request_dlc12`, `active_request_psa` | Native ActTest92/Pattern24 interpreter, all thirteen pattern instructions, selected DID support data, protocol-specific headers and repeat key |
| `active_requests_p5`, `active_reply_p5` | Native selected P5 normal/routine start/release SID prefixes, reply checks and numeric state/tick transitions |
| `routine_request_p5`, `routine_status_p5`, `single_routine` | Original single-routine P5 RID/tail packing, status-pattern matching, start/wait/status/wait/release ordering and native rejection/status codes |
| `ActiveTest`, start/status/stop methods | Explicit selected command sequences with ownership, failure cleanup, cancellation cleanup and retryable failed-stop state |

`Limits` bounds exchanges and elapsed time. Each synchronous exchange must have
its own I/O timeout: the host checks its deadline before and after the call but
cannot interrupt a blocked Python callback. Poll cycles share one budget.
Cleanup has a fresh bounded budget and can send the selected stop sequence after
cancellation. A failed stop retains test ownership and `stop_failed`; success
releases ownership. Losing a start response still triggers stop because the
start may already have reached an ECU. These lifecycle decisions are host policy,
not a claim of reproducing the Windows monitor thread scheduler.

`report()` is JSON compatible and carries descriptor provenance, request/reply
hex, receive-only markers and native statuses. Physical state always remains
`PHYSICAL_UNCONFIRMED`. No implementation here authorizes actual actuator writes.

## Native evidence

All addresses are RVAs in local Techstream 18 originals; image base 0x10000000.
Existing CommandCommon evidence/hash anchors remain in `toyota-protocol.md`.
Additional static annotated evidence is private under `analysis/evidence/no-car-2`.
No original DLL was executed.

- CommandCommon `GetKwpDiagCode` 0x75810: retry byte from ComSet+0x0e at
  0x75989; send on initial attempt, receive-only after full chunks at
  0x75a13..0x75a46 and 0x75b84..0x75b96. Status 0x90020323 exits before
  masking (0x75a9a). Status 0x91010009 following a three-code full chunk ends
  successfully (0x75aa6..0x75ab9); terminal masked failure clears all results
  (0x75bb5..0x75bcb, 0x75cbf). Timeout status names are intentionally not inferred.
- CommandCommon `GetCanDiagCode` 0x76240 uses byte 1 as total count and
  DTC16 pairs from byte 2, ending when the accumulated byte-sized count reaches
  it. `GetCanDiagCodeExt` 0x76780 receives up to 4096 bytes and ends on zero
  count/zero code or status 0x91010009 after at least one successful chunk; its
  terminal error masking can clear the list. `GetDkAbsTsOsDiagCode` 0x75d10
  keeps receiving after the count is met and accepts that status only when
  accumulated count equals the last advertised count. GetDiagCodeP4 Execute
  0x105c maps diagnostic types 1/2/3 to database function IDs 0x0a/0x0b/0x0c;
  these are function IDs, not service bytes.
- CommandCommon PSA `GetPSADiagCode` 0x7d380 and V2 0x7e5e0
  consume SID/count then DTC16/status triples; diagnostic type1 excludes
  status>0x28. NoStatus 0x7ead0 consumes DTC16 pairs. Group count is
  floored and truncated to a byte; incomplete tails are ignored. The first
  selected descriptor count>=10 enables overflow descriptors; a terminal
  error in the second descriptor ends successfully. DK ISO9141 0x7ba90
  reads the first selected response payload as byte codes, stopping at zero.
  PSA AddHt0x7dbb0 reads DTC16 at offset2 then stride5, with byte-sized
  floor((length+1)/5) and skips zero entries. Audio0x7e140 reads pairs
  fromoffset2, filters type1/2 by high nibble0x10/0x20, and uses the
  first count>=10 to poll the overflow descriptor until accumulated pair
  count reaches it or native0x90020321 partial reply byte2==0x12.
  Fallback DTC labels use native PCBU category bits and `%04X` lower14
  or `%06X` lower22 formatting; P5 fallback therefore has six hex digits.
- GetDiagCodeP5_DT 0x2910..0x2a9b reads availability byte 2, then starts
  DTC bytes at 3..5 and status at 6, stepping by four. Zero status/type is omitted.
  CommandCommon 0x7c840 combines three big-endian bytes, 0x7c990 maps status
  `(status & mask) == expected` to ORed diagnostic type bits. 0x7ca84 merges
  duplicate type/status. 0x7cfb0 loads DB0x242 selected by each diagnostic type
  bit; row+8 mask and row+9 expected become eight-byte runtime entries.
- GetDiagCodeInfo_DT 0x1730..0x1967 copies diagnostic row+0xc and detail row
  +0/+4/+0xa/+0x10/+0x11. Detail+0xc resolves highlighting DB0x230;
  signal rows copy word+2 and byte+4. String labels use the original getters,
  supplied after selected DB/string lookup rather than decoded by guessing.
- CommandCommon `GetFrzSupport` 0x76d20 and history variants 0x78700/
  0x78d50/0x7a040 patch SupFreeze row+2 into request index2 (length3) or
  index1 (length4). 0x76f96 requires reply length equal mask length;
  0x76fd8..0x77041 extracts first two nonzero masks into DTC16.
  `SetSptFrzNum` 0x776b0 marks matching DTC support and keeps the minimum
  frame number. History 0x78c00/0x79190 suppresses diagnostic type2 if the
  opposite list already supports the same code/frame; timestamp variant
  0x7a480 uses type1 instead. Shared `CompDTC` 0x792b0 checks all three
  fields (code, frame number, supported flag).
- CommandCommon `GetFFDType` 0x82fd0 classifies ordinary record numbers
  1,2,0x10..0x2f,0x30..0x4f,0x50..0x6f; extended 1..14 map to
  0x101..0x10e and 0x10..0xef to high-nibble groups0x210..0x2e0.
  `SetFFDExistFlag` 0x880f0 ORs native bits for types1,2,0x101..0x10e.
  `CompTimeStamp` 0x84d90 compares unsigned timestamp then odometer,
  returning1/2/3. Type table0xb1bf4 groups [1,0x10,0x30], [2,0x50], then
  pairs [0x101,0x210] through [0x10e,0x2e0]; 0x84dd0 sorts timestamps
  ascending within each group. Time-index and absolute timestamp metadata
  construction remain separate open operations.
- GetVIN_DT 0x11a5 takes count from byte 2; 0x1318 requires at least that
  many multi-results; 0x13ae strips three bytes **per result** and 0x143d filters
  zeros only at aggregated indices 0..2. The public API rejects payloads larger
  than the original 255-byte local buffer rather than reproducing an overrun.
- DataMonitorPhase3 0x9e10..0xa4d9 selects ActTest0x20b and Pattern0x20c.
  Header switch 0x9ecb uses protocol-low5; ActTest+0x52 supplies byte 1.
  Four low-first nibbles of word+0x4a dispatch through table at 0xa4dc.
  P4 0xaa30..0xb0f9, DK ISO9141 0x8ef0..0x95b9 and DLC12
  0x58d0..0x5f99 each have all 427 normalized instructions identical to
  this P3 interpreter; private comparison retains local branch offsets and
  imported identities. PSA 0x6690 uses the same pattern vocabulary but
  default header0x30/0x3d, optional DB0x23c row+2 header override and
  status0xc0050443 for unsupported selected DID parameters/zero masked bits.
  Support filtering activates after instruction11, not merely protocol4.
  Instructions 1..13 target 0xa342,0xa1cc,0xa1db,0xa1e7,0xa1e7,
  0xa1f5,0xa20f,0xa22b,0xa342,0xa23a,0xa24c,0xa2c9,0xa30c.
  These emit zero/value/shifted/constant/constant+value/length/auxiliary/high
  bytes or selected support-list expansion/masking. Pattern+0x14 enables
  returned repeat key word+2 (0xa46c). Protocol-low5==7 returns the header only.
- DataListIF `CCommEventPhase5AT::ActiveTestStart` 0xa080 prepends
  SID0x2f (normal) or0x31 (routine) to selected start/release data lists.
  `CheckRcvFrame` 0xa520 checks reply SID0x6f with length>=3 for normal
  or0x71 length>=1 for routine. Normal control3 schedules native state3
  at tick+repeat (uint32 wrap) orstate4 when period0; control0 moves
  tostate4/5 depending on following items. Routine control1 moves tostate4;
  control2 tostate4/5. Other controls retain state1. These are numeric
  native queue states, not inferred diagnostic service labels.
- SingleRoutineActTstP5_DT 0x15a3 writes RID high/low at request 2/3
  and appends the selected routine-command variable. 0x110e..0x1155 executes
  start, Sleep(200), status, Sleep(5000), release; the injected wait callback
  preserves ordering without real waits in offline tests. 0x161b..0x1634 maps
  native status 0x90020321 with partial reply byte2==0x22 to 0xa0040207.
  Status 0x18dd requires selected display-data length+4; 0x193c..0x198e
  assembles status after a four-byte prefix. 0x1cd0 loads DB0x248 and compares
  low16 against each selected variable pattern; mismatch is 0xa004020d.
  Python preserves failed release as an error, where shipped 0x1c2f..0x1c59
  discards its communication result. Failed start/status and failed cleanup
  both remain available through a BaseExceptionGroup.
- StartActTst/StopActTst Execute 0x1010 delegate to
  `CDataMonitorCtrl::DataMonitorRun`; they do not prove a universal wire command.

The scoped private original corpus check joined all 9,316 active-test rows to
patterns across 676 regional P3/P4 database files. Every pair executed the
recovered interpreter using injected synthetic DID support. A broader scan of
1,422 regional databases found 13,719 pairs: 12,382 executed and 1,337 reached
explicit native invalid-pattern status0xc0050102; that scan includes tables
outside the selected monitor family. It is negative-corpus evidence, not proof
that every retained database row is a supported command. This proves those static row layouts and
pattern coverage, not live success or coverage of different monitor families.
Authored replay/failure tests cover native status paths, continued receive,
scaling, active patterns, failed-stop retry, cancellation and deadlines.

Sienna Door uses `dtcs_can(..., sienna=True)` for an explicitly selected
native descriptor. CommandCommon 0x7faa6..0x7fb7a preserves the first five reply
bytes, then removes offsets0/1 from each following group of six before reading
DTC16 pairs. It continues receive-only after a nonzero count, even when the
number of pairs reaches that count. Zero count/code terminates; timeout after
an empty prior pair chunk succeeds, while timeout after actual pairs fails
(0x7fa23..0x7fa37). SID/short-reply failures and retry rules retain native status.
This selected single-descriptor engine does not infer the native optional
multi-descriptor selector from a generic ECU name.

Cancellation/deadline checks run after every exchange exit, including native
status exceptions, callback exceptions and invalid return types. A native error
remains in the trace when host policy takes precedence.

The P5 active path also provides explicit native argument and queue APIs:

```python
start, release, repeat = active_arguments_p5(
    selected_act_row, selected_data_id_rows, selected_start_frame.request,
    selected_release_frame.request, value, selected_data_length, selected_pattern,
)
queue = P5ActiveQueue()
queue.enqueue(start[1:], release[1:], repeat_ms=repeat)
session.start_p5_active(queue, now_ms=0)
session.p5_active_step(now_ms=25)
session.stop_active_test()
```

`active_arguments_p5` ports DataMonitorPhase5_DT 0xd3e0: DB0x244 row
DID word+0x34, bit bounds words+0x28/+0x2a; DB0x243 byte+0x0a selects
mode0/1/3/4. Mode0 writes a raw value and appends ordinal output masks;
mode3 omits masks; mode1 writes a single-byte bit value or explicit byte mask;
mode4 shifts across bytes and appends the full selected range mask.
DB0x243 ordinal/byte-position/width words+4/+6/+8 select masks. Function0x9d
and0x64 templates must have four bytes; repeat comes from selected DB0x20c
pattern word+2 when byte+0x14 is set. The selected ECU data length is required.
The original special-protocol maximum and cached-length lookup remain profile
selection responsibilities. Native local masks have256 bytes; malformed ranges
are rejected before I/O instead of reproducing native out-of-bounds writes.

`routine_arguments_p5` ports 0xe1b0 using DB0x247 RID word+0x1c,
function0xd5/0xd6 templates and the three explicitly selected routine variables.
It preserves OR overlay, skips zero mask entries when consuming scalar/byte
arguments, indexes button bytes by mask position, and preserves the native
transmitted-length preference (command, then value mask, then button mask).
Pass `routine=True` when enqueuing its resulting buffers after stripping SID.

`P5ActiveQueue` ports DataListIF 0xa080/0xa430/0x13f90 and the repeat-due
comparison in Phase5 ThreadMain0x12419. Starts retain native numeric states;
release buffers are kept separately, deduplicated by DID or RID and spliced in
on stop. Different normal DIDs conflict when a repeat period is present.
Native unsigned tick comparison is preserved, including behavior at uint32 wrap.
Host argument preflight is atomic; appending starts during release is rejected.
`start_p5_active`, `p5_active_step`, `active_test_status` and `stop_active_test`
share the session cancellation/deadline policy. Failed release retains its
current request for explicit retry, and a cancelled start still releases.

The P5 original-row corpus joined3356 active rows in106 database files;
all3356 executed after correcting native ordinal0 mask packing. Its headers,
scalar value and same-DID maximum lengths are injected test inputs. It validates
record/codec coverage and preserves input hashes, without proving selected
profile exceptions or wire success.

`absolute_time_values` consumes selected signal-to-PID joins and extracted raw
uint32 values. Original0x1c5b0 validates all eight BCD nibbles; P5 range checks
at0x83f51..0x84021 use six descriptors at0xb1cb4: signals0x3c..0x41,
maximum38/12/31/23/59/59 and minimum0/1/1/0/0/0. Invalid components are
omitted. No year epoch or calendar correction is inferred. `ffd_type` accepts
`subaru=True` for the separate0x8bbb0 ordinary/extended number mapping.

`p5_data_id_samples` ports the selected-row extraction in Common0x873b0:
DB0x23e flag byte+0x20 bit1 enables the row, PID word+0x24, physical key+0x2a,
bit bounds+0x2c/+0x2e, pattern key+0x32 and selector+0x3a. It requires explicit
PID support, skips unsupported/too-short rows and retains first selected PID
record semantics. It uses the shared native renderer; missing symbolic labels
remain unresolved. Raw metadata fields+4/+8/+0xc/+0x10 remain separately named,
without assuming a P5 threshold caller bridge. `parse_p5_freeze` and
`freeze_p5_data` accept an explicit `decode(did, payload)` callback to attach
these decoded samples.

Subaru has two distinct packet families: `freeze_subaru_stored` ports
Common0x88fc0, with a two-byte prefix followed by repeated record-number,
DTC24, ignored native status and DID count. `freeze_subaru_snapshot` ports
0x8abf0, using the six-byte DTC/status prefix then ordinary-number/DID-count
records. Both use selected DB0x23d byte lengths, duplicate-DID filtering and
the original request-number!=0xff zero-count fallback. Raw wire numbers and
native `(number-0x7f)&0xff` indices are both preserved. The optional decoder
is shared. Raw status does not imply a recovered DTC status classification.

`index_freeze_samples` and `apply_freeze_time_indices` port0x85510/0x85da0
for explicitly paired timestamp/odometer samples and one associated signal
list. The16 groups are `[1,0x10,0x30]`, `[2,0x50]`, then fourteen anchor/
companion pairs0x101/0x210 through0x10e/0x2e0. A group needs its anchor before
retaining companion timestamps. Stable type-order precedes equal time/odo ties.
The first anchor gets index0; distinct adjacent time/odo values increment or
decrement signed-byte indices. Equal pairs share an index. Without paired
clocks, only the first anchor in each signal list gets0. Full display ordering
and absolute metadata construction still require their remaining integration.

`read_monitor_initial_p5` and `read_active_initial_p5` port GetActTstInitP5_DT
0x2200/0x24e0. Each requires a single selected function0xca descriptor, patches
request bytes1/2 with row DID word+0x36 (monitor) or+0x34 (active), strips a
three-byte reply prefix and extracts the corresponding bit range. Native
short data remains status0xa0040202; cancellation/deadline always propagate.

`routine_initial_status_p5` probes a selected function0xd7 descriptor with RID
in bytes2/3. Native wire/SID failures return false; Subaru status0x90020321
with partial reply byte2 equal0x24/0x33 returns true. A successful response
must contain the selected pattern payload plus its four-byte native prefix.
Missing descriptors and host cancellation/deadline propagate.

`read_ecu_p3`/`read_ecu_p4` use the selected function0x6b frame and patch
byte1 from Freeze.byte0x4f. P3 strips the full request length; P4 copies from
that same position with native `(reply_length-2)&0xff` compressed length.
`expand_supported_pid` reconstructs P4 data from explicitly selected cached
byte-position flags: zero inserts0, nonzero consumes one response byte.
`freeze_p4` selects function0x11, patches frame number/PID into bytes1/3 and
copies `(reply_length-4)&0xff` bytes from `request_length-2` before expansion.
Host checks reject native buffer underflow and invalid selected bounds.

`read_initial_p3`/`read_initial_p4` take the selected Freeze84 and PhyData24
records and return native `GetValue`: raw extraction followed by affine
conversion. Display selector and decimal precision do not affect this value.
P4 additionally requires its selected cached position flags.

Legacy freeze windows are family-specific. `freeze_no_frame_number` uses
the selected cached PID length to accept either the full three-byte prefix or
the omitted frame-number echo. `freeze_dk_roof` patches byte1=1/byte3=number
and copies from response byte2 for `reply_length-request_length-2` bytes.
`freeze_dk_abs` patches byte1=number/byte3=PID and removes a two-byte prefix
and trailer. `freeze_psa` patches PID plus frame number or selected DTC16,
then removes the two-byte response prefix. All validate selected signal bounds.
`freeze_dk` reads one selected frame for a successful cached series and uses
`parse_dk_freeze` to retain sequential PID groups and native byte-sized offsets.
Repeated rows for the same PID share its byte window; moving to another PID
advances by the preceding selected PID length. Native wire failures propagate.
`freeze_cgw` consumes already selected DTC/SignalCheck/Freeze rows and explicit
function support, returns payloads by input-row index and skips the ten native
CGW statuses. Its operation-local cache preserves successful raw responses and
the two native cached negative statuses. Cancellation and one shared deadline/
exchange budget cover the complete batch.

`freeze_multi_p3` strips the request-length prefix from each accepted packet
before concatenating. After a valid packet it receives without retransmission
until native timeout0x91010009 completes the operation. Before any valid packet,
selected retries resend;0x90020323 remains immediately fatal. A different error
after a valid packet stops without resending. The host rejects aggregates beyond
the original fixed255-byte signal buffer.

`read_routine_data` ports `GetRIDReceiveData`0x6b0f0 for an explicitly selected
function0xcc/0xd7 frame. It patches RID bytes2/3, preserves the template tail,
appends supplied command bytes and removes the four-byte reply prefix. A reply
containing exactly that prefix returns empty data. This primitive does not
replace the separate native RID support/probe analysis or timestamp assembly.

`routine_support_bit` implements the native high-byte/low-byte RID support maps.
The original out-of-bounds `index==count` read is rejected explicitly.
`routine_data_no_enable_list` executes selected command0xcc/status0xd7 frames
in native flag order: bit1 high-byte probe, bit2 low-byte probe, bit4 command,
bit8 selected row's WORD20/22 extraction. Failed support ends the sequence.
Its phase/value/payload fields retain each completed stage; support is unknown
when no support probe was selected. One deadline/exchange budget covers all
stages, and identical successful requests share the operation-local cache.

Specialized native frame helpers always check positive SID and received length,
including when a supplied descriptor selects raw host handling. Additional
selected mask checks run after the native wire validation. CGW stores successful
wire replies before selected signal extraction; a malformed SID is never cached.

`P5ActiveQueue(dual=True)` also records the native DualBase last communication
tick after each valid response. Invalid SID/short responses do not update it.
The wire queue transitions match ordinary P5; the outer Dual scheduler is
still a separate unresolved contract.

`dtcs_tesla` requires selected support data: at least57 bytes, the first57 all
0xff. It reads exactly19 three-byte codes from a response of at least59 bytes,
retaining duplicates and order. `TeslaDtcDefinition` supplies a selected
DB0x231 row and resolved signature/name/comment strings. Its visibility byte
is respected unless the native context override `include_hidden=True` is
selected. Unknown codes use the original six-digit uppercase HEX signature
and `???` name. Both expanded24-bit and underlying16-bit codes are returned.

`assemble_absolute_log` validates the original twelve saved-log components,
using routine IDs1..12 or PID IDs0x8f..0x9a. It preserves selected order and
last duplicate component, rejects width-specific invalid log/counter values,
and applies the native individual ranges without inventing calendar correction.
`decode_bcd32` checks all eight nibbles and returns native A0040208 for an
invalid digit.

`read_absolute_routine_logs(command_name, status_name, log_numbers, components)`
executes selected and already support-checked CommRidData36 components. Each
component supplies `(logical_id, selected_row, bcd_flag)`. The native RID0x1104
command carries the low16 log bits in big-endian order; the full32-bit log number
remains the comparison key. Each log gets a fresh successful-frame cache;
components extract WORD20/22 bit ranges from the selected D7 reply. Invalid
components or native wire/BCD errors omit that log and continue with the next.
Cancellation, deadline and exchange budget failures propagate. Returned component
IDs retain neutral names where native semantic labels have not been proven.
This helper does not replace support selection or original display metadata.

`read_comm_pid(name, record44, category_type, positions=None, bcd=False)`
ports the selected CommPidData read path. Exact category types0x14/0x15/0x34
use function0xca and the row's WORD34 DID in request bytes1/2; other types use
function0x6b and BYTE39 PID in request byte1. The ordinary branch requires
selected cached support positions. Both branches preserve the original fixed
protocol count versus full-template copy offset; unsafe original overreads are
rejected. WORD20/22 selects the returned raw bits. Selected transport routing
(including the row's bus byte38) belongs to the injected ECU/descriptor binding.

`LegacyActiveQueue(family="ordinary"|"dk"|"psa")` ports the DataListIF active
event algorithms. `enqueue(data, repeat_ms=...)` receives builder bytes after
its SID for ordinary/DK, and the complete builder frame for PSA. Ordinary
prepends0x30; DK prepends0x3d. Ordinary operates on the head, while native
DK/PSA send/check operations use the tail. `send_frame(now_ms)` and
`accept(reply, now_ms)` expose the original event operations and states.
Ordinary `next_request` includes the proven MultiMon state gate; DK/PSA outer
scheduler gates remain the lifecycle owner's responsibility.

Ordinary `stop(initialize=...)` queues0x30 and preserves the initialization
flag. PSA derives its0x11 release control from the current repeated frame and
waits until at least50 native ticks after the last reply. DK stop is a local
worker lifecycle event and emits no diagnostic frame; calling queue stop as
though it produced a release PDU is rejected. `legacy_active_step(queue, tick)`
performs one bounded injected exchange with the native reply validator. Its
caller owns driver stop and scheduling, including cleanup after errors.

`comm_signal_data(record, raw, routine=False, unit="")` preserves the original
CommPidData/CommRidData SetData conversion fields: signed coefficients0/4/8,
selected width20/22, forced selector2, family-specific precision/sign/native58,
cleared names and threshold fields, and one raw MultiData item. The unit is
resolved from the selected database string getter by the caller. Shared native
rendering supplies value/display; raw data and neutral native fields remain
available for saved-log metadata assembly.

`comm_did_request` and `send_comm_did` port selected CommDidData24/function0x9d
command assembly. They append the selected mode/control bytes, insert zero bytes
for supported positions around the supplied command, and preserve the native
three-byte reply with byte2==0 rejection (`A0040207`). WORD2 belongs to target
category/support selection and is never mistaken for a wire DID.

`read_absolute_pid_logs` ports the selected category0x04 saved-log loop: the
logical setter2 receives the low16 log number, then logical components0x8f..0x9a
read cached ordinary PID responses. Only the original ten communication/status
codes omit a log. A masked setter failure still reads its components before
omission. BCD error `A0040208` and setter rejection `A0040207` propagate in this
PID path; the routine path omits native read/BCD failures. One deadline/exchange
budget covers setter and all component reads, with a fresh successful-response
cache for each log. Full export routing must first select/support-check all
twelve components; native BCD flags are true only for normalized components3..8.
The export's input-copy stage preserves the first metadata row for each unique
raw log number before either reading loop.

`NativeFrameSend(operation, command_id, request, parameter4, parameter5,
parameter6=0, parameter7=1)` preserves the literal seven arguments of native
`CCommFrameCtrl` sends. `SendInt`/`SendIntNoInit` use a byte request length;
`SendIntNoInitNoSession`/`SendIntExtDualMon` use a ushort length. `.arguments`
includes the derived length in ABI position3. Argument4/5 retain neutral names
because their meanings depend on the original caller. Inject `native_send`
into the session and call `native_frame_sends(calls, ignore_status=True)` for
native loops that explicitly ignore returned statuses, such as Mazda clear.
The provider returns an explicit uint32 status. These calls never receive or
infer success from an empty response. A single operation budget covers the
whole sequence; cancellation, deadline, provider exceptions and exhausted
budgets propagate even when native statuses are ignored. Six-argument NULL
initialization calls are a different ABI and are not coerced into this model.

`parse_dk_iso_freeze` ports the selected FreezePid/Pid length groups after the
first reply byte. Duplicate PID groups preserve the first value, as native
SignalDataMap.GetData scans from its head. `freeze_dk_iso` sends all selected
function0x11 frames, then parses the first response. `dk_iso_freeze_value`
extracts selected Freeze84 bit ranges. DK ISO transport checks receive length
1..255 without imposing a positive SID and retries every native codec status
up to the explicitly selected retry count, including `90020323`.

P5 DataIdForAct ordinal0 follows native signed division toward zero: it
sets bit0 of mask byte0, the same mask position as ordinal8. Ordinals beyond
the native256-byte mask buffer remain invalid.

`diagnostic_sequence(names, mode16)` ports the temporary native diagnostic-mode
chronology around ordinary frames. Inject `native_get_mode(ecu) -> bytes16` and
`native_set_mode(ecu, bytes16) -> None`. The sequence copies the old mode,
installs the selected mode, sends the selected frames, then restores the old
mode even after cancellation or a native error. Restore has its own bounded
cleanup budget. If both operation and restoration fail, both errors survive in
a `BaseExceptionGroup`. CARB mode metadata joins and DifferentAddress's
`91010009` fallback remain the workflow caller's responsibility.

`count_dtcs` implements plain, P4, AC, TT and VGRS native count wrappers.
`count_dtcs_profile` resolves actual function7/8/9 rows through the selected
profile and reads the first selected settings record's retry byte14. Frames
are tried in native source order only while they return `91010009`. Plain
reads reply byte2, P4 byte1, AC byte3 for type2 and byte2 otherwise. TT accepts
only types1/2 and returns byte2 for length3, byte3 for length4, zero for larger
replies. VGRS reads byte2 then drains receive-only calls until `91010009`,
ignoring other native receive statuses under the operation budget. All-absent
status is `90040501` for plain/AC/VGRS and `91010009` for P4/TT. Other native
errors stop immediately after selected retries; ordinary `90020323` bypasses
retry. Results retain diagnostic type, count, selected frame index and, where
native writes it, the low byte cached in shared slot0x0d.

`diagnostic_scope(mode_factory)` preserves fault ordering for address wrappers:
get/copy the old mode, run the selected DB mode producer, install, then yield
for frame selection and execution. Mode-producer failure performs no install
or restore; frame-selection failure after installation still restores. An
optional `native_cleanup_set_mode` provider allows workflow-wide forward
budget checks to remain separate from the bounded restoration cleanup.

`dtcs_dk_iso_profile(profile, function_id)` sends every selected frame with its
selected ComSet retry byte, then parses only the first full response bytewise
until zero. `count_dtcs_dk_iso_profile(profile, diagnostic_type)` uses native
function7 unconditionally and reports the low byte of the DTC
list length, preserving the supplied native WORD diagnostic type.

`dtcs_profile(profile, function_id)` runs the original selected KWP frame
chain. Unmasked failures advance to the next frame while preserving accumulated
codes and receive-only state; the native byte argument passed from cached
slot0x0d is unused by this helper. `count_dtcs_with_codes_profile` first reads
function7/8/9, then function0x0a/0x0b/0x0c, replacing the preliminary count with
the low byte of the actual DTC list length under one shared budget.

`count_dtcs_os_eng_profile` reads selected function7/8 count bytes2/3. A zero
count or type2 returns immediately; type1 probes exact one-frame function0x7d
then0x7e against their selected masks/checks. A first match preserves count;
a second match also sets `native_40_idling=1`; two mismatches clear the count.
First-probe `91010009`/`90020323` invokes native InitEcu: an observed connection
cache bus is required, then literal `SendInt(category, NULL, 0, timeout, bus,
1, 1)` is sent with ignored native status and no receive. `NativeFrameSend`
represents that NULL pointer explicitly as `request=None`, distinct from empty
bytes. Its `.arguments` retains derived length0 and all seven ABI arguments.

`multi_freeze_info(profile, functions, support_cache=...)` ports Common445d0.
It uses the selected ECU CommEcuData12 kind1/2/3 records, actual PID support
masks/enabled lengths, then function0x6b raw-bit reads. Missing records fall
back to function-cache values `(1,6,4/5/6)`; missing function values are
`C0040601`. Unsupported fields preserve unwritten outputs as `None`.
`read_comm_ecu_p4` exposes the selected raw DWORD helper separately.

`freeze_diagnostic_code_profile` ports function6 request-number patching and
masked WORD extraction. `freeze_support_profile` ports basic SupFreeze
association: exactly one function6 frame, selected DB202 rows in source order,
selected retries, no-response skipping and minimum supported frame number.

`dtcs_without_count_profile` ports `GetDiagCode_woCount`: a successful ordinary
count stage is mandatory, but a zero count still leads to the KWP read.
Nonempty codes query `(1,4,3)` before optional basic FFD association.
`dtcs_can_profile(..., family="p4_v2"|"carb_can")` selects functions0x0a/0x0b/0x0c.
Both use native frame index0 without advancing to later selected frames.
P4V2 omits FFD for type3 and uses its native FFD mask2; CARBCAN uses extended
receive and checks FFD for every diagnostic type with mask0.

`freeze_p4` accepts either observed `positions` or a concrete
`support_cache`. With deferred support, it receives/caches the data first,
then calls `support_bits(1)` and expands the selected PID. Missing PID support
is `C0040001`; cancellation/deadline checks run after producer errors too.
`stop_active_test(now_ms=...)` retains the observed uint32 release tick in
Dual P5 queue timestamps, including cleanup after a step error.

`dtcs_dlc12_profile(profile, client)` selects exactly one function0x0a frame
and calls an explicit `NativeVimClient` with command0x307f. Its three payload
bytes are the selected send BYTE0 and receive-mask WORD0. It reads the literal
native status plus CCmdBuffer envelope, copies the low-byte count, and preserves
duplicate BYTE DTCs and zero. Native NAK transport statuses use
ComTol04320 mapping; reply-object statuses remain literal. No ordinary
exchange, USB discovery or implicit connection is substituted for this ABI.

`freeze_operation_p4` ports Common23850/function0xe4. It patches number/PID
bytes1/3 and replaces byte2 only when the supplied control is nonzero. It
retains the P4 cached receive, late support discovery and bit extraction.

`dtc_metadata_profile` ports selected DB205 visibility and string projection.
It preserves FIRST matching code in source order; BYTE26 zero suppresses the
entry unless explicitly overridden. Signature is the inline UTF16 field,
name/comment use language IDs at bytes12/16. Missing code and lookup mode1
retain the native fallback. KWP/CAN/DK ISO/DLC12 profile APIs project each
code before append and preserve duplicate entries.

`dtcs_carb_profile` uses function7's masked count (`reply[2] & mask[2]`),
skips the read for count0, then reads function0x0a and optional basic FFD.
`dtcs_os_eng_profile` retains the count/probe sequence, forces current request
`13 00 00`, and reads exactly `ceil(count/3)` replies. Zero codes do not stop
that fixed loop. Positive preliminary count still reaches the FFD gate when
all received codes are zero. `dtcs_no_frame_number_profile` keeps the mandatory
count stage but reads even after count0; its FFD decoder requires exactly4/5
bytes and takes the last two bytes without a selected receive mask.

`freeze_cgw_profile` follows selected DTCGroup/SignalGroup/SignalCheck rows,
then the FIRST Freeze signal match with native PID wildcard. Flag78 bit2 and
function `(1,4,3)` gate each row. Data receive and actual support discovery
precede concrete `selected_freeze_metadata`/LSB; only the native ten data-read
statuses omit a row, while metadata errors stop the operation. Results retain
record, payload, metadata, raw DWORD and affine value. `dtcs_dk_cgw_profile`
omits FFD for type3; other types use the single SupFreeze number and mark each
DTC when its second appended signal has a nonzero value.

`dtcs_dk_at_profile` checks FFD for all types after nonempty CAN codes. It
reselects the diagnostic function before literal NULL initialization, preserving
ignored send status and connection-cache errors. The single function6 and
single SupFreeze drive two identical requests; each reply needs at least
sendlength+2 bytes and uses its last two bytes as code. Newly associated entries
from the second pass retain native label `"1"` in `freeze_labels`.

`NativeFrameSend` additionally represents `SendIntExt` and `SendIntNoInitExt`
with ushort request bounds; native source-build12 no-session BYTE truncation
is rejected at the concrete communication boundary.

`dtcs_plain_profile` selects the actual command0x13 count DLL through DB113,
including native FIRST-command fallback when the category group is absent.
All eight original selected count module names dispatch to their recovered
implementations. The cloned count type is WORD; the outer type is checked as
DWORD after positive count and shared0D lookup. Count0 skips the KWP read.
A count implementation that leaves shared0D unwritten requires its explicit
existing byte observation before the read.

`dtcs_can_profile(family="p4")` preserves basic FFD mask0; P4V2 uses mask2.
Family `"dk"` uses ordinary CAN and checks FFD for every type, decoding the
last two response bytes with minimum length sendlength+2. The DK ISO wrapper
`dtcs_dk_iso_wrapper_profile` reads raw byte DTCs, then the single function6
reply BYTE0 and associates frame number0; it does not query SupFreeze.

`decode_comm_pid_reply` is the shared pure Common1B880 decoder for an actual
patched6B/CA request/reply. It validates SID/bounds, preserves native fixed
prefix counts and sendlength copy offsets, expands ordinary PID support,
then extracts the selected DWORD. Explicit `bcd=True` adds the distinct
Common1C500 conversion; ordinary GetPidData uses the default `False`.

`CommandSpec.selected` retains the actual selected frame, function row and settings.
The optional `ToyotaSession(native_transaction=...)` receives `(ecu, spec, request)`
for `execute`/`sequence` and native ordinary/extended transactions. Patched
requests retain selected identity. This typed callback executes the complete
Common transaction, including selected ComSet retries. Session helpers therefore
invoke it once; the raw exchange path retains its native retry loops.
The same exchange budget, cancellation,
deadline and native-status trace apply. Optional `native_cleanup_transaction`
uses the same signature for an explicit fresh bounded cleanup provider; it
allows a lower adapter to release active state after ordinary cancellation.
Raw receive-only continuations keep
using `exchange(ecu, b"")`; an empty receive is never converted to initialization.
`routine_data_no_enable_list(response_cache=...)` can share successful probe/
status replies across ordered components within one selected context; callers
must use a fresh cache when the target or frame/settings context changes.
Public `read_comm_pid` accepts operation-local `response_cache` and
`begin_operation`, for ordered component reads within an existing budget.
Each cache belongs to one actual selected target/frame/settings context. For
ordinary PID reads, `positions=None, support_cache=...` sends/caches data
first, then discovers support via `support_bits(1)` and row BYTE39. Extended
14/15/34 reads do not query PID support. Wire failures skip support discovery.

`dtc_information_profile` implements selected legacy DB205 + DetailCode +
HighlightingSignalInfo and P5 DB241 metadata. It preserves hidden-match fallback
suppression, uppercase unknown-code validation, per-item partial output and the
last native helper status. Output fields without proven UI meanings remain
neutral raw fields. Invalid host language data raises a format exception;
malformed-language native error overwrite behavior is not certified.

`dtcs_psa_profile` supports plain, V2 and no-status selected wrappers. Duplicate
DTCs remain in native order. V2 counts all nonzero DTCs before status/visibility
filtering, saturates at256 and uses that count for descending numbered FFD.
A zero overflow header returns before writing that native count. The alternate
FFD mode patches each DTC into the request; the plain mode checks one unpatched
reply. Request bounds and wire failure behavior follow each separate helper.

`dtc_status_rules_profile(profile, requested_types)` selects DB242 groups for
individual bits of the full uint32 request, from low to high. The request mask
ORs row expected bytes; a zero mask does not commit rules. Passing `None` uses
the separate all-record cache loader, whose empty table is C0040101.
`parse_p5_dtcs` ignores incomplete trailing groups using native integer division.
These primitives do not substitute for the full P5 outer FFD workflow.

`read_p5_diagnostic_reply_profile` implements the P5 local2570 request stage.
It selects DB242 first and skips all later work for a zero request mask. CD
uses its first frame, preserves the Subaru2DA/2DB AF override, checks native
`pbCancel==1` as A0040003, requires the observed connection bus and carries native receive
capacity through `CommandSpec.receive_capacity` (bus14 FFFF, otherwise1000).
Its ten masked communication statuses leave `read_succeeded=False`; other
native failures propagate. Explicit `source_build=12` follows the separate
original12 stage: no Subaru category/AF query, no connection-cache requirement
or bus14 capacity override; capacity1000/groups3FF. This stage precedes the
full outer FFD association.

`dtc_metadata_p5_profile` implements Common7C9E0 selected DB241 metadata,
visibility and seven-character fallback. `analyze_p5_diagnostic_reply_profile`
implements local2910 ordered entry handling: empty/short, over-capacity and
unavailable-status responses succeed with an empty list. Both metadata loaders
resolve every string field in the matching contiguous DTC group before FIRST
row visibility, matching native SetRecString; unrelated groups are not hydrated. Existing codes merge
status/type before another metadata query. If the rule cache is empty,
`requested_types` supplies the actual availability reload context; a native
loader failure leaves availability zero. This differs from the stricter raw
`parse_p5_dtcs` validation policy.

`freeze_legacy_profile` executes selected plain, MultiRcv, Dk, Dk_AT,
Dk_Abs, Dk_Roof, PSA and NoFrmNo FFD wrappers. Distinct normal/freeze support
lists are produced before DB210 selection, and actual wire data precedes
selected metadata and SignalLSB. Dk/AT preserve native BYTE sorting and atomic
final copy; other families retain completed output on later failure. Dk_AT
performs its native NULL initialization and at most two DTC comparisons before
reading the selected freeze rows. Roof is original18 only. NoFrmNo retains
normal request number/PID patches; its support reply header is2or3 bytes based
on the selected base PID length, using the concrete support cache producer.

`freeze_dk_iso_profile` requires the concrete NativeCommunication and its
SignalLSB cache. It sends all selected function11 frames through execute_raw,
then interprets the first raw reply without positive-SID validation. Selected
DB214 FreezePid supplies lengths before DB206 normal PID fallback. Missing
required tables raise their native status. Both original builds register the
same FreezePid correspondence geometry; original regional corpora contain no
slot20 payload, so the selected-row tests use authored vectors.

`freeze_p4_profile` preserves support-mask creation before enabled-freeze-PID
creation, selected signal order, tolerated wire errors, then the conditional
multi-frame postprocessing. Its signed circular high-nibble mapping traverses
20,10,00,F0 when bounds cross zero, omitting high00 from wire reads. It keeps
the native alias marker and retains completed signals in a supplied output
mapping when a later function lookup fails.

`p5_freeze_existence_profile` creates ordered CE DTC/record associations and
prunes extended records whose prerequisite1/2 is absent. The separate
`p5_predictive_freeze_profile` uses CF and literal records10/12 with existing
DTC-only analysis; it is distinct from EachP5's D0 predictive protocol.
`p5_stored_freeze_profile` performs initial D0 then native fallback selectors,
captures before parsing, and merges a concrete temporary P5FreezeState through
the shared native merge implementation. The typed `stored_all` marker follows
the captured request selector FF, including overwrite/reset of an existing DTC;
it is copied after extended record numbers and before timestamp merging. `p5_diagnostics_core_profile` joins
initial CD analysis, CE, concrete EachP5 analysis-only consumption, stored D0,
and final display sorting/flag updates/removal within one budget. Original18
Subaru dispatch uses category BYTE72 high bits20 or category26B: stored113 first
(except26B), collected-frame count gates CE8880 and CF snapshot fallback.
Snapshot analysis decorates existing diagnostics without creating new ones.
`dtcs_p5_profile` supplies the exported original18 conditional log14 lifecycle;
original12 has no logging/Subaru/bus14-large-reply overrides. Body failures take
precedence over logging failures. All masked communication phases return native
A004020B. The original18 bus14 path has a runnable 1024-DTC selected CE→Each→77
regression, beyond the ordinary3FF bound.

Selected Freeze20A queries eagerly resolve every matching row's name through
Language before checking visibility. CGW resolves only its actual contiguous
signal group; ISO preserves its earlier raw exchange and PID-map creation.
P5 CD analysis commits each diagnostic and duplicate status/type merge directly
to the shared state, so a later metadata failure retains completed output.
Finalization sorts all diagnostics first, then updates flags and removes each
empty diagnostic immediately. Original12 CE and D0 do not require the connection
cache lookup introduced in18; D0 cancellation precedes that18 lookup.

CGW accepts an explicit `output` sink in both `freeze_cgw_profile` (a list) and
`dtcs_dk_cgw_profile` (a mapping). A later failure leaves completed records and
DTC associations available there. Successful calls retain their existing return
shape. `dtcs_can` publishes each metadata-successful code and DtcFreeze directly
to its optional output mapping, including failures during the initial DTC read.
Selected initial CAN DTC exchanges preserve the concrete CommandSpec and Common
retry ownership. The concrete workflow retains its NativeCommunication for
receive-only continuations: actual SupportReceive uses the selected timeout,
255/4096 capacity, argument5 zero and native wait flag100 (ordinary bus0C:200).
Initial Common attempts consume the same retry budget used by later receive-only
errors; continuations never send an empty frame. Both-build typed regressions
cover multiple packets, later errors, exhausted initial retries and cancellation.
This does not certify every application facade or native CAN branch.

## Unresolved native families

G2/G3 remain **OPEN** for original equivalence. Leaf2 still needs complete
independent P5 DTC outer and source-build/dependency review of the new selected
wrappers. P5 FFD/time-index/absolute codecs alone do not certify
their full selected outer workflows. Monitor integration, concrete shared
support, lower transport and global SavedLog orchestration are owned by their
separate modules and need their own gate evidence. These are software proof
gaps with local binaries available. Raw `execute` does not close them.
DB205 metadata and count dispatch were checked against both original corpora;
this does not certify every native export or communication dependency.

Run `python -m unittest discover -s tests -p test_toyota_session.py -v`, Ruff and
Pyright for the two authored Python files. Original-corpus evidence stays private.

CommEcuData support and raw P4 reads accept fields wider than32 bits, following
the paired native extractor's DWORD OR and modulo32 shifts. They retain selected
payload bounds: unsupported out-of-range support fields return false; raw reads
report their bounds error after the selected wire exchange. This does not widen
other record families without their own native-source proof.
