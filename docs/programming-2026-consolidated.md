# CUW2026 consolidated legacy engine

`programming_2026_consolidated` binds the exact registered
`TCUWLegacyCIDGettersAndFlashWriters.dll` source identity. It does not select a
CUW12/18 implementation by filename or by a similar CPU/family name.

The recovered export is `Execute` at RVA13170. Its controller constructor at
RVA c410 installs the vtable at RVA2caa4. Context+978 chooses normal CID lookup
(vtable+4, RVA dcf0) or the writer path (vtable+8, RVA c670). Context+738 supplies
the selected CPU to the writer path. The normal path stores context+9c4 through
RVA c660. The source uses native threads and callbacks; an injected host need
not reproduce Windows threads to preserve the business operation order.

`select_branch` implements the source's literal comparisons and precedence for
all seven primary getter constructors and ten writer constructors. SIL EMPS
selection uses CPU0; SIL M16C writing first tests the selected CPU. CAN kind4
selects the old ECB writer only when the controller's actual ECB ROM callback
has set its old-specification state. Unknown combinations fail with native
error9999. String normalization or a generic default family would change this
behavior and is deliberately absent.

The source has an additional reachable ECB ROM getter: the kind4 software-ID
worker's callback at RVA c570 constructs RVA15110, whose worker is RVA151d0.
This is not one of the seven direct getter allocations in RVA dcf0.

## Implemented primitive consumers

The following operations execute actual recovered wire requests using
`NativeRuntime2026` and injected J2534 primitives:

- CAN EMPS PS2: protocol6, native2000ms initial wait, `aa1e`, exact10-byte
  response beginning `ea1e`, eight-byte ROM text. Native pending-response
  handling accepts149 pending messages and sends `3e02` on the150th before
  reporting error3. Its timeout changes and filter lifecycle are preserved.
- CAN ElectricPowerControl: protocol6, `1a81`, native `5a` response prefix and
  five-byte software ID. The concrete2026 CanDiag exchange matches the
  consolidated helper's request/pending/busy/timeout/response checks.
- ECB ROM fallback: protocol6, native2000ms wait, two `a4` ROM reads with
  selectors0 and2, `e4` replies and eight-byte ROM values. Calling this routine
  alone does not claim that the enclosing software-ID fallback controller ran.
- CAN software ID: exact kind-dependent table order, selector discovery with
  `1a8800`, per-selector `1a88` reads, extended-address block-size changes, and
  actual kind4 error fallback through the ECB ROM getter. Successful fallback
  sets both native controller state flags. The native request-ID output records
  and separate software-ID/CAN-route records remain available in controller
  state, including duplicate request records for multiple IDs from one node.
- SIL CID: the four native OBD2/MOBD/Phase4OBD/Phase4 attempts, five-baud versus
  FAST_INIT setup, engine/ECT/HV targets, four-chunk CID assembly and partial
  result preservation across failed protocol attempts.
- SIL EMPS, occupant and VPNS: actual FAST_INIT modes, source delays and
  diagnostic requests; VPNS discovers and reads each software-ID selector.
- Common CAN foundations: exact batched CheckID,76-only memory request, fixed
  wide block operations and source finish variants. Write uses fixed1024-byte
  chunks and verify uses256-byte chunks, both with5ms status waits. The nonfinal
  verify exception path preserves the previous status byte; this is not a third
  completed writer or a whole worker substitute.
- CAN EMPS writing: fixed native loader/image geometry, two boot targets,
  security exchange using explicitly supplied authorized material, loader and
  image download/chunks/checksums, final reset, native error codes, ordered filter
  disposal and source progress notifications. Explicit retry prepares a new
  protocol6 session; it does not replay an image. This writer consumes the
  upstream connected session, as native RVA18950 does.
- SIL EMPS writing: native CPU57/58/59/60 page counts256/240/128/192,
  erase request, raw1028-byte page messages with complemented byte-sum checksum,
  final/nonfinal ACK checks and exact current/previous-page NAK bounds. Raw
  transport9/16 retry reconnects protocol3 and resumes the current page. Native
  nonrecoverable accepted retries wait3000ms and ask again; explicit finite UI
  answer observations preserve this behavior without an opaque operation callback.
  Initial FAST_INIT failure may prepare a replacement session and returns without
  erasing; its separate exception scope is verified from passive MSVC metadata.

- CAN FC writing: actual selected TargetData password (the source constructor passes null password state),
  prior matching software-ID route, security and three `a027` broadcasts,
  `1002` session selection, batched CheckID,76 memory information and native
  firmware/block ranges. Accepted in-block retry reconnects, disposes native
  write-error state and resumes memory discovery without repeating preparation
  or CheckID. Accepted errors outside block operations prepare a replacement
  session only. Native finish/filter catch-all scopes preserve the worker BOOL;
  host exceptions propagate.
- CAN EPB writing: fixed extended `07502c/07582c` security route with `270100`,
  source zero-padded seed behavior, three `a027` broadcasts and `1002` entry.
  Actual imported selected LocationID/TargetData/image records feed the worker;
  timeout120000 or10000,75 memory info and per-block25 erase/41 write/15 verify
  retain exact native wire order. Native error UI may reconnect protocol6 but
  does not replay the image. Selected counters reset on worker native errors;
  cleanup catch-all scopes retain the native result. No stage-success provider
  replaces these operations.

Electric-control foundations additionally preserve source15ed0's one-byte
seed-minus-one key, source6e70's five separate CheckID writes with four explicit
waits, and exact initialized CPU117 geometry (8KiB,120KiB,120KiB,8KiB). The two
initializer roots and authenticated passive PE data are retained as a separate
private reproducible proof.

`bind_can_electric_writer` binds selected global CPU/TargetData/image and CPU0's
preparation finish address. `write_can_electric` implements15ac0 preparation and
16300's four fixed blocks through75 memory,25 erase,41/45 write,47 inverify,15
verify and80 finish with ACK. It preserves separate3ms CheckID writes and the
first-packet3ms wait. Borrowed+a8/+ac bytes retain last-block/started state; an
error passes the actual+a8 byte into c2e0's password-state rule. A prior started
byte permits the main worker after a typed preparation error. Native main errors
reset the selected progress entries with count then percent notifications;
accepted retry reconnects only. The changed-password branch reads source05150's
actual global Parameter.ini/image DWORD. Unknown native preparation/body faults
and host abort propagate; only native filter cleanup ALL scopes are swallowed.
The full worker and actual imported-image test pass authored controls;
independent source/helper equivalence review is pending.

`ConsolidatedSILM16C2026` implements raw22d40 CheckID,22700 erase,228b0 write,
22b20 verify,11da0 bounded exact-length reads, and22eb0/22fd0 status requests.
These messages have no SIL diagnostic header/checksum. Excess bytes in a native
read are discarded;9/16 read faults become the helper's false return while other
native/host faults propagate. The source passes fixed256 as the percentage
calculation denominator, so successive write/verify pages can report above100;
the primitive preserves that behavior.

`bind_sil_m16c_writer` binds actual global per-CPU targets and archives, preserving
selected CPU17 and searching the first other CPU17/18 for native preparation.
The full22040 worker sets9600baud/parity0, uses10ad0's timing70/80 and exact10-byte
FAST_INIT, selects native programming mode0 and checks the selected CPU password.
It erases three fixed8KiB areas atFA000/FC000/FE000 and writes/verifies each256-byte
page using the selected imported archive. A missing otherCPU follows the native
error/retry path without programming. The distinct CSetBaudRateException subtype
maps to prepare error5; CJ/CPass errors retain their enum and unknown native
exceptions preserve the initialized error0. Write-phase native errors reset the
selected count/percentage without extra progress callbacks. Accepted retry only
prepares a replacement protocol3 session. The timeout2000 assignment precedes
the state5 cleanup scope; only later faults emit the native1000 reset. Host
faults/cancellation propagate. Independent actual47→51→48 replay verifies the
positive full worker and boot-helper message contracts; whole-module review and
whole-worker independent review remains open.

`bind_can_old_ecb_writer` consumes the actual successful old-ROM fallback flags,
request-record count and all selected per-CPU archives/TargetData. `write_can_old_ecb`
executes selector0/2 security preparation, fixed-node9 duplicate records, all CPUs
from the selected index,120000 timeout,76 memory, old-table ranges and actual
wide block erase/write/inverify/verify. A65/ACK hands off between CPUs and the last
CPU sends80 with its own finish address. Native range failures retain exactly
1ec50's immediately previous range count (not a cumulative sum), update the
password byte from the actual last-range flag and expose finite retry answers.
Accepted retry reconnects6, executes05/ACK65/ACK disposal and resumes the same
CPU/range through CheckID and memory discovery. Actual ROM observations→imported
CUW→writer and distinct multiple-CPU image/location checks pass; independent
whole-worker exception and metadata review remains pending.

`ConsolidatedSILFlash2026` now supplies shared raw programming/boot primitives
under the M16C specialization, plus literal35/25/47 block operations,119c0 status
retry and11700/11865 memory75→76 discovery. Unknown format is probed once and
retained; the native75 read catch-all falls back while host faults propagate.
The six literal CPU-probe names and nine alternate CPU pairs are recovered from
ed70/eec0/ed10 and initializer3820; a bounded passive register-assignment proof
verifies all nine pairs. `bind_sil_writer` and `write_sil` now implement the full base10eb0 selected
CPU/TargetData/archive workflow, classic and shrink transfers, actual firmware
checks and runtime CPU remapping through the initialized pairs. Source121f0
executes100 programming-mode calls,100 memory reads and100 blank checks per baud
candidate9600/9800/10000; these repetitions are native behavior. Its first-mode
FF retry and blank-failure05/readone cleanup are preserved. Write packets use
four256-byte messages, exact send/receive timeout changes and native ACK Boolean
handling. Raw verification's nonfinal CPass status catch skips to the next packet,
unlike the CAN retained-status path. The native normal callback is selected
before flashing; a write failure can therefore retain `completion_callback=normal`
while `writer_completed` is false and the native error enum remains present.
Native write/prepare retry state and host cancellation remain distinct.

Classic, shrink, CPU4→12 discovery and actual imported CUW→wire controls pass.
The full base worker remains an independent-review candidate.

CAN target selection in this binary comes from the internal table at RVA2c4c8
and the selection routine at RVA9ff0. These three getters use fixed native table
rows: EMPS node15 (`07a1/07a9`), ElectricPowerControl node55 (`07c1/07c9`), ECB
node9 (`07b0/07b8`). Their two-byte values are expanded with two leading zero
bytes by native CBytes sizing. Arbitrary catalog or observation addresses cannot
replace these source-bound targets.

`bind_native_context` parses the actual CUW2026 metadata and chooses the first
CPU and vehicle contact/kind fields before constructing any of the seven
primary getter consumers. It accepts no filename/geometry/target override.
Tests include authored CUW envelopes whose imported metadata reaches actual
primitive requests. Explicit low-level context construction is available for
injected tests and requires the exact native table values.

`bind_can_emps_writer` imports actual2026 archive records and validates their
fixed native address/length constraints. Modern node formats101+ remain rejected
at this writer boundary until their selected-image mapping is audited.
`bind_sil_emps_writer` binds the first native CPU archive and its separate
`FlashSize`. The source writes the CPU's fixed page prefix and uses `FlashSize`
as the progress denominator; safe extra backing is retained, while short backing
is rejected. `FlashSize=0` remains outside the accepted host contract pending
the native floating-point conversion behavior. Historical multi-CPU metadata
continues to use the global first archive, and mutable modern node projection
can reach these binders after native `SetCPUType`; neither path selects an archive
by the active CPU index. CAN EMPS likewise transfers safe prefixes from native
loader `length` and image `FlashSize`, while retaining its fixed advertised
download geometry. These bounded cases do not claim support for every archive
format.
`bind_can_fc_writer` and `bind_can_epb_writer` read actual selected global CPU,
TargetData, LocationID and materialized archive records. Only explicit authorized
security conversion material is attached; image/address/password overrides are
rejected. EPB dispatch tests the first CPU while its firmware/geometry checks use
the actual selected CPU. Streamed archives still require their byte producer.

Only source-proved pure codecs and typed contracts are shared with older implementations.
The batched check-ID frame codec is used after proving consolidated6970 ordering.
The source-equivalent2026 ACK/status contracts are reused without replacing
consolidated fixed delays, wide ranges or exception mappings.
Pure software-ID parsing is shared with the older implementation. Source
RVA1fbb0/26100 independently proves the sixteen-byte copy, NUL termination and
trailing-space behavior. The twelve-byte truncation kinds in RVA1fbb0 are
unreachable from this controller's software-ID selection kinds4/5/6/7/13/51.
No older plugin supplies consolidated orchestration or transport business logic.

All resources acquired by these consumers are released after malformed replies,
transport faults, cancellation and normal completion. The host runtime enforces
finite deadlines, message/call/resource bounds and cancellation between primitive
calls. Providers must honor the supplied remaining deadline. Returned identifier
text retains native NUL termination; original image/key material is never logged.

The EMPS worker exception boundaries are checked against authenticated passive
FuncInfo (`runtime/no-car-51/emps-eh-proof.py`). CAN initial ControlIO35=2 is
outside worker catches. Its one filter-cleanup ALL scope skips remaining filters
after a native fault and preserves the callback BOOL; host cleanup attempts the
other filter before propagating. CAN18820 and SIL20820 retry routines swallow
native disconnect exceptions, catch only CJ connect failures and ask again.
A non-CJ native connect exception propagates without worker timeout restoration.
CAN exposes actual post-disposal `error_code` and causal `initial_error_code`.
SIL's initial FAST_INIT scope catches CJ plus ALL, so CPass/unknown ALL retain the
initialized zero error. Erase/page ALL also retain the current enum. SIL's60000
receive timeout and20000 send timeout lie outside worker EH. Host faults retain
explicit bounded cleanup and propagate. Neither timeout-restore failure becomes
a successful writer result.

## Complete branch candidates and review boundary

All ten reachable writer families now have authored primitive implementations,
including chassis and occupant/VPNS. `bind_can_chassis_writer`/`write_can_chassis`
implement13760/14100: fixed7b0/7b8 selector preparations,100ms key delay and
threeA027 messages per selector, source CPU-specific batched/separate CheckID,
3000ms worker timeout,76 memory, initialized old CPU ranges, multi-CPU65/ACK
handoff,80 finish and phase-specific reconnect-only error handling. CPU68's
initial skipped blocks become zero-length prefixes, as native14e70 inserts.
Borrowed counter resets have no observer calls. Native finish/filter catch-all
preserves the normal completion callback; host faults propagate.

`bind_sil_occupant_writer`/`write_sil_occupant` implement23580/247e0. Both kind37
and63 execute actual diagnostic FAST_INIT/security/session23620 before the
worker's native catch scope. Kind37 then emits five raw boot writes, reads17
bytes and uses native baud discovery. Kind63 uses70/170 programming FAST_INIT,
the27-row CRT3d00 firmware table, raw80/ACK finish and timeout restoration.
Security24290 uses the two-byte seed complement/add; VPNS13360 performs six
sequential in-place rotate/add updates. Firmware metadata and selected archives
are actual imported data. Native write faults set the borrowed started byte;
typed native catches reset progress, unknown native catch-all retains it.
The passive table proof is `runtime/no-car-51/vpns-table-proof.py`.

`ConsolidatedExecute2026` represents one retained DLL controller. Its first call
validates the actual global Parameter.ini's31 P5-Unified defaults and selects
kind/firstCPU/contact keys once. Later calls preserve that parameter selection,
ECB ROM state, password/range flags and CPU progress vectors. The required
shared `CommonDefinitions2026` provides native `num_cpu_maxnum` capacity at
first controller creation; current imported CPU count can be smaller. Caller978 chooses
vtable+4 getter or+8 writer;738/73c supply the selected global CPU and exact
TargetData index vector. Recovery980 is passed only into source consumers.
The05e80/05d70 thread rendezvous is synchronous in this offline implementation;
workers still execute their full primitive protocols. Native normal/error
completion determines the HOST projection `execute_return` of the completion
byte, including base SIL's early normal callback selection. Authenticated raw PE and the actual CUW caller prove
an eight-bit Boolean return in AL; no 32-bit Win32 BOOL contract is claimed. Worker results expose separate native enum and driver-error slots: CJ catches
copy the driver DWORD, CPass/ALL retain it, and source accepted clear-error retries
clear both. Export132ca records the exact754 enum,974 failure and744 abort fields
while retaining caller758 driver state. `error_snapshot(code, driver)` observes
the actual c340 error notification before retry UI, independently of later
internal slot resets. Thus CJ9 followed by an accepted retry and unhandled
connect CPass13 yields caller754=13/caller758=9. Reports expose these caller
slots separately from the worker's internal enum/driver slots. Host faults and cancellation propagate. No injected operation
claims an entire stage succeeded.

These are complete branch candidates, not independent equivalence acceptance.
Gate51:G2 and Gate51:G3 await parent acceptance of the retained source/EH and
actual-input evidence. All ten writer families have positive Execute routing
controls, and final independent review reported no remaining concrete finding
in its audited scope. Physical vehicle behavior remains `PHYSICAL_UNCONFIRMED`.

The original1045-function C source omitted sixteen CRT initializer roots. All
sixteen now have exact retained manual ASM with authenticated body hashes.
Three CPU-table roots additionally have independent semantic assignment review;
the other thirteen have bounded CFG/library-boundary review. This does not
assert broader initialization semantics. Cold PE table pointers are not runtime
initialized values. The `consolidated_firmware_matches`, `consolidated_block_ranges`
and `consolidated_block_sizes` helpers preserve these source rules without
substituting newer FlashUtils geometry or normalizing CPU text.

Native callback cancellation and host abort are distinct. Native helper returns
can retain pending data or produce an empty CID from zeroed output; source guards
choose whether to append. Only successful ECB completion sets old-spec flags.
SIL native `ReadMsgs` consumes an indication before the data read; FAST_INIT's
extra drain uses raw `WrapReadMsgs`. A successful empty getter reply maps to its
native error, while the SIL EMPS erase accepts zero status from zeroed Data.
Secondary ECT native failure is swallowed after the primary CID succeeds.
VPNS errors retain prior successful IDs in `partial_identifiers` on the original
exception subtype. A later empty ID maps to native3, while all-space ID text
retains its first space exactly as the source trim loop does.
The common CAN memory request preserves context+6c after its first ACK even on
later descriptor failure; downstream writer state retains that format selection.

Run the authored checks with
`python -m unittest discover -s tests -p test_programming_2026_consolidated.py -v`.
Private retained source, passive PE vtable/target proofs and body hashes are not
redistributed with this implementation.

Raw SIL operation catches match the native CJ-only outer scopes: a plain CPass4
from status framing remains4 through blank/erase/inverify/write/verify instead
of being remapped to each operation's error. The119c0 read catch retries any
CPass up to three attempts; the preceding50 write is outside that retry scope.
FAST_INIT indication16 consults the actual J2534 `get_can_frame_padding` state;
padding true drains an additional raw message, false skips it.

CAN progress snapshots publish the native whole vector before each user callback,
including the actual active CPU during multi-CPU writes. Electric and occupant
workers share the controller's borrowed last-range byte; host cleanup failures
retain the flags already mutated by primitive work.

Getter workers use their own CJ/CPass/ALL scopes and fresh working CID/enum/driver
slots. Their final `Disconnect` lies outside those scopes. `Execute` therefore
reports a caught getter failure with native error completion and caller974/744
false; an unhandled final disconnect fault reaches the export catch instead.
All eight final slot12 Boolean observations select normal/cancel callbacks before
disconnect. This is authenticated ASM behavior; the split Ghidra C functions omit
the live register selection. Cancellation retains completed IDs without selecting
normal completion.

CAN getters append IDs before `StopFilter`: a native filter-release fault retains
the completed CID. Software-ID detailed routes append per ID; request rows append
only after the complete node helper returns. A second-selector fault therefore
retains the first CID/detailed route and no request rows for that failed node.
After a successful parent disconnect, supported runtime handle snapshots retire
invalidated filter ownership, including an unreturned handle left by failed
cancellation rollback. These bookkeeping operations issue no extra device calls.

Mutable CAN progress vectors are borrowed from the retained controller. Silent
chassis resets therefore remain visible even if final cleanup raises before a
worker report is returned. M16C's silent reset updates the same retained scalar
state through a state observer without issuing a user progress callback.
The base SIL final-mode partial-ID exception retains the original CJ driver slot.

`runtime/no-car-51/execute-return-proof.py` passively authenticates the original
CUW caller's loaded `Execute` pointer, four stack arguments, returned AL to BL
copy and normal/error callback selection. It also proves the consolidated
completion-byte return and epilogue preservation. This establishes an eight-bit
Boolean return; it does not establish a 32-bit Win32 `BOOL` type. Independent55 confirmed
the same original caller, epilogue and callback-selection byte windows.

`runtime/no-car-51/check_execute_routing_matrix.py` reruns eight literal fixtures
through the actual retained Execute root. It changes only each authored fixture's
root call, preserving imported containers, primitive queues and assertions; no
production function is patched. FC first produces its software-ID route through
the same retained Execute instance. OldECB/chassis retain their actual
getter-produced typed state. Independent55 reran this matrix and also verified
CAN EMPS, base SIL and Electric Execute positives, covering every writer family.
