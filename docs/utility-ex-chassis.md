# UtilityEx NK chassis and smart-key bodies

This workstream remains **OPEN**. The implementation executes 73 shared recovered
business operations for exact NK12, NK18, DS4 and GTSPlus modules, plus thirty-one
ABS35/36/37/38/40/50 operations and forty-one SMRT45/46/47/48/50/53/56/58/63 operations present in NK18/DS4/GTSPlus. It does not implement the
remaining ABS/SMRT bodies or claim complete UtilityEx or vehicle
equivalence.

`scripts.utility_ex_chassis.run_body(export, arguments, context)` returns a native
integer status. Four-byte `bytearray` arguments represent writable native uint32
outputs in little-endian order. Argument validation and the exact module SHA-256
guard run before communication. Unknown operations and unsupported source
identities raise `UnsupportedChassisOperation`, rather than returning success.
The original void timeout-flag setter has the host return convention `0`.

The shared UtilityEx engine owns selected profile/broker context, scheduler,
deadlines, native cancellation and communication objects. This module constructs
requests, interprets replies, repeats native business polling, updates shared
registration state and chooses native cleanup branches. It does not accept a
callback that claims an entire operation succeeded. No device opens on import.

Implemented operations:

- SMRT63 preserves its own6301/6302/6303/6305/6306 classifications, caller
  support6350/6351 and shared caller-driven counter. The body never increments
  the counter;960 maps6304 only after the native pending/cancel branch.
  Pre-cancel invokes one stop/close; pending0 cancellation retains the manager.
  All source helpers were read independently. NK18 direct export aliases were
  confirmed from static PE export slots. Actual NK18 support6351 and erasure/
  poll6306/normalclose raw SDK traces pass through public admission and the actual worker.

- SMRT50 implements all support predicates and the optional5050/5051 caller
  result, retained erasure start, all key-status classifications and direct
  keepalive/end-session exports. Native pre-cancelled reset deliberately makes
  two stop/short-normal/close attempts. Actual NK18 body-to-rawSDK support5051
  and keepalive/start/poll5001/close traces pass through public admission and the actual worker.

- SMRT53 preserves online certification, challenge and seed copies, retained
  manager/keepalive, native4006 without challenge, sticky target extensionB5,
  and send-key close/reset. ASM restores the old helper's successful echo0A
  branch omitted by the decompiler. Caller4003 applies only to the final
  status probe; earlier numeric101 failures write4001. Public worker tests on
  all three exact sources preserve entry-time references across busy wrapper
  overwrite. Actual NK18 public authentication/retain/send raw SDK trace passes.

- SMRT55 implements ConfirmDIDRIDSupport, GetKeyDiagInfo, CHKSupportStatus,
  SetKeyDiag, SetKeyDiag2 and both termination bodies for the exact NK18, DS4
  and GTSPlus images; NK12 has no family55. It preserves the delayed support
  output-pointer read, shared A/B bytes, partial writes, ordered waits and
  retained successful setters. CHKSupportStatus reads the live globals without
  creating a communication manager. TermKeyDiag2 follows the consumed
  zero-argument contract while its formal header ABI remains unknown. Public
  wrapper admission and lower-chain review remain separate gates.

- SMRT56 checks all four DID/RID support predicates, preserves session error
  6000, and retains the initialized manager and keepalive after successful
  fingerprint start. Termination performs no initialize and returns6005 even
  after cancellation. End-session initializes only for argument1. Real NK18
  support and start/retain/terminate raw SDK traces pass. Plus callbacks missing
  from the collector were recovered from exact static bytes.

- SMRT58 executes the complete IFBOX registration routine, keepalive start,
  fifty-millisecond poll waits, unsigned thirty-second deadline and native
  cancellation distinctions. Errors and timeout issue the stop routine before
  normal session cleanup; session return values are intentionally ignored.
  Actual NK18 routine/poll/normal-session raw SDK trace passes. Missing Plus
  callback bodies were recovered from exact static PE bytes.

- SMRT48 implements support, digital-key serial and both VIN branches. VIN
  dispatch uses argument zero independently of the current broker mode. Classic
  VIN preserves three ECU profile probes and target restoration. Fixed VIN
  preserves physical/functional address configuration, the F802 fallback and
  live broker AB save/write/refresh/restore. VIN copies up to seventeen bytes
  without adding a terminator; native partial writes are retained. Actual NK18 raw SDK traces cover functional, physical and F802 fallback
  paths. Other source lower joins and independent review stay OPEN.

- ABS35 support uses separate DID reply offsets and preserves classifications
  1000 through 1004. Solenoid driving executes the full twenty-command,
  thirty-five-second sequence, including distinct cleanup for each active phase.
  Cancellation shortens waits while preserving later commands. Two missing Plus
  callback entries were recovered from original static PE bytes.
- ABS01 solenoid driving preserves its separate 2/8/default-12 masks, strict
  echo in the status-12 branch, initial cancellation result 99, initialize-failure
  mapping to 4 and session retention on every native result. Its mode-four
  type discovery reads state seven, tests 0f/0c/0a support masks and partially
  updates two caller padding counts. Bleeding consumes those counts, preserves
  the 2/8/12 selection masks and retains the session on every native outcome.
  Its ABI takes two arguments on all four sources; old decompiler prototypes
  incorrectly omit the second pointer.
- ABS TRC air bleeding, resurrection, TRC/ABS solenoid driving, and their three
  direct or scheduled stop exports. Requests preserve selection masks, four- or
  five-byte command forms and the native three-byte status-12 branch. Driving
  restores retry/pending defaults after every exchange. Resurrection intentionally
  tolerates subsequent errors after its first successful command.
- ABS03 decompression preserves its repeated solenoid commands, five-second
  activation window, one-second transition, relay drive and final five-second
  delay. Status four skips the cleanup command; cancellation shortens waits but
  preserves subsequent commands. Actuator checking writes one result byte in
  mode four and returns zero without communication in mode three.
- ABS05 direct A8 support discovery writes two uint32 support flags and three
  command padding counts. It preserves the first flag on wire failure, leaves
  the second flag untouched until successful discovery, and retains partial
  counter updates. Invalid native count offsets fail closed within host bounds.
- ABS14 support discovery preserves six A8 masks, partially updated padding counts,
  four-second solenoid activation followed by two-second group driving, exact
  selection mappings and direct stop/relay cleanup. Solenoid status 12 requires
  an echoed three-byte response; relay commands require exactly two bytes.
- ABS15 two-snapshot support discovery preserves statuses 1500/1501, six masks
  and the two padding counts even when masks fail. Five patterns, status-1503
  polling, the 15-second first phase, different cancellation results between
  polling workers, native counter normalization and unconditional execution
  cleanup follow each source. GetSupportInfo has no arguments; StartAirBleeding
  takes one pattern index despite incorrect old decompiler prototypes.
- ABS22 shared-cache support predicates preserve statuses 801/802. Two rounds
  of solenoid commands, 21-second nominal timing, final relay activation and
  short-call stop preserve the native sequence. Replies longer than two bytes
  succeed when their third byte is nonzero; zero returns status 12. Early errors
  finalize without a stop command, and cancellation skips waits while retaining
  the source command sequence.
- ABS25 support discovery uses two shared metadata profiles and statuses
  911/912. Refresh packs its seven-byte request through native support masks.
  Activation checking waits before polling and returns one while pending.
  NK12/NK18 stop on checking failure or cancellation; DS4/GTSPlus omit that
  stop call. Both variants finalize, and the difference is source-bound.
- ABS36 support, ECB prohibition, zero-down drive, dealer/normal mode, motor
  deactivation and delayed routine stop preserve the fixed UDS manager, extended
  session/keepalive contracts, statuses 3600/3601/3603/3604, cleanup flags and
  retained sessions. Motor deactivation copies the complete read response, writes
  service `2e` and byte four `80`, then rereads after one second to verify bit six.
  StopRoutine waits 20 seconds, performs cleanup and returns zero independently
  of the native exchange results. NK12 has no ABS36 exports and fails closed.
- ABS37 refresh start/stop and completion polling preserve cancellation at each
  native request, one-second poll delays, pending states 1001, invalid state 1002
  and normal-session cleanup that stops keepalive only after a successful
  response. The stop operation deliberately ignores initialization status.
- ABS38 five-query support discovery and shared cached payload, ECB/accumulator
  start retention, vacuum-flag read/modify/write and stop preserve statuses
  1200–1206 and writable errno arguments. Vacuum writes require exactly three
  reply bytes; a longer reply fails as in the native assembly.
- ABS40 support-mask metadata and VSC line bleeding execute the six native
  compressed requests, five drive cycles per stage, 1.5-second keepalive,
  42-second stage timing, error-bit aggregation and mutable stage/stop pointers.
  Stages run from 1 through 25 and advance only after all phases succeed. The
  shared native metadata cache belongs to the communication layer. Host polling
  yields one millisecond in the native busy waits; missing metadata fails before
  communication rather than emulating a native null-pointer read.
- ABS50 seven-query support discovery, rear/ECB step transitions, SLM refresh
  polling and vacuum reset preserve statuses 4600–4607 and 4700–4703, retained
  sessions, the rear-stage output and cached reset bytes. Plus additionally
  supports nine mode-22 branches through the distinct `native:101c6da0` manager;
  its vacuum reset rereads and validates the DID before writing a separate cache.
  Support discovery remains mode 20 only.
- SMRT03/08 entry-key counts, registration-mode entry/end, master-key checking and
  completion checking. Polls preserve the shared count baseline, two distinct
  response flags, family-specific count limits and native statuses 100–104.
  Successful mode entry retains the session for later checks.
- Smart-key erase count retrieval, mode entry/end, mode-status polling,
  key-status polling, check and progress-timeout flag. Timeout, cancellation,
  native status 15 and cleanup differ between the worker and exported wrapper;
  these distinctions are preserved.
- SMRT31 support discovery, key-status parsing, registration request and checked
  or unchecked termination. Six polling modes preserve the native 3101–3109
  result mapping, count clamping, output flags and cleanup decisions. Key status
  takes a writable structure of at least 13 bytes: uint32 initialize flag at zero,
  uint32 close flag at four, mode byte at eight and output bytes at 9–12.
  Request/checked termination read a uint32 flag from a caller buffer of at least
  four bytes. Selected Mode2/Mode3 scopes share the exact initialize/send/receive
  vtable slots in each source; later virtual slots are not assumed equivalent.
- SMRT47 independently preserves its own structure offsets, kind-three mask
  20, request `3b8720`, statuses 4700 through 4706 and public `NomalChk` spelling.
  Its mode slot is field one and metadata occupies fields two through five;
  registration checking and cleanup follow their separately audited branches.
- SMRT46 key-code checking preserves the four native query modes, fixed reply
  byte tests, cancellation inside mode two and separate thirty-second statuses
  4600 through 4606. Registration checking writes modes three and four into the
  shared structure with a poll between them. Stop and cleanup branches preserve
  ignored stop replies, initialization-error mapping to 14 and the mode-two
  timeout that intentionally skips stopping. Its support mask differs from SMRT45.
- SMRT45 owner-key registration is present only in NK18/DS4/GTSPlus. It
  preserves support failures 4510/4511 without copying unsupported metadata,
  progress writes 450/451, the four-entry status table and shared internal status.
  The four polling flows preserve their different pending, terminal and stop
  branches across the unsigned thirty-second timeout; all finalize.
- SMRT42 support discovery preserves both metadata kinds, byte-sized record
  copy lengths, partial outputs on mask failure and unconditional metadata append
  after native initialization errors. Its shared argument structure retains fields
  between wrappers. Registration checks and status queries preserve distinct
  session retention and stop branches; key counts use packed support ordinals,
  nibble clamping and the native late pointer read. Erasure preserves the unsigned
  60-second timeout and statuses 3200 through 3204. Busy polling yields one
  millisecond while retaining the zero-once native response buffer.
- SMRT41 certification supports direct reply offsets and shared metadata
  profiles, caller status gating, challenge and seed outputs, timestamps,
  four-second keepalive and key transmission. Metadata append preserves native
  duplicate profiles and its ignored return value; lookup uses the first match.
  Exact source wrappers preserve conditional argument stores before the mode
  guard through the shared engine preparation plan. Workers read those globals
  at the source read points: certification captures output pointers and branch
  flag before initialization, then reads the selected offset or metadata after
  initialization. A public invoke/thread regression preserves concurrent busy
  wrapper overwrites without replacing the worker body. Busy polling yields one
  millisecond on the host; invalid packed ordinals fail within host bounds.
- SMRT32 support-bit discovery, registered-key-count classification, erase-mode
  entry/end, and both key-status polling bodies. The five support requests,
  zero-filled offset-seven boundary, status-3001 session retention, 30-second
  status-3002/3003/3004 classification and cancellation cleanup are preserved.
  NK12 tests the entire low nibble for value four at timeout; later variants
  test bit two. EndEraseMode deliberately ignores the native exchange status,
  restores the short-call flags/defaults and closes the selected communication.
  Its original export takes one unused uint32 argument on NK12/NK18 and no
  arguments on DS4/GTSPlus; argument validation preserves that source ABI.

Supported source identities:

| Variant | SHA-256 | Implemented / named ABS+SMRT exports |
| --- | --- | --- |
| NK12 | `980435d6bb2d9c57aab29e8f281d2641e3822b3172728f223c975ec6493d3c1e` | 66 / 135 |
| NK18 | `8d9623f028f23876f69cb02baa10e1881c01fa01a4f906013bd36266f7e0fb33` | 94 / 310 |
| NK DS4 | `797833dc0c798984fcb739c21ac6fbd5230871fb67495d3339698df2ee53753f` | 94 / 310 |
| NK GTSPlus | `36dcdad2e72e29aae813db5576daf0168dd032b08a9cdda3841078dfb0b7b9fd` | 94 / 310 |

The NK12 port is based on 89 paired export/helper bodies: 88 match normalized C
and normalized assembly/CFG; the remaining pair contains the implemented SMRT32
nibble-mask difference. Three stop workers were disassembled separately.
Normalization removes relocated addresses; it does not establish
equivalence for unexamined callees or other operations. Relevant NK18 helper RVAs
are `27e10`, `28040`, `281d0`, `282b0`, `28390`, `28a50`, `3a980`,
`3aae0`, `3ac10`, `3ad20`, `3aec0`, `3afc0`, `3b130`, `3b240`,
`3b3e0`, `3b4e0`, `3b650`, `3b7a0`, `3dc80` and `3dd20`.
The DS4/GTSPlus port separately reviews 60 algorithm/helper correspondences and
all selected export wrappers. Their newer compiler outputs are not claimed to be
byte-identical. Nonsecret protocol constants remain in authored code; raw source,
source hashes and the correspondence review remain in private evidence.

Classic communication uses `context.comm("selected")`; ABS36/37/38 use the
source-specific fixed UDS manager (`native:1014f5e0`, `native:101b6758` or
`native:101c18a0`, plus `native:101c6da0` for the recovered Plus ABS50 mode-22
branches). Typed `session()` and short-call configuration primitives
preserve keepalive and cleanup semantics. The NK18 fixed manager now has a
source-bound trace through the actual context, lifecycle, UDS scheduler, CAN
lower, pool and typed raw SDK exports. ABS36 support success, unsupported masks,
wrong echo and negative responses verify native retry and full resource cleanup.
The same actual chain now verifies ABS35 DID success/unsupported results, plumbing
classification and the complete twenty-command solenoid flow with resource cleanup.
Other joins and independent verification remain open. The native initialize argument
remains distinct from configured communication addresses: SMRT03/08 sets the
selected address to `0x40`, extended address to zero, and calls `initialize(0)`.
The source-specific configuration RVAs/global RVAs are translated for each variant.
The primitive implementation must consume those fields and resolve the selected
broker mode/protocol; a fake successful initializer alone is insufficient proof.

Run the authored synthetic checks:

```sh
python -m unittest discover -s tests -p test_utility_ex_chassis.py -v
```

They cover requests, native faults, malformed replies, output/cache behavior,
mode/source guards, native cancellation, host deadline exceptions and cleanup.
Private local evidence records exact input hashes, source/ASM hashes, export
inventory and replay results under `analysis/evidence/no-car-96/`. Raw OEM source,
ASM and input executables remain private. Tests use authored synthetic data.

Outstanding software work includes 623 source/export contracts,
independent source review and actual shared-engine primitive
integration. Physical execution remains `PHYSICAL_UNCONFIRMED`.
