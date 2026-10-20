# Native NK powertrain business bodies

`utility_ex_powertrain.run_body(export, arguments, context)` implements 91 business bodies for the exact supplied 12
module and 94 for each exact supplied 18/DS4/GTSPlus module identity. The
shared UtilityEx scheduler calls it after binding the native export wrapper.
It does not load a vendor DLL or open a transport.

Implemented operations:

- `Ex2ECD_InitialSupplyPump`: selected communication initialization mode 19,
  pending/retry limits 1, request `3b 06 01`, exact two-byte response and
  selector 06, finalization and native limits restored to 100/3.
- `Ex2ECD_12_InitAFSensorLearn`: native uint32 argument narrowed to its low
  byte, six-byte request `3b <selector> 00 00 00 00`, exact two-byte reply and
  matching selector; communication delay changes 150 → 100.
- `Ex2ECD_12_GetSupportInfo`: one-byte caller-owned output buffer retains
  existing bits. Query `3b 00`, require six-byte reply, OR bits 1/4 from
  native response bits; conditional extended query `3b 20` ORs bit 2.
- `Ex2ECD_22_ClearZFCLearningValues`: low-byte cylinder bitmap, selected
  cylinders 1–8 in ascending order, 100 ms wait before each eleven-byte
  `3b 19 00 <cylinder> 00 00 00 00 00 00 00` request, exact two-byte reply,
  stop on first fault or native cancellation.

Each body retains its native error mapping. A malformed business reply returns native
status 3. The shared communication primitive owns service validation, pending
replies, retries and selected-driver resolution. Configuration helper RVAs are
bound per exact module identity, including the different 12 helper addresses.
The scheduler owns native thread/result handling and cancellation status
normalization. Host exceptions restore communication settings and finalize the
selected driver; this is explicit host cleanup policy.

- `Ex2STR_ChangeRegistMode`: native mode 3, `a5 99 04 00`, retains the
  initialized communication session only for the direct two-byte success. The
  three-byte zero-status reply takes the `21 03` fallback with retry limit 4;
  bit 7 produces native result 1001, otherwise 1000. Faults finalize the driver.

`Ex2ECD_25_ClearLearningValues` takes a one-byte selection bitmap. It sends
a 19-byte `3b 10 <cylinder>` command for each selected cylinder, stops on the
first fault, and maps initialization failure to native status 4.

The preset read/write bodies use `a9 5a` and `3b 5a <value>`. Read requires
a minimum three-byte reply and publishes the value byte only after validation.
Write polls at most three times, compares the low seven bits, and returns native
2600 on a persistent mismatch. Native cancellation preserves the current status.

Crank-time initialization sends a 39-byte alternating reset pattern, queries
support, and conditionally sends a second reset. DPF-ash reset queries support
and selects a 16-byte or seven-byte reset; failed support returns native 2300.

`Ex2STR_ConfMasKey` queries `21 03` with native pending/retry limits 1/4.
A valid master-key bit pattern returns 0; the native inconclusive result 300
is mapped to 100. Malformed replies return 3; transport errors are preserved.

The direct `Ex2ECD_14_CheckCodeSupportInfo`,
`Ex2ECD_14_CheckCodeSupportWID20Info`, and `Ex2ECD_31_CheckCodeSupportInfo`
bodies query `a9 00` / `a9 20`, require at least six reply bytes and matching
selector, and copy the four payload bytes to the original caller-owned buffer.
Longer responses are accepted. `Ex2ECD_24_GetCodeSupportInfo` requires exactly
six bytes from `3b 00`, ORs bits 1/0 from reply bits 4.0/5.7 into the existing
output byte, and returns native 2400 only if that resulting byte is zero.

`Ex2STR_Init` performs selected initialization and always finalizes, retaining
the native initialization result. `Ex2STR_RegMasKeyConf` queries `21 03`,
requires at least three bytes and selector 03, and returns 480 if bit 7 is clear.
The 12/18 exports retain their unused uint32 argument; DS4/Plus take none.
Native pending/retry defaults are restored even when initialization fails.

`Ex2STR_GetRegKeyNumBefore` clears two caller-owned DWORD outputs before
initialization and queries `21 04`. `Ex2STR_GetRegKeyNumAfter` uses the retained
session without reinitialization and preserves outputs on error. Both split the
returned count byte into high/low nibble DWORDs, preserve alias write order,
restore pending/retry settings and finalize. The shared export wrapper owns the
After output references stored in native globals before its mode check.

These direct operations contain no native cancellation check; host cleanup on
provider exceptions restores settings and releases the selected session.

`Ex2ECD_31_ReadCode` executes every supplied native record branch: selected
flags trigger `a9` selectors 02, 06, 07 (four cylinders), 09, 0e, 0f, 12,
and 15 in order. Build 12 has no selector-15 branch. Each reply updates its
native record field and selector marker only after validation; an error stops
later fields, preserving earlier output. Native helper failures map to 1406.
Selector 15 accepts a four-byte reply and copies a DWORD from the zero-filled
native backing; the host reproduces the two zero bytes beyond that reply.

`Ex2ECD_13_ReadCylinderInfo`, `Ex2ECD_17_ReadCylinderInfo`, and
`Ex2ECD_22_GetCylinderNum` consume the literal support snapshot record for C1,
compute its native payload position from preceding nonzero support bytes,
and query `21 c1`. The 13/17 outputs are DWORDs and permit cylinder counts
4/6/8; 22 writes one byte and also permits 3. Their native unsupported/value
errors are 1300/1301, 1700/1701 and 1501/3 respectively. The 17 body contains
no delay setter. Malformed snapshot backing is rejected at the host boundary;
the native one-past-end support-table access is rejected safely.

`_Ex2STR_43_CheckOnlineSupport@4` is a direct mode-4 diagnostic query, with no
network access. After initialization and native raw `Sleep(100)`, `21 12`
requires at least four bytes. Reply byte 3 bit 1 sets native result 4311 and
publishes reply byte 2 bit 7 as a DWORD; otherwise existing output is retained.
The explicit `context.native_sleep` primitive preserves the distinction from
the native cancellable wait implemented by `context.sleep`.

The actual NK18 selected CAN path is tested through `UtilityExEngine.invoke`,
its real communication facade, driver binding and individual typed SDK callbacks.
Authored wire observations cover support-word output and all three cylinder
snapshot consumers, native NRC errors, malformed service replies, foreign
provider exceptions and session cleanup. No business exchange or whole snapshot
producer is substituted in those checks. Other selected variants and remaining
operations still need input-to-consumer verification.

The original and `02` `Ex2STR_WaitCompEraseKey` bodies reuse the retained
session, poll `21 06` while bit 6 remains set, then query `21 04` and require
count byte 10. Their native malformed/timeout/final-mismatch results are
1051/1052/1053 and 101/102/103. Cancellation preserves the last native poll
result, including 171. Each query restores pending/retry settings; completion
always finalizes the retained session.

`Ex2STR_GetRegistKey` first queries `21 03`, rejects byte 3 bits c0 with 1002,
then reads the caller's one-byte result with `21 04`. Only its successful
result keeps the session open. `Ex2STR_WaitCompRegistKey` polls `21 06` until
bit 6 clears, reads the result with `21 04`, and always finalizes. Its native
poll timeout/error results are 1003/1004. Cancellation immediately after a
successful busy poll returns the previous result 0 without changing the
output; the host preserves this native distinction and the wrapper has no
cancel normalizer. The scheduler owns worker stop deadlines.

`Ex2STR_ConfRegArea` sets pending/retry 1/4 before initialization, retries a
failed initialization once after raw `Sleep(2000)`, then queries `21 03`.
Byte 3 bit 7 returns 440; initial cancellation returns 5. Success retains the
session. Fault cleanup finalizes before restoring defaults, preserving the
native order.

`Ex2STR_ConfRegMode` queries the retained session with `21 06` until bit 6
clears, then returns 0 and retains the session. It checks cancellation only
after a busy reply, returning native 5 and finalizing. A clear reply wins even
if cancellation was already set, matching the native branch order.

`Ex2STR_CngEraseMode` uses `a5 99 80` with pending/retry 1/1, native busy
window 10000 ms and communication delay 3000 ms. Two reply bytes retain the
session; a three-byte zero result returns 12. All defaults are restored before
fault finalization. `Ex2STR_InitImbi` preserves the exact selected-manager
and target fallback: target 10 then, after failure/finalization and raw
`Sleep(300)`, target 13 with its distinct manager. A second failure selects c1
and finalizes. The private NK18 dispatcher-to-SDK acceptance also proves the first override
manager uses the distinct legacy P4 lower and literal FAST_INIT `81 10 f0 81 02`;
the successful session is retained until explicit finalization. Other exact
module lower implementations remain OPEN.
`Ex2STR_CngEraseModeImbi` consumes that retained session with `a5 99 00`,
returns 401/402 for three-byte results, resets target c1 and override zero,
and always finalizes.

`Ex2STR_16_Foced_Termination_Of_FM` retains the supplied misspelled export name.
It maps initialization failure to 1601, sends `a5 99 01 00`, then sends `82`
unless status is 1601. The second command's result is ignored natively. Initial
cancellation skips initialization and the first command, still sends `82`, and
returns 0; this literal behavior is separately tested.

The three STR42 bodies execute the support-to-length-to-erasure flow. Support
kinds 1 and 3 check literal record selectors/masks and store the source-local
length DWORD. Erasure builds the native `3b 01 80` command with that length and
retains only a successful session. Mode verification polls `21 16`, then reads
`21 14`, preserving 700–704 fault distinctions, raw waits and finalization.
The direct native condition loop has no cancellation check; an explicit host
budget of 65536 primitive calls raises `TimeoutError`, never native success.
The host also rejects native out-of-bounds support-buffer access.

`Ex2STR_41_EndFactoryMode` consumes its source-local length and the full uint32
argument to construct `3b 01 08` with native zero padding. It maps NRC22/status7
to 26 and always finalizes. `Ex2STR_41_GetRegKeySupportInfo` produces the
same command length through native support kinds 1 and 3. It preserves the six
required selector/mask checks, optional extended support, `21 12` / `21 16` /
`21 14` queries, native mode and six-byte packed count globals, three mutable
outputs (DWORD/DWORD/byte), conditional 4116 result and conditional session
finalization. The source length remains intact when the native support-record
sentinel is absent. Twenty default count/mode/length DWORDs were read statically from
the exact PE images and verified as zero.

The direct `STR41_GetCurrentMode`, `GetCurrentStatus` and `GetRegKeyNum`
queries consume the retained session. Status validates `21 12`, `21 13` and
`21 14`, preserves unrelated count bytes and returns native 4107/4108 errors.
The old 12/18 decompiler omitted the 4108 bit-7 branch; literal ASM proves it.
`STR41_ResultTransponderID` also retains the old ASM bit-7 branch, the extra
broker70 == 17 wrapper gate, unconditional finalization and native 4105 result.
`STR41_GetCurrentModeRepeat` retains two caller-owned DWORD references in native
wrapper globals before mode checking, polls mode with a 50000 ms scheduler,
compares source baseline key counts, and preserves session/current status on
native cancellation. The body raises a host `TimeoutError` at 65536 polls.

`STR41_GetCurrentStatusRepeat` uses a 50000 ms scheduler, mutable DWORD/byte/byte
outputs and three native packed count pairs. It preserves forced second reads,
comparison order, 4114/4115 retained-session outcomes, and cancellation checks.
The three registration operations preserve literal wrapper argument permutation,
zero assignments and stores before the mode guard. `RegTransponderID` sends
`3b 01 20` or `3b 01 00 00 40`, and checks `21 00` after writing the timestamp
only in full-word mode 1. `RegNewKey` sends `3b 01 40` or `3b 01 00 00 80`,
maps timeout to 4113, and checks mode on other command errors. `StartCommunication`
first initializes, writes the timestamp and queries `21 00`, then follows the
new-key sequence. Their caller-supplied command-length DWORD broadens the host
bound to the native 4128-byte request backing; oversized commands raise a host
error with cleanup. Native 4112/4113 results preserve the appropriate session.
`STR41_StartKeepAliveCheck` polls unsigned 32-bit elapsed time, writes its
second tick before `21 00`, preserves initial cancellation 99 and maps failed
queries to 4118 without native finalization. A 65536-iteration host budget bounds
the otherwise busy native loop.

ECD19 support queries require exactly six response bytes and check native
cancellation only after initialization and the 150 ms delay setter: cancellation
returns zero with the original output intact. ECD16 writes support DWORD bytes
at offset 5 of its caller-owned record and accepts extended replies. ECD15 and
ECD20 read count bytes at source-record offsets 16/32 and OR existing output
flags; unsupported results preserve 1501/2000. The Plus ECD15 decompiler's void
argument list is corrected by literal `RET 8` and its tail jump.

ECD09 normal-learning and ECD10 detailed-learning mode changes use the retained
session and `3b 10 aa <low-byte>`. They retain only success and distinguish
NRC22 statuses 902/1002. Their diagnostic erasure initializes only when the full
uint32 argument is 1, sends `04`, requires exactly one response byte, and always
finalizes. None of these four bodies tests native cancellation.

STR43 state operations preserve their distinct recovery behavior. Registered-key
count (`21 14`) returns 4307 for nonzero counts and always finalizes. Mode worker
(`21 16`) retains the session only when cancelled after a valid busy reply; its
initial cancelled result is 4306 with finalization. Both query helpers map native
2/5 to 4305 and malformed/other errors to 4306, perform raw Sleep100,
finalize/reinitialize while ignoring the recovery status, then restore delay100.
The mode wrapper uses a 20000 ms scheduler. StartCommunication initializes and
retains only success. The host caps otherwise unlimited mode polling at 65536.

STR20/22 support checks use the concrete current-target/protocol cache: refresh
kinds 1 and 3, obtain the stored record snapshot, then apply the exact 17790
selector/length/mask algorithm used by derived helper 20980. The old 20100 C
prototype incorrectly hides its kind argument; ASM supplies 1 or 3. STR20
retains the session even on native failures, while STR22 finalizes failures.
Their ACC/IG confirmation workers consume fixed PE condition tables. All twelve
tables were read from the supplied images and pinned with literal decoded
index/mask/expected triples; STR20 record stride is 6 and STR22 stride is 8.
The workers preserve 504/2204 on cancellation and never natively initialize or
finalize the retained session.

STR20 registration start/end use the concrete native `support_length(3, C1)`
primitive to pad `3b c1 40` / `3b c1 80`. Missing length returns 82 without wire
traffic. NRC22 maps to 507. Start waits 1000 ms, then checks `21 22`, preserving
503 versus 506. Older EndKeyRegist C prototypes suggest an unused cdecl word,
but the full wrapper/thunk/body chain reads zero semantic arguments; the
reviewed contract exposes zero arguments and preserves this formal-arity
uncertainty explicitly in private evidence. Plain RET alone does not prove
formal arity.

STR41/42 StartKeepAlive call the source-specific shared CMN starter with literal
interval 2000 and a zero-length request. The shared engine writes its native
fields before checking busy status and owns the 10000 ms worker. Leaf132
executes the selected exchanges and native recovery. STR41 has an additional
protocol-17 guard and a void return; STR42 propagates native startup status.
These operations do not use the separate native timer keepalive API. The private
STR42 SDK trace proves shared fields, real `21 00`, cancellation during the
post-reply wait, worker/result status and retained-session cleanup.

The exact decorated `_Ex2STR_43_StartKeepAliveThread@4` is supplied only in
18/DS4/Plus. Its native void wrapper schedules 10000 ms, polls a caller-owned
DWORD timestamp with a 4000 ms unsigned delta, stores a second tick, and sends
one-byte `3e`. It continues after native query errors and publishes the last
status on cancellation. No alias is fabricated for the absent 12 export.

STR20/22 key-number queries use `21 24` and accept nibbles 1–7/F, with zero
absent and 8–E invalid. STR20 increments existing caller DWORDs in literal slot
order, retaining partial writes and unsigned wrap. STR22 computes local totals
and commits master then secondary only after all eight slots validate; invalid
2203 preserves both outputs and finalizes. Their aliased-output behavior differs.
STR20 `KeyRegist` polls these counts from zero every 1000 ms and writes the first
two DWORDs of its four-DWORD record only when either baseline is exceeded.
Otherwise `21 22` must retain bit 7; a clear bit returns 503. Cancellation
preserves the current status and native paths retain the selected session.

The STR20/22 CMN starters pass literal one-byte `3e`, length 1 and skip-validation
flag 1. STR55/56 starters pass an empty request; these exports are absent in 12.
The general mode-3 STR starter retains retry 4/pending 1 and passes the caller's
full uint32 interval. All use the source-specific CMN worker, with native void
returns preserved where supplied.

ECD09/10 keepalive checks only native protocol 17/33/81 and imposes no mode
predicate. It retains retry/pending limits 0/0, starts CMN with literal `21 0c`,
interval 2000, length 2 and skip-validation 1, then returns 0 even when startup
reports busy 16. The modern decompiler's fastcall argument only occupies the
unused half of a local word and supplies no semantic input.

ECD50 support refreshes native cache kinds 1 and 2, checking selector 4b fields
5–8 with mask ff and selector 50 fields 3/4 with mask 44. It preserves refresh
errors, maps missing support to 3011/3012 and always finalizes.

STR53 single queries perform `21 16` when unsigned timestamp delta reaches
1000 ms and write a second tick even after a native query failure. Switch checks
use `21 11`, returning 4501 for the opposite bit-5 state; key/mode queries split
`21 17` into two caller-owned byte outputs. Immobilizer queries require bit 5
from the timed mode query or return 4502. Single immobilizer always finalizes;
successful single switch/key queries retain the session. The four polling
exports preserve native busy/cancel distinctions and shared argument references
written before mode checks. OnExit retains only after at least one successful
timed exchange; cancelling before one preserves status 99 and finalizes.

Prepared native shared fields take precedence over stale scheduler argument
tuples. STR53 callbacks capture their pointer fields once on entry; STR41
repeat and registration callbacks reread fields at their native read points.
Standalone authored body checks populate fallback fields only when none exist;
partially initialized structures fail explicitly. Busy or mode-rejected wrapper
calls can update shared fields before the original worker enters.

STR43 support executes both metadata producers and all 4301/4302/4303
branches, retaining caller flags and native length/option bytes in source order.
Modern length/option bytes alias the upper half of the STR41 count-tail DWORD;
STR41 WORD resets/updates preserve those bytes. Initial backing was checked
against all four supplied images. Seed requests set the caller mode to431/432,
zero the first seed DWORD, then require exact eight-byte `27 05` replies and
copy six bytes; native4309 retains the selected session. ClearAllKey accepts a
six-byte caller key through `27 06`, or full-word mode1 supplies a native length
byte directly. It emits padded `3b 01 00 03 08` / `3b 01 04 03`, maps command
failure4304 and performs one `21 16` query before success. It does not poll the
separate CheckModeThread operation. All shared argument stores and lifecycle
branches are source-bound.

Thirty `21` query call sites explicitly use native minimum reply sizes; `27`
and `3b` exact-size checks remain separate. The private SDK corpus currently
covers35 authored paths and33 owned operations through the actual dispatcher,
selected lower and typed SDK exports. Public checks remain94 authored tests,
zero BYOD dependencies and zero skips. These are bounded software checks.

This is a partial implementation. The other STR and ECD bodies remain OPEN.
Unknown operations raise `NotImplementedError`; an unsupported module identity raises `ValueError`.
Export inventory is evidence of named entry points, not proof that their
business semantics execute. Exact PE enumeration found 168 ECD/STR entries in
each of 18/DS4/GTSPlus and 150 in 12, including entries omitted by the older
candidate grouping. No count quota defines completion.

Private source bindings and exact module/operation inventory are under
`analysis/evidence/no-car-95/`; proprietary decompilation stays in the private
source collection. Public tests use authored synthetic observations only.

Public validation (authored observations only, no BYOD dependency or skips):
`python -m unittest discover -s tests -p test_utility_ex_powertrain.py -v`.
Source-dependent SDK acceptance is a separate private corpus check under
`runtime/no-car-95/test_selected_sdk.py` and requires the exact supplied image.
No adapter or vehicle was used; physical behavior is PHYSICAL_UNCONFIRMED.

STR52 support/data/keepalive/key callbacks retain their four exact NK wrapper
variants and native shared pointer fields. Support refreshes kind 1, checks
selector 12 field 4 mask 02 from the bounded cache, then performs `21 12` and
`21 00`; mode 1 continues with `1A 84` data and `27 07` seed writes. Other
callback modes retain the successful session and return native 4406. A
non-`0x104` profile saves the selected target, applies the exact 104 manager,
and restores it on failure or explicit key cleanup. Data reads retain their
successful session; key submission sends exactly the caller's declared bytes
and always finalizes. KeepAlive uses unsigned 3000 ms tick deltas and stores a
second tick before `21 00`, with no native sleep. Host bounds require complete
DWORD/output backing and cap key length and busy-loop iterations; these checks
do not change native result codes.
