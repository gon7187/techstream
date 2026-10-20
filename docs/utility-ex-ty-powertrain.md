# TY powertrain business bodies

`scripts/utility_ex_ty_powertrain.py` implements individually recovered native
business bodies. This is an incomplete domain port. The assigned ECD, EFI, HV,
ECT, ECO, ASG, AMT, MMT, HNECD, HNSCR and PSA domains remain OPEN until every
reachable operation and supplied variant is implemented and independently reviewed.
A name in the allocation packet does not make an operation callable.

The module exposes `supported_exports(sha256)`, `direct_exports(sha256)` and
`run_body(export, args, context)`. Only exact supplied module bytes matching the
registered variant enable a body. The common engine owns wrapper mode guards,
thread scheduling and publication of native worker results. Direct exports retain
signed returns and bypass the worker scheduler.

Current complete bodies at this boundary:

| Operation | Exact variants | Arguments and native behavior |
| --- | --- | --- |
| PSAECD03 reset | 12,18 | One mutable buffer, at least4 bytes; full DWORD1/2/3 maps toAD/AE/A0, other values to0 |
| PSAEFI01 reset | 12,18 | One mutable buffer, at least1 byte; the first byte is the reset selector |
| PSAECD01 water temperature | 12,18 | One mutable buffer, at least5 bytes; retains native output atoffset4, repeats below0x7a |
| PSAECT01 initialize | 12,18 | One mutable buffer; negative7f1122 maps to0x2332 even with a communication error |
| PSAECT01 oil read/write | 12,18 | One mutable buffer, at least4 bytes; raw byte order and write CRC16 are preserved |
| ECO10 engine-start counter reset | 12,18,GTSPlus | No arguments; normal/extended sessions and restore-error precedence |
| ECD59/ECD60 dummy workers | 18,GTSPlus | One mutable buffer; native bodies publish1001/1000 without communication |
| PSADSG02 main/additional identifier writes | 12,18 | Zero-main guard, selected additional slot preservation, CRC16 and raw output mutation |
| PSADSG03 transmitter | 12,18 | Selector mapping, 250 ms polling, native120000 ms deadline and9999 timeout |
| EFI57 display frequency read/write | 18,GTSPlus | Raw mode, byte wrap on write and deliberately ignored session restore status |
| ECD55 reset / ECD57 ash clear | 18,GTSPlus | Exact20:17/20:14 requests and session restore error precedence |
| EFI58 PM regeneration | 18,GTSPlus | Support, start, result, stop, deposition and dealer-stop polling; persistent manager and native reason mapping |
| ASG02 support/initial learning/status | 12,18,GTSPlus | Two A8 support snapshots, indexed reads, retries, native retention and partial error output |
| AMT01 support/history read/write | 12,18,GTSPlus | Native12 34-byte versus18/Plus46-byte layouts, support snapshots and size-dependent writes |
| EFI28 learning reset | 12,18,GTSPlus | Pending setter precedes initialization;3B1E5A,1000 ms,04,2000 ms and length-only replies |
| HNSCR01 reset | 18,GTSPlus | Normal-first session,30 ms wait,31011201, restore with stop-on-error and ignored restore status |
| HNSCR02 adjustment | 18,GTSPlus | All8 actions, support masks,11-field polling order,1/2-byte values, ready/stop flags, reason byte order and retained sessions |
| HV11/HV13 reset | 12,18,GTSPlus |3B2101/3B2301; length-only replies;HV13 waits native10000 ms |
| HV10 selected classic | 12,18,GTSPlus | Support92/optional93 metadata, unconditional indexed2192 outputs, EEPROM deadline661000 ms and secondary judgement |
| HV12 selected classic | 12,18,GTSPlus | Support with inline180000 branches, DTC/EEPROM status, native result mappings, update00 versusPlus01 |
| EFI44 session transition | 12,18,GTSPlus | Mode4 inline4404;20/21 normal session/finalize;Plus22 distinct fixed manager |
| EFI52 switch / EFI53 routine | 18,GTSPlus | UI byte flags and toggle, retained initialization, native polling and distinct Plus P6+10a4 handling |
| EFI55 literal table | 18,GTSPlus |109/112-byte literal writes and81/83-byte read-back comparison; ignored tail differences |
| EFI59 ten-record routine | 18,GTSPlus | Per-record selector/start, retained manager,10-byte result polling, deferred caller output and1008 terminal failure |
| EFI61 short-trip estimate | 18,GTSPlus | Exact35 versus P6 min35 support packets; any-nonzero selections write four zero bytes |
| EFI54 throttle learning | 18,GTSPlus | Normal session,31011193 echo, native last-error mapping and unconditional finalization |
| HV15/HV17 reset | 12,18,GTSPlus | Selected initialization, pending150,3B3101/3B1F01, exact length2 and byte1; no SID check |
| HV14 support and battery reads | 12,18,GTSPlus | A8 support masks at all48 source positions; length publication follows both masks; temperature minimum over16 big-endian words; voltage averages included four-byte groups according to the low mask nibble |
| HV18/HV19 accelerator field | 18,GTSPlus | All support/write/verify actions, variant masks10/08, positions2c/2e and native3000 ms verification |
| HV20 history | 18,GTSPlus | A944, zero61 bytes, variable payload, retained padding and DWORD64 length |
| HV21/HV22 battery field | 18,GTSPlus | Support and3B44 writes, caller21/22 values versus clear0000, exact63-byte HV21 allocation and verification |
| ECT01/02/03/09/10/12/14 routines | 18,GTSPlus | Distinct routine identifiers, retained start,200 ms polling, caller stop flag and ignored stop/restore statuses |
| ECT04/05/08/11 memory | 18,GTSPlus | Zero4128 output bytes on read, preserve length on error, raw writes and ECT08 native2000 ms timeout |
| ECT13 prefixed write | 18,GTSPlus |18 fixed46-byte zero prefix; Plus descriptor prefix and byte-length wrap; P6 distinct9421 length header |
| ECT15 bulk / ECT16 checksum | 18,GTSPlus | UInt16 bulk count and4092-byte bound; source-specific112/71/133-byte checksum transforms |
| ECD67 CharToInt | 18,GTSPlus | One native integer; low byte is converted, invalid input returns signed-1 |
| ECD67 HexToByte | 18,GTSPlus | Input bytes, mutable output buffer, signed capacity; preserves partial writes on an invalid pair |

ECD67 input is null-terminated ANSI in18 and aligned UTF16LE inGTSPlus. The newer
body counts UTF16 units but deliberately converts only each unit's low byte.
Whitespace is rejected rather than normalized. Odd input or insufficient native
capacity returns0xffffffff before mutation; an invalid later pair preserves the
previous decoded output. A missing bounded terminator is a host input error.

PSA bodies use the actual selected broker6F/70 communication object. ECO10 uses
its exact source global-object identity. Native initialization errors, waits,
reply-length/echo checks and cleanup order remain explicit. The common CRC16
implementation is reused after verifying the12/18 helper polynomial, initial
value and final complement against their actual ASM.

The host bounds native input/output buffers to65536 bytes and requires declared
capacity to fit the supplied output allocation. These are host safety limits.
Cancellation and provider contract faults are host exceptions; they cannot be
replaced with a successful native status. No vendor library is executed.

```sh
python -m unittest discover -s tests -p test_utility_ex_ty_powertrain.py -v
```

The TY18 HV15/HV17 tests execute the production public wrapper,97 aggregator,
101 business body and108 selected classic CAN facade through raw positional SDK
exports. Positive, malformed echo, HOST exception identity and cancellation cases
verify both filter removals, disconnect and native status globals. This is a
software composition check using authored SDK replies. The remaining variants
and operations still require their own concrete lower composition; full G2/G3
and vehicle behavior remain OPEN. Other communication controls here are component
tests and are not evidence of complete domain integration.
ASG/AMT support queries execute their recovered business scans through the
separately owned native multi-frame A8 snapshot algorithm; flattening that
algorithm into one `exchange` is incorrect.

PSADSG main writes require all four existing main identifiers to be zero; a
nonzero main identifier returns0x2337 without a write. Additional writes first
replace the caller's nine identifier DWORDs with the ECU snapshot, then restore
only the selected caller DWORD. An out-of-range selector still publishes the
snapshot and succeeds without sending a write. Positive write replies check
length and byte1, preserving the native absence of a positive-SID check.

EFI58 start success retains the initialized exact manager; result and dealer-stop
polling reuse it without initialization. Stop ignores the helper's native status
and retains the connection. Dealer-stop returns1002 and retains the manager when
the caller's stop flag is set. Cancellation and provider exceptions remain host
exceptions with explicit cleanup; they are never converted to native success.
The branch tests cover all six start-reason mappings, both dealer-stop extra
reasons, partial deposition output, compact support-bit ordering and native
connection retention. They do not establish a live ECU or initialized lower108.

The exact-source worker-wrapper packet is private evidence under
`analysis/evidence/no-car-101/reviewed-wrapper-packet.json`. It binds every
admitted source/export pair to its own wrapper and body C/ASM hashes, mode,
arity, timeout and return convention. A source-bound test executes the public
83 worker wrapper through the97 aggregator and this101 body with an authored
communication control; the concrete108 initialization boundary remains OPEN.

ASG initial learning retains its native retry counter in the caller buffer;
ordinary failures increment it at most twice, while statuses5 and1460 return
immediately. Its normal status, after-timeout and004 status workers deliberately
have different initialization and finalize rules. The after-timeout worker ignores
an initialization error and still reads the native status. Indexed89/8A outputs
are written even after native transport errors; source byte order is preserved.

AMT12 support stores two34-byte records at40/74 and reads34 history bytes;
18/Plus store46-byte records at52/98, retain the support length at144 and read46
history bytes. Read helpers copy fixed buffers and record raw response length even
when communication reports an error. Native write size depends on the18/Plus
selector fields;12 always writes36 bytes including the command header. The host
rejects native requests/support copies that exceed the recovered allocation.

Literal OEM `Sleep` calls use `native_sleep`, preserving one host primitive call
and its full duration. They do not use the common cancellable100 ms helper. The
public worker check records the actual host calls to distinguish those paths.

The current partition has550 exact source/export pairs.193 have implemented body
components;357 remain missing business bodies. The partition is an explicit OPEN
reconciliation, not domain closure or physical parity. DS4 contributes no named
exports in these assigned domains in the supplied canonical four-variant union.

HV14 support, temperature and block-voltage workers are present for exactly the
supplied12,18 and Plus images. Support uses the selected multi-frame A8 snapshot,
requires all16 PID81 and32 PID87 bytes to equalFF, and publishes each native length
only after both masks pass. Temperature checks declared length and echo87 before
writing the minimum of16 big-endian words at caller offset8. Block voltage checks
declared length and echo81, then averages the two words in each unmasked low-nibble
group; an all-masked request preserves the native NaN result. The caller's other
bytes remain intact. Concrete Plus and12 lower integration and independent review
remain OPEN; no vehicle behavior is claimed.

The source-bound public-wrapper fault matrix covers every admitted source/export
pair through actual selected83 wrappers and the97 aggregator. It distinguishes
normal statuses, direct conversion returns, dummy workers and the PM stop helper's
ignored transport status. The authored lower communication control is a component
test seam. Actual TY18 selected CAN and standard fixed-manager joins are tested
separately;12/Plus, CComTestModeP5 stack and Plus P6 initialization remain OPEN.

HNSCR02 preserves its separate start, poll, end and condition-result actions.
Polling orders the11 fields using the native permutation, stores both each raw
value and its original field index, and retains its shared manager on native
returns. DID100D and1012 return two-byte values;102A returns one byte. The Plus
support table deliberately disables field6 while18 uses mask8; this difference
was checked against each source and the Plus read-only PE constants. Native
unknown actions return0 without communication. Host faults still clean up.

HOST finalization uses an operation-local cleanup scope: the original exception
object survives a second finalization failure, and finalization runs once. A sole
cleanup failure still propagates when the caller happens to be inside an unrelated
exception handler. This host error policy preserves native normal-return retention
and does not infer an original PE exception class from a Python exception.

The complete supplied EFI52–62 cohort has16 named exports in each18/Plus image.
All32 source/export bodies and every Plus22 callback are implemented. Native
P6+10a4 has its own source field semantics; it is not ordinary UDS `busy_ms`.
The concrete P6 facade remains guarded in108. TY18 production SDK tests cover
EFI52 UI stop/toggle, EFI53 retained routine, EFI54 faults/cancellation, EFI58
retained start followed by EFI44 cleanup, EFI59 retained records and EFI62
all-action read/write. These use actual83→97→101→108 code with authored SDK
replies and do not execute supplied PE code.

All14 assigned ECT exports in18 andPlus are implemented, including each separate
Plus22 callback. P6 ECT01 keeps its10a4 override across polling, stop and normal
restore; ECT04 deliberately strips only the first response byte. These contracts
remain distinct from ordinary fixed-manager behavior. TY18 public SDK tests cover
all seven retained routines with positive, native failure, HOST and cancellation
outcomes and all four memory operations with their exact timeout. Plus/P6 lower
composition remains guarded; source-component success does not close that gap.

Source instruction authenticity can be replayed with:

```sh
python runtime/no-car-101/check_source_images.py
```

The replay reads original PE files, verifies their complete SHA256 identities and
compares every referenced cached instruction's bytes with the original image.
Semantic equivalence still requires the separate branch tests and independent
review; byte agreement alone does not close the business domain.
