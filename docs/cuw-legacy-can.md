# Original CUW executable CAN controllers

`scripts.cuw_legacy_can` reconstructs the original executable's CAN controllers and helpers over
injected low-level primitives. It does not load executable code or open a vehicle
transport. Executable identity and imported CPU selection belong to the common
executable router.

`CommonCAN(io, request, response, padding=...)` accepts complete four- or
five-byte native CAN headers and the actual channel padding flag.
`CommonCAN.from_io(..., state=channel_state(context))` binds the actual mutable
legacy channel RAM. All wrappers share live padding, receive timeout and send timeout
fields; timeout setters update that RAM before the primitive callback, so reconnect
uses the latest value even when a provider stores nothing. Standalone unbound helper
fixtures still obtain explicit fields from provider getters. `write_messages` returns an accepted message count of exactly one;
`read_messages` returns complete `NativeMessage` values or mappings containing all
six message fields. A byte string alone cannot represent a native message because
it omits `RxStatus`. The helper implements `ReadSpecifiedCanMsg` modes zero, one
and two. Mode two requires the actual channel padding flag explicitly.

Every write clears the receive buffer with ioctl8. Protocol6 applies padding
flag40 when enabled and awaits its matching native transmit indication. Actual
bound protocol5 writes use TxFlags0 and skip that indication read, matching
46eff6/46f001/46f016 and470bc1. Unbound standalone helpers retain protocol6.
Ordinary helpers copy four header bytes. Finish preserves an optional fifth
extension byte and its transmit flag. ACK accepts only a five-byte frame ending
in `3c`; native driver errors 9 and 16 return false. Status performs `50`, ACK,
status read, ACK, and retries native status errors up to three times. Driver errors
from the status data read and host cancellation/deadline failures remain distinct.

Memory opcode `76` requires a full frame of 13 or 15 bytes. Its decoded address
and inclusive end address are three or four bytes respectively, followed by
block size in KiB and the firmware descriptor.
The final response byte is excluded by the original getter.

The original 18 executable SHA-256 is
`97f7b9302a6090e2715ca6c9713aecc73404d6c0f75aede2dd52f09bd201074b`.
Source anchors: status `45a9f0`/`45abd0`, ACK `45ae98`, finish `45acac`/`45ad4c`,
memory `45b41c` and decoder `46be4c`, matching read `46f464`.

`check_id` emits the native five-message batch atomically. Its interframe variant
emits five individual writes with four waits. Both preserve the mode-one response
indication, optional first-response timeout and final `3c` acknowledgment.
`check_block`, `erase`, `inverify`, `verify` and `write_block` generate actual
`36`, `26`, `48`, `16`, `41`/`45` transactions. Data fragments are exactly 256 bytes
for verification and 1,024 bytes for writing; supplied bytes are never padded.

`calc_block_sizes` implements executable `46ac58` CPU branches, including the
19/73 branch's discarded remainder below 4 KiB. `select_block_ranges` implements
`46c050` first-match/sentinel selection over an explicitly supplied native table.
These helpers do not infer geometry from a product or filename.

Host limits are explicit: 65,536 received frames, 16 MiB aggregate receive data,
and the shared runtime's monotonic deadline, cancellation and primitive-call
budgets. These are host policies, not recovered ECU limits.

Run the authored vectors with:

```sh
python -m unittest discover -s tests -p test_cuw_legacy_can.py -v
```

The concrete `CCanFlashWriter` and `CP5CanFlashWriter` entrypoints now execute
through imported RAM, source codecs, raw SDK primitives and recovery112. Whole
source review and final manager/replay admission remain OPEN; the current
checkpoint below lists the remaining dependencies.

The executable ordinary CPU branch has distinct helpers:
`ordinary_check_block`, `ordinary_erase`, `ordinary_inverify`, `ordinary_verify`
and `ordinary_write_block`. They preserve commands35/25/47/15 and their extended
index variants36/26/48/16. Their busy statuses are respectively10/80/40/20/40;
these differ from the shared virtual range helpers' low-nibble checks.
`ordinary_flash_blocks` implements only the source block loop over a bounded,
materialized imported image. It checks all geometry/image intervals before erase.
It does not claim controller preparation, recovery or finishing has completed.

`collate_seed_key` requires an explicit four-byte key provider. It emits271,
waits100ms after successful seed/key calculation, and emits272/key. Native seed
transport statuses9/16 become CPass22; an exact seven-byte7f27 negative frame
becomes CPass23. Key/material bytes never enter reports. `change_reprogramming_mode`
preserves its caller's mode byte,50 response prefix and native error18.

`ccan_functional_header` follows41448c and its callers464fd5/46282c: the first
CPU type selects CPU0 orCPU1, and the header uses that row's final LocationID word.
The current write CPU's physical headers come separately from41a1e4. DLL address
selectors do not substitute for either executable metadata producer.

`m16c_flash_regions` preserves the executable's separate CAN-transport bootloader
branch: erase each supplied region, then interleave each256-byte program and
verification page, followed by3000ms. Imported region order is retained; image
bytes are consumed consecutively. CPU-specific appended regions are recovered by
`ccan_m16c_extra_regions`, built in the source's initially empty vector without
substituting a manually guessed memory layout.

`prepare_can_addresses` consumes actual source-produced `CAddress` rows. It
acquires every flow-control filter, performs security per target, excludes only
CPass22/23, sends the functional diagnostic-mask triplet, changes accepted targets'
mode, and releases every owned filter. Cleanup failure retains primary exception
classification; host cancellation/deadline is checked after final cleanup.
`ccan_prepare_mode` preserves the native mode60 and repeated-mode branches.

`p5_diagnostic` implements45d898's null-cancellation-pointer calls used by CP5.
It uses mode-two receive, receives pending replies without retransmission, raises
the caller's native category on driver failures, and restores the observed receive
timeout. Its pending timer uses180 whole local seconds with midnight rollover;
pending receive timeout is5530ms. Only native pending expiry emits3e. NRC21 is not
retried. `p5_collate_seed_key` has no CCan100ms key delay; `p5_prepare_routine`
implements31011003/71011003 with caller error25. These concrete helpers do not
represent completion of the full CP5 controller or its recovery tail.

`ExecutableCANError` retains its `ValueError` identity and now belongs to the
`ExecutableNativeError` domain. Foreign native catch-all paths can therefore catch
CPass exceptions without catching arbitrary host/provider errors. J2534 errors
retain their separate `NativeTransportError` ancestry and original instance.
CP categories use one native signed byte: `native_code` is signed and `code` is
the unsigned protocol view. PublishingCPff therefore produces DWORDffffffff.

`p5_cpu_order` reconstructs the local P5 identity index vector from original12
`40e90c` and original18 `41a29c`. It validates contiguous runtime CPU rows and
keeps original source/image provenance indices separate. Sparse runtime rows are
rejected before CAN preparation. Static opcode assertions for both source hashes
live in `runtime/no-car-68/verify_p5_order.py`; this closes only that producer,
not the full Execute or recovery chronology.

`runtime/no-car-68/verify_execute_eh.py` decodes the actual original12/18 Borland
Execute exception tables for both controllers. Its source-hash-bound output
`execute-typed-eh12-18.json` preserves CJ2534, CPass and native catch-all scopes.
The decompiler hides several handlers; this evidence is required before porting
their control flow and does not claim that the handlers are implemented.

`write_frames` sends different four-byte CAN headers in one native message batch,
clears RX once, and waits only for the first message header under protocol6.
`write_many` delegates to that same batch boundary for its common-header frames.
`read_selected` implements original12 `4476f8` / original18 `46f648`: request the
remaining header count, accept only complete header matches with indication3,
remove one matching header, and retain full frames in arrival order. Duplicate
headers remain separate obligations. A failed read exposes no partial output
and preserves the original native exception instance without9/16 retries.
The read group requires bound protocol6 channel RAM and shares receive budgets.

`OriginalSeedKey(context)` reads the admitted original executable's four native
WORD-constructor instructions at12 `451400` or18 `47f0c4`. It verifies each
0x10c-stride destination and constructor call, preserves the native big-endian
WORD byte order, and applies the four conversion rounds at12 `437ea8`/`43809c`
or18 `45a1b0`/`45a388`. This is an embedded algorithm; no authorization service
or captured-key callback substitutes for it. `CanController(context, io)` and
`execute(context, io)` use this source-bound producer directly.
`PYTHONPATH=. python runtime/no-car-68/verify_seed_key.py` verifies both original
hashes and512 independent algebraic vectors without executing an original image.

The full-controller implementation remains under independent review and is not
admitted to the manager router. Actual original12/18 P5 replays cover the source's
ordinary CPU1 no-transfer branch, two CPU86 SREC images, CPU136's R32C geometry
and logical90/physical86 M16C transfer. CCan replays additionally exercise ordinary,
shrink and M16C geometry, recovery finalization and accepted retry tails. These
software checks do not prove vehicle behavior.

`automatic_ig_off_cancel(context, io)` implements original18 `56646c` with its
own fixed extended-address filter. The primary1003 query suppresses driver9/16;
the exact7f1012 native response selects the reachable1070 fallback that Ghidra
incorrectly removes. Normal mode reads DID2001 and conditionally updates its
second byte. The fallback retains45d458's distinct NRC21 retransmission and NRC78
receive counters and suppresses only exact7f10{11,12,13} native replies.

`original_location_id` follows original12 `40e134` and18 `4199f8`, rather than
requiring a DLL-style eight-byte field. The native256-byte array is zeroed first;
even, short ASCII strings therefore provide zero bytes beyond their parsed
length. Each two-character pair uses the native base16 `strtoul` grammar and
must be consumed completely. Odd or invalid pairs raise a foreign native
exception with no invented transport category. The whole controller reads the
original imported `locationid` text and consumes its first eight initialized
array bytes. Host bounds reject lengths beyond native capacity and non-ASCII
CRT domains whose locale behavior is not established.

The P5 mixed90/86 replay uses the logical90 image for256 M16C program and256
verification pages over the physical86 header, then programs the86 ZV image.
Both versions consume133120 image bytes and6023 Execute primitive events.
The M16C recovery helper includes the original37 raw protocol5 reset frames,
protocol6 reconnect and filter reacquisition. Whole accepted-retry checks also
exercise the separate physicalCPU15/16 reset path, which sends256 zero bytes
under protocol6 instead of the raw protocol5 sequence.

The current CCan implementation also consumes the actual112 `finish(io)` API:
normal final completion deletes through two bounded host primitives, resets native
recovery RAM, then writes the source terminal CPU cursor. Original12 always uses
no-ACK finish. Original18 selects ACK by the source ECU-kind/CPU predicate; ACK
exceptions set the retry flag and rethrow. No-ACK finish catches native exceptions. Kind51
followed by CPU15 forces the native loop counter to its end while preserving its
original position snapshot: that branch emits finish but does not reset recovery.
Both original fixtures assert zero delete calls, cursor2 and active recovery.
ACK finish also changes a caught driver's native category to35 on the same
exception instance; the driver status remains unchanged.

The per-CPU P5 reconnect handler catches only CJ2534; CP and foreign native
exceptions escape. CCan catches CJ2534 and CPass there. Both initial-error
reconnect handlers catch those two typed categories and preserve foreign native
exceptions. A caught reconnect error publishes its signed category and driver
status, then repeats the existing GUI state without applying password state
again. P5 skips its earlier progress resets on this repeat; CCan retains its
post-readback resets. Independent raw checks inject a second fault after an
actual accepted retry to exercise these scopes.

The accepted CCan retry tail emits virtual30 `PrepareReprogramming` command05,
using the error category saved before GUI reset. It does not substitute virtual60
`CheckFinish` command3e. A real69 CGW startup followed by a CCan fault, accepted
retry, legacy AES gateway transition and complete retransfer passes on both
originals. Original18 additionally runs AutoIG; original12 does not. The actual
M16C reset replay asserts all37 raw protocol5 frames and the protocol6 reconnect.

Current source review remains OPEN. The MainFrm event that produces automatic
recovery `RetryMode=true`, original18's modern CGW registered online-key sender,
final manager/replay routing and whole-branch independent review remain explicit
dependencies. CPU54's complete replay uses an explicit one-million primitive-call
budget; its71000 calls exceed the shared runtime's65536-call default.

The current reproducible controller check is
`PYTHONPATH=. python runtime/no-car-68/check_execute.py --mode all`. Its output
records input hashes before and after all checks and rejects concurrent source
changes. The fixture defaults to the actual58 `execute(context, io)` factory
route. `manager_route=False` is reserved for isolated controller-scope observers
and does not demonstrate manager integration. The same CPU22 input asserts one
finish read (TX indication) on12 and
two (TX indication plus ACK) on18. Older `ccan-finish-ack-unwind.json` results
that treated12 as an ACK controller are superseded by this version-aware check.
The positive matrix also covers both source CPU19/73 thirty-block range tables,
CPU20's individual interframe CheckID with Kind47, CPU98's endian/range-gap path
and CPU216's Kind0 finish predicate. Images follow the actual native geometry;
these branches cannot use a generic1KiB fixture.
