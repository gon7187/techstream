# Original executable vendor programming

The module implements original12/18 CAN EMPS controller composition and the
source-bound DCM, DH and FHI Execute and TechVim finalization predicate. Full vendor-family
acceptance remains open pending independent review and remaining controllers.
It must not be advertised as a working vehicle programming path.

EMPS routine stages use `31 01`, `31 02`, and `31 03 <sum modulo 256>`.
Download uses fixed native address/length pairs, not the supplied image length.
Transfer sends `36` plus at most 240 bytes, without a sequence counter; exit is
`37`. Positive diagnostic payload checks preserve native error codes and accept
trailing bytes as the original helpers do. The four-byte CAN identifier belongs
to the transport envelope and is excluded from these helper inputs/outputs.

`EMPSWire` implements the native receive helper over complete PASSTHRU_MSG
objects, preserving RxStatus and the channel flag used by mode 2 filtering.
Matching pending replies use 5000 ms after the first response. The 150th pending
reply sends `3e 02` and raises the caller's operation error. A nonpending reply
resets the timeout to 1000 ms; an exception retains the current timeout.
Byte-only replies are rejected because they discard native RxStatus.
Writes preserve the native channel padding bit in TxFlags, clear the receive
buffer before sending, and await the matching transmit indication through the
shared executable CAN helpers.

`write_region` composes the recovered routine/download/transfer/exit/checksum
chronology over the concrete read/write primitives, including empty images and
partial final chunks. Main-region acknowledgments publish the doubled byte count
and truncated percentage through the native scalar notification fields. Percentage
arithmetic rounds both native x87 operations to the source runtime's 64-bit
significand before truncation; host binary64 arithmetic differs at some boundaries.
Helper
J2534 catches retain the raw driver DWORD and rewrite only the native category;
a region result is not an Execute result.

`prepare_emps` admits the selected executable, decodes its startup frame operands,
sets parameter `0x23` to `2`, acquires both native flow-control filters, and sends
the startup frame three times with 100 ms after each transmission. The shared
host runtime retains acquired resources when a later primitive fails. Native
filter-stop chronology is handled by `EMPSController`.
Session selection tries both native header pairs in order: only read failures
with driver status 9 or 16, or mismatched positive response shapes, try the next
pair. A write failure does not select another pair.

The original12/18 security helper validates the native seed/acknowledgment shapes
and reads the fixed key operands from the explicitly supplied original executable
after the shared build/SHA admission check. Authored code contains no native key
literal. The source helper does not derive a key from the returned seed.

DCM wire helpers use the shared source `45d458`/`43b6fc` policy with five-byte
headers, separate busy/pending budgets, and both native 100 ms waits. They preserve
the sequence byte, low 24-bit download fields, response minimums and checksum byte
order. Its two-byte seed conversion reads its operands from the admitted original
image; a short response retains the zeroed native receive-buffer tail. Header,
region and countdown are bound by `DCMController` to actual imported context.

`DCMController` composes original12/18 native address-factory selection with the
first record's exact three-byte slices right-aligned to five-byte diagnostic
headers. It retains the distinction between first WORK image size (1024-byte block
vector) and indexed compacted CPU image data. Bounds reject native overreads
before I/O. Transfer publishes doubled acknowledged byte counts and x87-derived
percentages against the selected image size; percentages may exceed 100 when
native first/indexed sizes differ. The countdown chooses its source-bound
15000/660000 millisecond branch, publishes immediately after the first acknowledged
transfer, then decrements in 500 millisecond steps after reset.

DCM Execute handles manager retry-mode reset/wait, separate setup/programming catches,
explicit foreign-native catch-all identity, filter stop, error prompt/reconnect,
second-phase progress reset, and native completion. Unknown host exceptions retain
their type. Host cancellation restores the entry timeout using the cleanup budget
and releases filters without a native completion callback. Native retry only sets
the manager retry-mode RAM flag; it does not silently start another programming attempt.
Actual original12/18 SHA-bound composition runs imported authored CUWs through
concrete driver primitives with both CPU indices, retry-input, typed transport
faults, and host cancellation. Independent full source review remains open.

Source-derived headers come from startup initializer operands, since the native
header globals are uninitialized in the file. EMPS dereferences the first native
WORK image/flash-code pair without the explicit image index used by DCM. Shared
compacted WORK-vector binding is still being integrated; selected-CPU synthetic
success does not establish this producer. Main SREC transfer length is the sum of data lengths, so
native programming uses that prefix of the materialized span. Overlapping records
that would cause a native buffer overread are rejected. A VBF main image keeps its
flash-code record raw, including a record that happens to begin with `S`.

Source-specific helper catches rewrite only the native J2534 category; the raw
driver DWORD remains separate. Host cancellation and validation errors retain
their own type. Focused fault checks cover every implemented helper category.

Full EMPS/DCM entry points require the actual mutable `ChannelState` in their
executable context. Common CAN and session helpers share that same state for
read/send timeouts and padding; provider getter snapshots cannot override it.
The EMPS constructor timeout remains separate from the Execute-entry timeout.
DCM captures its restore timeout at Execute entry, including a native RAM change
that occurs after the Python controller object is constructed.

`EMPSController` keeps configuration outside the two typed native catch scopes,
skips the second phase after a first-phase failure, and preserves separate native
category and driver status fields. The native stop scope skips the second filter
after a first stop failure; a separate host cleanup pass then handles resources
still owned by the runtime. Native completion and host cleanup results are reported
separately. The constructor timeout snapshot is restored after native error handling.
Host cancellation/deadline aborts use a separate cleanup budget to restore the
captured entry timeout, then release owned resources. They preserve the abort,
attach cleanup-failure notes, and emit no native completion callback.

The TechVim binding compares imported base ContactType/KindOfECU against the
admitted original executable's string resources and retains global CPU count/index.
The matched success callback pair remains a controller precondition. The predicate
alone does not authorize finalization.

Outstanding gates include the full TechVim controller, whole-family
independent source review, and the final getter/manager/recovery and outer resource
lifetime composition. Current source-bound EMPS/DCM/DH router checks cover the
implemented paths and do not close every original12/18 branch or manager behavior.

No vendor binary is executed and no device, network or authorization service is
called by this module. Source-bound seed/key transforms run only in authored code.
Tests cover the recovered byte layouts, minimum response lengths, error
codes, checksum wrapping and the TechVim branch truth table.


`DHController` follows original12/18 CPU resource-table selection, nineteen-round
seed conversion, shared channel state, and source-specific raw protocol 5 startup.
The special CPU does not require a flash-code record: it connects protocol 5,
writes the native raw mask three times without a transmit-indication read, then
reconnects protocol 6. Other CPUs use the ordinary mask/session path. Only the
security call has the inner typed CJ retry scope, with raw status 9/16 and thirty
retries on the source-selected kind/CPU combinations. Mask and session failures
do not enter that retry loop. CPass and foreign/host exception identities remain
separate.

DH download and verification-download lengths use the first WORK image's full
materialized span (`Length`), while each main transfer uses its `FlashSize` prefix.
These differ for sparse SREC input. The loader uses its own materialized length.
Block negotiation retains native unsigned subtraction; zero divisors and native
stack-buffer overflows are rejected. Main transfers publish local half-percent
progress and cumulative acknowledged bytes; loader notifications retain zero
progress. Native tail restores both constructor timeout snapshots. Host abort
restores Execute-entry timeouts before runtime cleanup.

The source-bound private DH matrix calls the real `engine.execute` router on
original12/18 admitted images and authored imported CUW files. It covers all seven
CPU-table rows, special CPU without flash code, selected CPU 1 with unindexed
first WORK data, multi-chunk images, sparse Length/FlashSize differences, native
retry/error UI, protocol 5 faults, host errors and cancellation. Independent
review confirmed the security EH boundary and sparse service/transfer lengths.
Whole DH/FHI source review and the remaining TechVim getter/controller lifecycle
remain open; these checks do not establish hardware behavior.


`FHIController` composes original12/18 grouped native CAN operations. The first
address-factory call uses the actual configuration for probes and per-node
sessions; the second passes no configuration and selects the programming header.
Kinds 31 and 32 therefore retain different programming targets even when the
configured candidate list is identical. The optional TCM absence and already
programming branches preserve their typed CJ status 9/16 handling.

The initial wait reads `WaitTimeAfterIGOn` from the first CPU's actual parameter
catalog with native long-prefix conversion. Read timeout is 180 ms for broadcast
disable-DTC, then 500 ms after its 120 ms wait for communication control. Security
and ordinary transfer use 2000 ms; erase uses 5000 ms and verification readback
uses 10000 ms. Native tail restores 2000 ms, while host cancellation restores the
Execute-entry timeout. Group operations retain one native batch write, the first
request's transmit indication, and the source remaining-header read counts.

FHI's two sixteen-round key arrays, substitution table, four routine values,
flash base and address width are extracted from the admitted original image.
Download/upload lengths use the first WORK materialized span; writing and readback
verification consume its `FlashSize` prefix. B6/B7 requests carry the native
address rather than an invented sequence counter. Negative group replies permit
three retries; pending responses retain the separate 149-response budget.

Current FHI source-bound tests pass through `engine.execute` with original12/18
images and authored imported CUW/catalog data. They include both kinds, positive
and missing TCM paths, already programming, service faults, retry/pending, error UI
reconnect, sparse images, selected CPU 1, and host error/cancellation identity. The
500 ms transition was independently reproduced as a failure and rechecked after
the fix. Whole FHI source review remains open until the independent reviewer
finishes the remaining initializer, EH and consumer checks.
