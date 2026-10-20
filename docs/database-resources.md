# Diagnostic DDR primitives and stored resources

`capture_section` and `capture_file` in `scripts.database_resources` inspect the
native `MILMessage`, `MktMonRam`, and `MktMonRamSSR` sections. They reuse the existing
TSE codec and native feature/index selection. They perform no communication and
load no vendor library.

```python
from scripts import snapshot
from scripts.database_resources import capture_file

file = snapshot.load("recording.tse")
capture = capture_file(file, "MktMonRam", source="recorded_unverified")
print(capture.summary())
# capture.raw retains the original section; resources retain exact raw buffers.
```

Each resource retains its original index path, raw strings, optional raw block
identifier, and every buffer. The section and enclosing file have separate SHA-256
identities and the native section offset is retained. No write occurs. An explicit
source label distinguishes authored examples from unverified recordings; it does
not certify the recording or its vehicle origin.

`MILMessage` is the native MIL message information section (feature `0x271b`).
The native getter/setter exports independently identify its meaning.
The first list contains message screens; the second contains confirmation screens.
Each record contains three counted strings and two counted buffers. Individual
string/buffer roles remain unresolved and their bytes remain unchanged.
There is no established connection to `GetDDRInfo`, `GetADSDDRInfo`, or saved-log
producer outputs. This is not an embedded vehicle database loader.

MarketRAM contains named groups of counted blocks. Versions after `0x1000` store
a raw 32-bit identifier per block; older versions do not. Every block stores a
32-bit byte length. Native GUI converters copy the identifier, byte count and
buffer into the file-controller container without decoding the bytes. This
supports lossless stored-payload inspection, not numerical playback or full
engineering display. Empty blocks remain represented; empty named groups also
remain represented.

The summary reports buffer sizes and hashes. `payload_semantics` remains
`unresolved`, even for a structurally valid file. The native TSE codec enforces
its byte/node/version bounds and rejects truncation/trailing data. Cooperative
cancellation is checked before/after the bounded native parse and between resource
records; it does not interrupt a parser operation in the middle.

## Evidence boundary

Static observations come from Techstream 18's GTSFileController and native GUI:

- GFC `0x100a1d90` / `0x100a1e30`: feature `0x271b`, two MIL screen lists,
  three strings and two buffers per MIL screen record.
- GFC `0x100b67e0` (`GFCSetMilMessageInformation`) calls `0x1004c8a0`,
  copying this exact container. `GFCGetMilMessageInformation` reads it.
  `GFCGetMilMessageScreenCount` reads the first list count at root+`0x498`;
  `GFCGetMilConfirmationScreenCount` reads the second at root+`0x4a8`.
- GFC `0x100a23b0`: MarketRAM group/block reader and versioned identifier.
- GUI `0x46a1b0`: normal MarketRAM converter; `0x46a30c..0x46a394`
  copies block data. GUI `0x618618..0x618642` appends the converted capture.
- GUI `0x476130` / `0x476690`: SSR converter and exact buffer-copy helper;
  `0x51c236..0x51c25a` appends the converted capture.
- `GFCSaveFileDdrDataOnly` at GFC `0x100b8700` selects additional resources
  and feature flags `0x2711`, `0x2724`, `0x272a`. The actual `DDRData`
  container is vehicle control history: `GFCAddVehicleControlHistoryData` at
  `0x100b82d0` appends to the same root+`0x4c0` list selected by this writer.
- `GetDDRInfo_DT` imports RAM-block and DDR trigger/monitor/address operations.
  Imports establish dependencies, not the complete output schema or connection
  to the stored vehicle control history record fields.

The diagnostic DDR producer and saved-log workflows are not implemented by this
inspection API. Actual payload decoding and physical operation remain unverified.

## Native P4 RAM reads

`RamFrame` retains the exact eight-byte native frame descriptor. `ram_request`
uses the first selected A1 template: service byte, descriptor selector byte,
requested length, then the address in native big-endian order. `ram_payload`
validates the echoed service, selector, length and address before returning data.

`NativeRamReader` selects A1 from `VehicleProfile.frame_records`; each `RamQuery`
carries the exact selected function, communication and settings records plus
provenance to its typed exchange provider. It does not open a transport. The
provider must honor the selected transport settings and bound blocking I/O.

`read(address, length)` implements the native P4 low-word bank alignment,
block-cache fill and requested byte extraction. `read(..., real=True)` implements
DdrReal's uncached exact chunks and final partial chunk. Block size is explicit:
the actual normal record helper `0x3090` constructs it with `0x38`; other
producer branches can use a different explicit size.

The reader preserves its successful exchanges and native error replies as
`RamTransaction` records. Cache, retained recording bytes, exchange counts and
runtime are bounded. Cancellation is checked around I/O and between blocks.
Ordinary P4 malformed replies never enter the cache. `read(..., pcs=True)`
implements native PCSDdr policy for cached and Real reads: the first consecutive
failed I/O supplies `0xff` bytes; a second failure propagates. A successful I/O
resets this flag; a cache hit does not. Original failure statuses/replies remain
in the recording, so synthesized fill is not presented as observed ECU data. This lower primitive alone does not
implement the upper diagnostic DDR/ADS/saved-log workflow.

Native source anchors are CommandCommon `0x45860` (P4), `0x45bc0` (DdrReal),
`0x45d40` (cache fill), `0x46210` (cache extraction), and `0x46440` (A1 request,
response checks and payload copy).

## Selected DDR records and recordings

`selected_ddr_record_plan(profile, spec_value, header)` reproduces the normal
producer's selected resource lookup. `spec_value` and the two header bytes must
come from observed diagnostic data. The shared `profile.ddr_records` owns table
selection, exception overlays and versioned keys. The returned plan retains the
trigger record, both prefix address rows and each monitor/address pair.
`DdrSamplePlan.capture` binds that plan to the same selected profile and native
frame `01 00 04`; it returns exact bytes and the producer's unsigned MSB-first
scalar. The sample address is `((record_index << 16) | address_record_u32) +
base_address`, preserving the exact native order of operations. No engineering
scaling is inferred.

`encode_ram_recording(reader, source=...)` produces a
`techstream-native-ram-v1` document wrapping the shared ordered native exchange
format. `RamReplay(profile, raw)` validates the selected DDB hashes, ECU category,
exception selection, exact A1 records, frame and block size before replay.
`replay.reader.read(...)` consumes the recorded transactions; call
`replay.assert_complete()` to reject leftover exchanges. Authored and unverified
recordings remain explicitly distinguished. Neither label establishes a physical
vehicle result.

`selected_ddr_less_a8_attribute(profile, logical_id)` exposes the explicit lower
LessA8 decoder only for selected B1/B2 PID groups. It uses selected function
`0x6b`, byte-39 PID and byte-38 native parameter with operation-local TEMP caching,
without A8 position expansion. This helper does not decide activation: all native
attribute slots initially use ordinary decoding. Only observed logical118 value2
with logical137 value2 or3 activates the native legacy B1/B2 override.
Missing attributes return `None`.

These primitives have authored request/reply, selected-resource, malformed-data,
error, replay-order, cancellation and bounds checks. Full DDR/ADS/P5 acquisition,
SaveLog communication-log setup, no-buffer connection, support routing and final
history report construction remain open software work.


`prepare_ddr_session(cache)` implements the actual normal producer's C3/C4 then
C1/C2 preparation sequence. It uses selected private DDB templates, native word
arithmetic, zero-challenge skip and selected receive mask/check validation. Each
invocation performs fresh exchanges and stops on the first failure.

`capture_ddr_record_samples(reader, spec_value=..., base_address=...,
record_index=...)` follows the normal record helper's two one-byte header reads
with a 56-byte block cache. It skips unknown trigger headers and returns the
selected plan plus `(monitor_id, raw_bytes, unsigned_value)` triples. One deadline
and exchange budget cover the whole operation. Native RAM failures skip the record while preserving the failed exchange;
selection failures, cancellation and deadline failures propagate.
`record.ordered_values` follows the native full monitor-table order, repeating
the first captured match when the table repeats an identifier. This is ordering,
not a validity decision.

`capture_ddr_timeline_samples(reader, record, base_address=..., record_index=...)`
implements native `0x3890` with a fresh 56-byte cache and one operation budget.
It returns the selected monitor/address plan, original timeline bytes and exact
unsigned samples. Native non-byte stride windows and eight-bit byte-offset wrap
are preserved; zero samples still require the native one-byte read. RAM failures
skip the timeline while preserving their status and reply. These raw values
precede native transformations and final vehicle control history construction.


`NativeRamReader.from_communication(channel, frame=..., block_size=...)` connects
the RAM producer to the concrete `NativeCommunication` send/receive algorithm.
It uses the selected A1 function, communication and settings records, and fresh
native direct transactions. It preserves the channel's observed bus identity in
each query and recording binding; native communication failures retain their
status and partial response. The typed lower operations provider supplies frame
I/O. No vendor library is loaded by this factory.


`select_ddr_attribute(cache, logical_id, connections=..., ecu_specific=...)`
implements native `0x1c930` candidate routing for the 41 normal producer entries.
It uses shared selected DB136/DB110 rows, validates the target category type,
reproduces the native type-20 DDR item bypass, and otherwise calls the concrete
DB130 support dispatcher. Native per-candidate support errors continue selection;
cancellation and host bounds propagate. A nonempty tuple of
`DdrEcuContext(category, bus_id)` filters by full-width exact category/bus equality,
matching native `0x6b6b0`. The native producer constructs this context from the
selected category and remembered bus; an empty list performs unfiltered selection.

The returned `DdrAttribute.read(target_cache)` binds to the actual selected target
profile, patches the native 6B/CA template and uses the operation-local response
cache. Ordinary attributes use shared support-position expansion and the canonical
Toyota decoder. Required logical118/137/136 also use ordinary decoding until the
separate observed legacy override applies. This is raw
attribute acquisition; complete group chronology and report production remain open.


`initial_ddr_attribute_plan(profile)` reproduces native outer preflight for all
41 entries: absent logical rows remain absent; a present logical group must
contain the selected current category. The plan retains that row's initial PID
byte separately from later target selection. After `prepare_ddr_session`, call
`plan.check_support(cache, ecu_specific=..., connections=...)`, then
`plan.validate_required()`. Present required entries118/137/136 must be supported;
requiredness is separate from decoding mode. After reading PID group0x21 and
logical118, `plan.with_legacy_group_override(spec, variant)` reproduces native
1d80: only spec2 with observed logical137 variant2/3 forces B1/B2 support and
LessA8. Otherwise `plan.group_supported(0xb1)` requires at least one enabled,
present B1 entry and support for every such entry.

`plan.read_group(cache, pid_byte, connections=...)` reproduces native `0x27a0`:
all present entries in the initial PID group read through one fresh TEMP cache.
An unsupported ordinary entry still uses its native index-zero candidate; only
group `0xb2` disables unsupported entries. It returns the updated plan and exact
`(logical_id, unsigned_value)` observations. `plan.read_one(cache, logical_id)`
reproduces `0x28d0` without group support suppression. Mapped targets use actual
`NativeCommunication` instances under the parent cache's aggregate deadline,
cancellation and exchange allowance. These primitives do not complete the upper
DDR/ADS/P5 report workflow.

`capture_ddr_attributes(cache, connections=..., ecu_specific=...)` now joins the
normal producer's complete attribute phase. It returns a `DdrAttributeCapture`
with the selected plan, ordered observations, specification and native capped
group count. It performs the preparation and support checks, reads group0x21,
requires logical136 value0xA0, reads logical118 ordinarily, applies native2dc0
bank and attribute-presence rules, then handles the observed legacy override or
B1 support before reading B2 and B1. Native group-count limits are7 forspec2/3,
9 forspec5 and11 otherwise. The existing cache operation's aggregate limits cover
all exchanges; this function does not reset a caller's allowance. This result
precedes record acquisition, transformations and final history-report conversion.

`select_comm_pid_target` exposes the same native target-selection engine for
other consumers; its returned attribute uses ordinary decoding. Native type-20
logical IDs 3/16 require the distinct tire-ID algorithm, which raises an explicit
`NotImplementedError` until recovered. The current selector implementation is
bound to native build 18; build-12 equivalence is not assumed.


`DdrPacketLog(common_documents, native_frame_operations)` implements the recovered
native-18 kind-2 file lifecycle and binds the concrete lower packet-log hooks.
Bind the retained `NativeFrameController` when communication can switch lower
classes; its hook survives those changes. A fixed `NativeFrameOperations` is also
accepted. The explicit root replaces only Windows common-documents lookup; the native
suffix remains `Techstream/EcuData/DDR.log`. Start opens a read/write truncated
file; repeated start on the same instance reuses it. Lower native operations
write uppercase hex of deframed application packets followed by the two literal
ASCII characters backslash+n. Stop removes one matching final literal pair and
closes the file. Actual LF bytes are retained. Native writer/close failures return
`0x90020706`; open failure leaves the lower logger unbound. The host output limit
defaults to 32 MiB and bounds writes without changing diagnostic transport status.
This file is distinct from the RAM exchange replay document. Normal native18 saved-log acquisition and formatting are implemented below;
TSE vehicle-history composition remains open.


Bulk DDR uses a distinct `01 00 02` descriptor.
`capture_ddr_bulk_record_samples(reader, spec_value=..., address=...)` implements
native `0xa0b0`: a fresh 24-byte DdrReal read, header-selected trigger/monitor rows,
record length, and scalar fields inside the header. It skips scalar addresses
outside those first 24 bytes before querying their monitor resources.
`capture_ddr_bulk_payload(reader, header)` implements native `0xa740` using a
56-byte Real reader for the remaining payload. Its shared pure
`decode_ddr_bulk_payload` implements `0xa970`/`0xad40`: additional scalar fields
and either packed bit windows or the address row's explicit byte stride. The
native unused 24-byte allocation prefix remains zero. Original header/payload
bytes and source plans remain available. Both stages support the same primitive
recording/replay API separately; full bulk scan ordering, transformations and normal report orchestration
are joined by the capture APIs described below.

`DdrValueSeries` retains native identifier/kind and ordered `(uint32 value,
uint32 flag)` samples. `ordered_ddr_series` joins both scalar and timeline lists
before native4090 first-match ordering. Duplicate monitor rows repeat the first
matching complete series. `transform_ddr_record` applies native42D0 for records
without a marker, otherwise the complete4390 chain:4430 marker numbering,
4CF0 trigger-pair existence, legacyB260 ranges,5230 selected invalid conditions,
BAE0 ID13 cutoff, and5580 pending-reference propagation. Raw values never change.
Flags remain native numbers; this does not assign inferred engineering labels.
Malformed indices/counts and evaluation budgets fail explicitly. Condition and
propagation cancellation are cooperative. Native4430's repeated ID19 rows and
5580's ordered pending queue are preserved, including their unusual behavior.

`capture_ddr_records(channel)` joins the actual attribute phase to the native
normal2/3/5 record banks or the other specifications' bulk scanner. It uses exact
observed base/count attributes, native24/56-byte reads, per-record RAM-error skips,
selected cutoff and transformations, and signed32 subtraction sorting on IDs7/10.
The retained `NativeCommunication` cache supplies one aggregate communication
budget. `DdrCapture.transactions` retains header/payload/timeline wire chronology,
including skipped reads. Each captured record retains its group/address, source
plan, original RAM bytes, timelines, and transformed series. `format_ddr_capture(profile, capture)` builds the recovered normal CCmdDdrInfo
report; `capture_ddr_report(channel)` joins both stages.

`capture_ddr_records_saved_log(channel, log)` runs the recovered native18 saved-log
record phase: resource preflight, start kind2 log, invalidate A8kind1, no-buffer
connection, observed category/bus-specific capture, then conditional stop. The
packet log must bind the exact retained channel controller. Start failure still
allows acquisition, skips Stop, and becomes the result error when acquisition
succeeds. Stop failure replaces success while preserving an earlier acquisition
failure. These status rules are distinct from logging file lifecycle checks.
`capture_ddr_saved_log(channel, log)` also builds the exact61E0 report before
Stop. Normal formatting removes monitors with BYTE43==2; SaveLog preserves them.
SaveLog shares one command-owned TEMP across all attribute phases, unlike normal
fresh phase caches.


`format_ddr_info` retains raw samples and joins selected monitor/physical/unit/
pattern/language rows, paired trigger bytes, trigger names/memos, scalar fields,
extra metadata3 and native main/side timeline cuts. `DdrReport` includes observed
logical103/spec118, optional159..171 presence/masks, and native filtered monitor
catalog with backing rows. Empty captures preserve native no-format behavior.

`DdrPacketLog.start(kind)` (also `start_comm_log`) supports the recovered native12
and18 file lifecycle. Names0..19 match both sources; native18 adds20..26. Each
build enforces its own upper bound. Start reuses an open same-kind handle and
rejects another kind; Stop trims only one final literal backslash+n pair. The
explicit common-documents root remains caller supplied.

P5 is a distinct producer. `initial_ddr_p5_attribute_plan` retains the exact45
Common412C0 logical entries and selected WORD34 DIDs. `capture_ddr_p5_attributes`
runs C1/C2 preparation, actual52 DID support, spec118, native bank disabling,
support selection and DID1401 reads with one shared command TEMP.
`DdrP5DataIdReader` uses the selected CA template and actual supported DIDs,
retaining status, partial response, payload and TEMP hit provenance.
`capture_ddr_p5_raw_records` runs all selected header DIDs first, then case groups
with separate TEMP lifetimes. Unknown/failed/unsupported records follow native
skip/break rules. It retains original header/case bytes, selected plans, the
zero-initialized4096-byte decoder buffer, timelines and actual DID chronology.
P5 packed extraction preserves native windows; explicit strided selector0x22
swaps bytes0/1 before extraction. Case DID mapping and inclusive native range
removal are source-bound. Host bounds reject the native overflow branch's unsafe
512/4096 subtraction rather than reproducing an out-of-bounds write. This API is
an acquisition stage: `capture_ddr_p5_records` applies the native marker/condition/link rules, first-only
BCD conversion111..116 and literal signed-comparator pair-swap sort.
`capture_ddr_p5_report` adds native3C7C0/3CE00/3F0D0 presentation, additional
byte fields117/111..116 and410E0 CSV support values170 and177-fallback171.
An empty acquisition bypasses formatting, matching native Execute.
`capture_ddr_p5_saved_log` uses the concrete outer controller: Start2, no-buffer
connection, acquisition/report, Disconnect1, then conditional Stop. It does not
invalidate A8. ADS uses the separate path below.


ADS lower primitives are separate from normal P5 support enumeration.
`DdrP5DataIdReader(cache, enable_list=False).read_no_enable_list(did, control)`
implements69C70/6A0C0 global bitmap0101, group bitmap and data stages with shared
TEMP and literal native states1/2. `cancel_ads_security(cache, key)` uses selected
109/10A templates, exact16-byte seed, zero-seed bypass, and AES128 block appended
to the full selected key prefix. `selected_ads_security_key(original_common_pe)`
extracts its material from verified instruction immediates in the exact supplied
native18 module. It reads bytes only; it never imports or executes the PE. Public
code/test files contain no vendor key constants. Authored NIST known-answer,
request-prefix, zero/short-seed and bitmap/TEMP tests cover these lower stages.


`capture_ads_ddr_report(cache, key)` joins selected native18 ADS security,
no-enable readiness, behavior/index/record exchanges, grouped DID parsing,
64-bit decoding, validation and native command formatting. Raw captures retain
all selected resources, partial replies and transaction statuses. Logical values
retain unsigned64-bit data and native missingflag3; header/marker conditions,
24-byte invalid rules, BCD6..11 and scalar/timeline propagation are distinct from
normal DDR. Reports retain trigger resource IDs and separately selected text,
metadata-backed scalar channels, raw byte/mode fields, marker groups, main/side
channels and monitor catalog. `format_ads_ddr_info` and
`format_ads_ddr_capture` expose the same pure source-bound presentation stages.
Optional RoB data-ID bit references resolve selected slot89 plus the exact
management variable DID and require a nonzero type7 bit in the same packet group.
Missing resources retain the native invalid/missing result. Pure decoder/transformation loops enforce
cancellation, sample and work budgets.

`bind_ddr_report_header(section, report)` fills the source-proven normal DDR
saved-header fields of an existing complete `DDRData` record: observed maximum
recording count103, specification118 and13 ordered support/value pairs159..171.
It preserves all other record fields and supports native versions1004..1027.
The bridge serializes through the native report codec and does not manufacture
unresolved whole-record content.


`ddr_saved_information(info, version=..., encoding=...)` converts normal/P5
command information into the exact b1340/b1760 wire pair, including scalar
conversion, metadata, memo IDs/text, main/side channels and separate validity.
`bind_ddr_report(section, report, encoding=...)` fills this pair list, header and
monitor catalog in an existing complete DDRData record. P5's final stored slot
uses observed177 when present, otherwise171; its stored normal slot label remains
171. Native1004..1027 layouts retain the versioned tails.

`ads_ddr_saved_information` and `bind_ads_ddr_report` provide the separate native
ADS b2190/b2560 pair/list at versions1009..1027. Extended signals retain full
uint64 raw values, native metadata, sample text/type and separate validity arrays.
The1009 legacy extra signal/byte is omitted beginning100A. Both binders preserve
caller-supplied common/context fields; neither fabricates a whole-history record.

CommandAPI06AD0/06D80 call ConvertData05F70 before saving each sample CString.
The producer uses the existing source-derived `signal_display.render_signal`,
with exact narrow-byte handling for character selectors and explicit low/high
words for float64. Sample type remains0; validity occupies its own arrays.

`DdrPacketLog.change(kind)` (also `change_comm_log_file`) implements native
ChangeCommLogFile for12/18: inactive no-op, otherwise close/create even for the
same kind, retaining the active flag on failure for the outer wrapper to stop.
`DdrP5DataIdReader(..., no_init=True)` preserves the ADSOperation no-init setting
inside its own temporary response scope and restores the caller's flags.

`NativeRamReader.read_end_trim(length, cancelled=...)` implements the separate
native12:31690/native18:459D0 P4EndTrim path. It starts at the frame's exact address,
reads uncached block-sized requests and shortens only the final request. Native
post-I/O status and reply-validation failures produce an FF-filled chunk and the
next chunk proceeds; host cancellation, budgets and address-overflow rejection
remain visible. Zero length performs no I/O. `from_communication` binds both
builds for this operation; cached/Real `read` remains explicitly native18-only.

The authored selected92 normal/P5 integration check uses actual
`NativeCommunication.send/receive`, selected CommDid attribute bytes, native A1
RAM reads or actual C8 DID bitmap/header/case reads. It checks exact chronology,
report values, saved DDRData and named parameters without replacing a capture
stage. `runtime/no-car-49/emit_selected_ddr_fixtures.py` emits full native TSEs,
authored DDBs and a hash manifest under the private49 evidence directory for GTK
review. Surrounding caller context uses explicit minimal layout defaults.

`DdrPacketLog.get_size()` returns native `(status, size_or_none)` without moving
the cursor. `set_pointer(offset)` performs the native FILE_BEGIN seek **and
truncate**, including extending the file when a bounded offset exceeds its
current length. Both build12 and18 implementations use this sequence. Rollback
restores the host byte allowance; the image caller owns stopping after an error.

`capture_internal_ddr_report(channel, p5=..., connections=...)` implements the
reachable native12 and native18 inline normal DDR path against canonical
selected BC metadata on the retained controller and bus0x12. Native12 requires
the authored `0x0100030C` DDB schema, supports specifications2/3/5/6/7/8, and
rejects P5. Native18 retains its existing schema and P5 behavior. Inline normal
DDR reads only preparation/signature/specification/B2 and writes the13 support
objects; its native trigger list stays empty, so it performs no B1 data/RAM/row/
catalog acquisition and no disconnect. P5 disconnects the shared controller
while keeping the caller's host context available. Native12 external DDR
record/report and saved-log routes remain unsupported.

`ddr_report_support_values(report)` exposes the two actual receiver support
objects: normal logical170/171, or P5 logical170 and177-primary/171-fallback.
Presence and values remain distinct, including an empty successful report.
The native final monitor-catalog call runs after these receiver writes. A
`DdrPartialReportError` preserves its native status and `partial_report` when
that final call fails, so image consumers can use already-written support for
their native header filter without treating the inner command as successful.
Earlier acquisition and row-format failures do not invent partial support.
The inline normal image helper bypasses row/catalog formatting entirely;
that helper cannot produce the final-catalog partial failure.
