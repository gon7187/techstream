# CUW2026 calibration values

`scripts/calibration_2026.py` reads a complete, bounded CUW byte container and
produces the metadata consumed by the native2026 adapters. It does not execute
OEM code or open a vehicle transport. Its record value types are shared with
`calibration.py`; none of the older metadata readers or record binders is called.

`parse_cuw_2026(bytes)` verifies the signature, total length, container CRC32,
record framing and each record CRC32. `native2026_metadata(container, node=1,
cpu_index=0)` independently reconstructs that framing and checks its SHA256 before
binding records. Reports omit metadata values, keys, signatures and firmware.
Original section dictionaries are immutable and remain available as `sections`.
`vehicle` and CPU values contain the recovered historical name conversions.

The `GetCPUType` dossier historically grouped under no-car-5 is for the exact
CUW2026 `TCUWCalibrationFile.dll` identity (SHA-256
`3fb44c9ac011d5be1affd04305a8455c113b107655cc250e31ff937dd5d72950`,
FileVersion `1.0.0025.0`). Its `0xae9c` CPU-record stride is CUW2026 evidence;
it does not establish the registered CUW18 layout, which remains unresolved.

The native Format.Version values are literal integers, not an ordinal remapping:
`2,3,4,5,6,7,8,9,10,12,40,101,103,104,105,106,107,206,209,300,400,500`.
The outer byte versions are separately checked against
`1,3,4,5,6,7,8,9,10,12,101,102,103,104`. Outer version1 does not authorize a
metadata Format.Version1. Metadata9 uses a two-byte record count.

Historical2/3 use the exact case-sensitive CUW2026 constructor tables (49 CPU
names and21 ECU names). The native CPU10/SIL exception becomes CPU9. Metadata4
retains its populated01..04 CPU image names and trailing flash-code record.
Metadata9 retains FileNxxx records. Metadata10/12 require one CPU01; their
StartAddress is a variable-width byte string. Download sizes use hexadecimal
conversion; an uncompressed size of0 remains0 for the consumer's native fallback.
CPUType and LocationID are empty in10/12 and modern formats because those parser
branches never read the corresponding INI fields. Raw aliases remain only in
`sections`. A later explicit runtime SetCPUType transition can change CPUType.
Ordinary historical CPU rows likewise do not read CompressionAlgorithm,
SecurityProperty2, ReproMethod, OffsetAddress or P4ServerMaxTime; their effective
values stay empty/zero.

Modern nodes select the logical schema for RequiredSpecReproVer03,04 or01;
02 and10 use CPU rows. Mixed nodes consume records in native node order.
Logical slots1..32 are scanned until the declared populated count is reached.
NewCID deduplication assigns the actual global CPU index. The06230 exported CPU
vector stops at the first row whose four identifiers and declared target values
are empty. `cpu_rows` and `cpu_node_indices` retain that exact exported vector.
Mixed189e0 record ownership remains separate from the exported prefix; a logical
block referencing a CPU outside it is rejected before use. The global getter
helpers `native2026_cpu_values`, `native2026_cpu_type`,
`native2026_location_id`, and `native2026_new_calibration_id` accept that global
index; `metadata.cpu` uses the selected node's CPU ordinal.

The seven logical area strings have distinct meanings:

| Native offset | Input field | Public value |
| --- | --- | --- |
|00|StartAddress|`address_bytes`, `address`|
|18|Length|`length`|
|30|CRC|`crc`|
|48|CMAC|`cmac`|
|60|DigitalSignature|`digital_signature`|
|78|TransferLength|`transfer_length`|
|90|CheckData|`check_data`|

CMAC, DigitalSignature and CheckData retain explicit input bytes; protocol
consumers validate the width their operation requires. CheckData is not silently
substituted with either signature field. Keys require explicit sixteen-byte values. Their CUW wire fields use the
actual2dae0 codec: pairs of hexadecimal characters encode bytes, and each decoded
byte has its index subtracted before the resulting hexadecimal text reaches
CBytes. Vehicle/node ECUAuthKey and ServiceAuthKey, CPU SeedKey/Nonce, and logical
Nonce use this codec. Historical TargetData and NewPassword use it before numeric
conversion;8/9/10/12 and modern TargetData remain native zero. SeedKeyID in10/12
is decoded as text; OffsetAddress remains a plain hexadecimal field.
`decode_metadata_string_2026` preserves the native byte arithmetic, including its
lowercase-nibble behavior; `encode_metadata_string_2026` builds authored fields.
There is no plaintext-key fallback. Nonsecret Nonce and OffsetAddress use the
native zeroed CBytes backing: a fixed first16 or first5 bytes are copied, padding
short or absent values with zeros and truncating longer values. SeedKey and
authorization getters retain the host requirement for explicit sixteen-byte
inputs. No embedded key or authorization bypass is supplied.

Node hexadecimal timing values retain native units: WakeUpTimeAfterReset and
WaitTimeAfterProgrammingSession multiply by50, EmissionsRelatedSystem by10,
ChargeLocalBusEcuStartTimeAfterPowerOn by50, and IntervalTimeBetweenFrame has no
multiplier. Modern CPU/logical P4ServerMaxTime multiplies by60 and defaults to03 when the
field is absent. Historical CPU P4ServerMaxTime remains native zero. Windows signed32-bit strtol saturation precedes DWORD timing
multiplication. Gateway fields use01_,02_ prefixes, not an unnumbered alias.

`native2026_archive(metadata, flash_code=False, preserve_srecords=False)` returns
`NativeArchive2026`. The caller must supply the selected
FlagToHoldSFormatRecords value for an ordinary CPU S-record archive. The result
separates `data`, `length`, `flash_size`, `header`, `header_length`, `records`,
`kind_records`, and original `raw` bytes:

* 10/12 and the native case-sensitive `.vbf` filename branch retain binary bytes.
* Metadata4 multi-image archives use mode1 S-record conversion. The first image
FlashSize is the sum across its image list; other images retain individual sizes.
All multi-image GetLength values remain0 and headers remain empty: the native
export copies only data and FlashSize. Its flash-code archive retains FlashSize0.
`file_index` selects a dense global image ordinal; without it, the selected global
CPU chooses its corresponding image. Only CPU0 retains the physical slot list.
Metadata4 without indexed image names uses ordinary CPU archive classification.
* Metadata9 file archives convert a leading S-record and retain other raw bytes;
file FlashSize remains0. Effective ALFID DownloadAddress adds the first S-record
address and DownloadMemsize retains the original value, formatted to native widths.
`native2026_cpu_file_flash_size` exposes the separate CPU accumulator that divides
each file data-byte count by two. Original metadata stays in `sections`.
* S-record binary mode retains S0 payload bytes and an FF-filled first/last data-row span;
FlashSize counts actual data bytes rather than gaps. Retained-record mode has
`data=None`, keeps the original encoded length, and excludes the first S1 payload
from FlashSize while counting every S2/S3 payload.
* Intel HEX retains an address map and `data=None`. LZF hexadecimal parsing retains
ZV frames without decompressing them.
* Flash-code S-record checksum mode2 applies only to KindOfECU149/CPU311. It uses
a checksum sum of0; ordinary mode uses255.

`native2026_logical_archive(metadata, block, kind)` applies the actual189e0
ownership and41670/48670 classification. Method00 has no separately owned routine
archive. EraseMemory and segment geometry likewise create no archive. Version500
reads an owned routine before whole data; other versions read whole first.
Raw206/209/400 logical archives retain FlashSize0. Other versions can create
S-record maps; `.binx` whole/routine names skip that transformation.
`native2026_logical_cpu_flash_size` computes the distinct13d20 aggregate.

CPU TargetData becomes0 in metadata8/9/10/12 and modern formats even if an unused
field is present. CPU target arrays preserve trailing empty slots; native05e80
rejects populated slots after an empty slot and nonzero data without a target name.
Logical blocks sharing a NewCID contribute a first-seen distinct target union to
their synthesized CPU; validation applies after that union. `native2026_cpu_targets`
uses the selected CPU by default and accepts an explicit global CPU index.
The synthesized CPU retains constructor P4ServerMaxTime0; each logical block's
pending limit is a separate field with its own hexadecimal conversion and default.
NewPassword is read only by the ordinary historical CPU schema.
`native2026_new_password` uses an explicit NewPassword first, otherwise a bounded
PasswordAddress into a materialized image: ByteOrder with a zero low16-bit word is little endian; a nonzero low
word is big endian. `native2026_archive_password` performs the archive getter
directly and ignores a CPU NewPassword override.

Host limits are explicit:64MiB complete containers,1MiB metadata, bounded counts,
strict INI duplicates/defaults rejection, bounded numeric and hexadecimal fields,
and rejection of overlapping S-record/Intel HEX rows. These are memory-safety
policies, not inferred OEM limits.

The separate `cuw_large.native_large_cuw_2026(path)` producer verifies a file-backed
large container without loading it into memory. `native2026_metadata` accepts only
its issued container objects, validates the backing identity and retains
`source_container`. Large logical areas have `data=None`; their records expose
bounded reads. `native2026_logical_archive` applies the recovered36f30 branches
for107/209/500 and returns `streamed=True`, a 0x144-byte (324-byte) materialized descriptor in
`data`/`raw`, and the issued `LargeMaterialization2026` in `backing`. Its `length`
remains the original payload length, as16030 retains that separate archive field.
Individual logical `flash_size` remains0; the CPU total is a separate getter.
The caller keeps the container open and validates the materialized backing before
streaming. Large CPU archive classification and USB external source regions remain
open and are rejected by this module. A manual stream flag is insufficient.

Logical CPU archives remain separate from their owned logical-area archives:
their GetData is null and GetLength0, while GetFlashSize is the CPU aggregate.
`native2026_archive` preserves this distinction and creates no concatenated image.
An absent flash-code archive likewise returns empty native fields. `records`
retains parsed source rows for inspection; `mapped_records` and `record_count`
expose the actual retained-map state, which is empty for materialized binary data.
Retained S-record maps include S0 headers alongside S1/S2/S3 data in source order;
S5 counts and termination rows are excluded from that map. `records` remains the
data-only convenience view and `kind_records` retains source kinds for consumers.

Metadata dataclasses are producer return values, not a certification of arbitrary
objects constructed by application code. Production consumers must obtain them
through `native2026_metadata`; direct dataclass construction is outside that
contract. No physical adapter or vehicle has been tested.

`native2026_with_cpu_type(metadata, global_index, value)` represents the native
SetCPUType transition and returns an updated context while retaining original
metadata sections and source identity. `native2026_export_state` returns only the
current global CPU types and an explicitly supplied runtime shrink flag, matching
ExportData. Consumers carry the updated context between operations; the source
container itself remains immutable.

`native2026_metadata_for_cpu(metadata, global_index)` reselects a CPU through the
original validated container and preserves runtime CPUType overrides. It maps a
logical CPU to its first matching block without fabricating node or CPU geometry.

`native2026_header_info(metadata, kind)` retains the native header's DataFormatID
and every StartAddress/Length string, including zero, empty and nonnumeric values.
Its `count` is structural. An operation requiring numeric geometry must explicitly
call `numeric_areas()` and enforce its own bounds before I/O. The older CPU area
tuples are convenience views and cannot establish that a declared header is valid.
Modern header DataFormatID remains empty because that parser branch never reads
the field. Modern effective CPU values contain only fields read by their schema;
unread aliases remain available solely in the original `sections` mapping.

The `region` argument is the zero-based region stored by the native file-import
entry points. It selects the SCC vehicle projection from VehicleForNA or
VehicleForEUOT, with native partial/empty fallback rules. The context retains it
through CPU reselection. Vehicle System takes precedence over EngineType before
that projection. KindOfCal flags compare their decimal values with1.
`initial_shrink_flag` derives from all declared converted CPU rows, before the
exported CPU prefix truncation: every NewCID must match one of that CPU's targets.
An engine must seed its runtime flag from this value and export its current flag.

Metadata4 CMACForCPUImageData and CMACForFlashCodeData use the encoded string
codec and are available through `native2026_cpu_cmac`. Other schemas leave them
empty; the consuming protocol validates its required field width.

`native2026_with_parser_parameters(metadata, general)` validates the native
historical M16C/FOREST condition using the concrete General Parameter.ini source.
It reads every declared CPU's M16CTypeFlag and, if any is true, requires at least
one FORESTTypeFlag. Missing rows throw the actual parameter lookup error. Modern
and10/12 schemas skip this lookup. CPU reselection preserves this validated state;
the caller must also bind the General source to its selected catalog.

DateOfIssue remains a raw-source field with an open presentation contract. The
native parser uses MSVC time_get with `%Y-%m-%d`, then the native user's locale
with `%x`. `native_date_of_issue_components_2026` and the context's
`date_of_issue_components` implement the recovered numeric parser for ASCII ctype
whitespace, including width limits, signs, trailing text, year0 and February31.
They return components rather than imposing a calendar validation. Additional
locale ctype bytes and Windows `%x` presentation remain open; Linux date parsing
or a hardcoded date format is not claimed equivalent.

`native2026_file_header(metadata, caller_header, date_presentation=...)` and
`native2026_file_cpu(metadata, global_cpu_index, caller_row)` serialize the parser
fields of ReadReprogrammingDataFile's 0x98-byte header and 0xbbac-byte CPU rows.
They return new bytes, preserve caller padding and reject fields that would
overflow their native destination. Header strings are DateOfIssue, VehicleName,
ModelYear, VehicleType and EngineType; CPU row offset0 is NewCID, not the image
filename. Target diagnostic strings use the CPU's node DiagID, falling back to
LogicalAddress, and retain the native six-byte truncation plus NUL.
The engine owns header flags at5f/60/8c/90 and the CPU DWORD atbba8; these helpers
preserve them. Mode handling, multi-file grouping and one-based region conversion
belong to the engine wrapper.

A valid DateOfIssue requires `native2026_date_presentation(metadata, formatter)`.
The platform formatter receives the exact parsed components and returns native
locale presentation bytes. Its registered result is bound to the original
container, raw date and components; copied results and same-hash reparses are
rejected. This validates provenance, not the formatter's Windows locale parity.
Empty or invalid ASCII dates serialize an empty string without a formatter.
Metadata2 converts a nonempty ModelYear using signed32 decimal-prefix parsing,
signed remainder100 and `%02d`; metadata3+ retain the original year. Original
section values remain untouched. Negative output requiring more than the native
two-character destination is rejected rather than reproducing CRT buffer failure.

`native2026_recovery_header(prefix, cpu_capacity=..., region=0)` implements the
separate331b0→120e0 standalone INI header path used for SCUW recovery inspection.
The caller supplies the original bytes preceding `[datacompression]` and the
actual configure32 CPU capacity. Its registered source is distinct from binary
CUW framing and retains no fabricated archives. Format500 is the30390→05170
constructor default;120e0 does not read a Format section. The node vector remains
empty. Only DateOfIssue, VehicleType, EngineType, VehicleName, ModelYear,
ContactType, CPU NewCID and target strings are read. Unread aliases remain in
`sections`. Target gaps are retained because120e0 does not call05e80.
Its actual snprintf_s truncation is retained: `CPU%d` has a six-byte buffer, so
CPU100 reads sectionCPU10; indexed target keys have a21-byte buffer, so ordinal100
reads `100_TargetCalibratio`. The original section names/values are untouched.

The metadata12 external USB archive condition compares
`Vehicle.CANIDTx_Phys_USDT` with0795. KindOfECU is a separate string and does not
select this branch. That external source-span producer remains required.

The runtime source producers now include `native2026_select_received_cids` for
34e10→3ddf0→3e710. It consumes the actual CID byte tuple, aligned twelve-byte
identifier records, configured constructor-zero CPU flags, original General
parameters and runtime shrink flag. The result contains issued rebuilt metadata,
ordered-to-authored indices, target indices and the FOREST CPU offset. It retains
the original archive backing, prunes logical blocks using the selected target,
remaps logical CPU indices, and uses17280→163c0 to append an unmatched promoted
FOREST CPU's current calibration/password. The original logical CPU FlashSize
remains the copied aggregate after pruning:19300→19360 does not rerun48670.
The pure34e10 matcher accepts an exact configured-capacity Boolean tuple through
`configured_cpu_flags`. SCC/Phase6 branches require this real per-FILE input;
`None` is permitted only on a reached branch that never reads those bits.
CPU+184 is its retained node association, so configured bits use
`native2026_node_index`, including after CPU reorder, rather than CPU ordinal.
`configured_metadata` is the distinct actual indexed TABLE FILE used by4b0f0;
preseed uses current metadata, while target skips and the later NewCID pass use
that indexed metadata's SCC/Phase6 predicate and node association. Named callers
must supply it; default current metadata represents only direct/no-named-table
composition. A non-SCC/non-Phase6 helper returns before any CPU-index lookup.
Blank/D4F8 skip target matching but retain configured target0 and the actual
unmatched footprint. Insufficient received CIDs retain the native initial
configured-target0 Boolean, then still compute targets/unmatched; they do not
raise a convenience exception. Host capacity/provenance/record errors still raise.

`native2026_validate_phase6_pair` performs19c00 without issuing a new source.
`native2026_merge_phase6` additionally applies4a850's first-node identity guard
and19910 composition: duplicate slot/NewCID and crossed target collisions fail;
Protocol, first GatewayMode and the fixed ServiceAuthKey must agree. First-node
logical slots are sorted, three timing DWORDs take their unsigned maxima, and
LEFT header and other nodes are retained. `NativeCompositeSource2026` retains
both exact metadata/source leases. Its digest proves composition and must not be
presented as the hash of serialized CUW bytes.

`native2026_project_node` implements32130→19300→13040→173d0 with native target
indices zero, resets the retained node and CPU node indices to zero, and uses the
retained Node.ContactType. Native Node16 naming is covered by an actual authored
sixteen-node container. `NativeNodeSource2026` keeps the original parent source;
reselection and typed-source reconstruction preserve the exact issued lease.

For metadata12 with Vehicle.CANIDTx_Phys_USDT0795,165f0's declared CUW end can
precede the original file's EOF. `native2026_usb_source` and the trailer branch
of `parse_cuw_2026` retain that original complete source.32130→2bc70 verifies the
CRC of the actual trailer against the first CPU image's big-endian DWORD at+8.
The first big-endian QWORD is the copier's free-space requirement, independent of
the actual trailer length. `native2026_usb_source_span` exposes an issued bounded
read view of that trailer, its full-file source hash and CPU0 image filename.
508c0 captures these copier fields; it does not replace the CPU archive with the
trailer. The archive still exports the original twelve-byte header. This byte
producer has the existing64 MiB host allocation bound. `native2026_usb_file_source`
adds a pinned regular-file source throughUINT32_MAX, verifies prefix/full-file
SHA/trailer CRC in5 MiB chunks, and detects path, inode, timestamp and close
changes. Its issued span supports bounded `read` and `iter_chunks`; a real300 MiB
authored sparse file passes complete trailer hash consumption and mutation checks.
Actual engine/copier/persistence ownership composition remains cross-owner work.

Large ordinary CPU import now follows the actual2aad0 rewritten descriptor buffer.
165f0/189e0 call16030 with flag zero for ordinary CPU rows, so the original record
length and CRC apply to the rewritten descriptor bytes. Oversized payloads fail
at import with the native storage bound; mismatched descriptor CRCs fail before
metadata publication. Logical rows still import324-byte descriptors with flag one.
A crafted valid300 MiB mixed209 input whose ordinary payload exactly equals its
source-issued descriptor exports324 raw bytes, GetLength324 and FlashSize0: the
fast36f30 pass visits only logical nodes. Positive, CRC mutation and oversized
ordinary CPU failure controls are retained in the owned suite. This does not
claim that arbitrary large CPU images become ordinary streamed archives.

Issued metadata is validated by `native2026_validate_runtime_metadata`: every
factory, reselection and owned transition registers the exact immutable object.
Copying the same projection token into altered metadata does not authorize it.
The common caller can validate legitimate runtime projections without rebuilding
raw authored metadata and losing selected targets or logical backing.

Initial32130 node filtering precedes378b0/36f30. Node projections recalculate
logical FlashSize after target-zero pruning and classify ordinary archives using
the retained node's new globalCPU0. Runtime3e710 reorder/pruning instead preserves
the already loaded CPU archive and aggregate, as the source does.

`native2026_logical_resume_cpu` implements the19710-guarded3ffa0 option branch:
matching ReproData Length string presence selects method05 without a routine
Length string or01 with it, recalculates13d20 and writes nonzero FlashSize only.
It returns the first current-node logical block's CPU index for the caller remap.
Retained S-record export GetLength0 does not erase the internal native wire Length
used by13d20;417b0 transfers records without clearing that field.

The34e10 special branch for a first CPU image containing `.vbf` checks
`NumberOfTargetHardwares` and each `%02d_TargetHardware` against the exact captured
hardware string. Zero entries or no match returns an issued false snapshot even
when a target CID matches: all authored targets stay-1 and unmatched vectors stay
empty because the native branch exits before their population. With matching hardware, nonempty received CIDs follow normal matching;
an empty **live global** received vector selects CPU0 target0 without adding
unmatched CIDs. `received_identifiers` plus aligned records represents selected
local6c/local80; `live_received_identifiers` supplies the distinct global D270
vector. Its default aliases the selected vector only for direct/no-distinct-vector
convenience; engine/H callers supply both actual sources.
`received_hardware` defaults to the native constructor's empty string; the actual
389c0 getter capture must supply any nonempty hardware value. The direct positive
primitive test does not claim that cross-owner getter integration is complete.

34e10 matching and36800 rebuilding are separate operations.
`native2026_match_received_cids` returns an exact issued `NativeCIDMatch2026`
authored target/unmatched/companion/count snapshot without General lookups or
metadata mutation. `native2026_rebuild_received_cids` requires that exact match,
its original metadata and General object, and the36800 source gate. A first CPU
image containing `.vbf` or a nonempty first CPU indexed-image vector skips3e710,
including3ddf0 FOREST promotion and17280 password lookup.
`native2026_unrebuilt_selection` preserves the original metadata, identity order,
authored targets and zero CPU offset for that branch. The convenience selection
API applies the same gate; callers needing actual chronology use the split APIs.
Earlier eager VBF FOREST promotion positives were withdrawn and replaced by
valid S-record `.hex` rebuild inputs and explicit skipped-branch controls.

The match's `check_target` records the34e10 result, including hardware rejection,
insufficient-CID false and failure when NewCID additions fill the unmatched vector
to the CPU count despite an authored target match. False remains a registered
snapshot with the footprint reached by that exact branch, not malformed input
converted into a normal result. Actual callers gate rebuilding on this result.
`native2026_rebind_cid_match` carries the snapshot across registered SetCPUType
and CPU-reselection parent edges, because those native operations keep the same
FILE object. A fresh parse of the exact same source is not such an edge and is
rejected, as is a copied metadata or match value. Rebuilding uses the live issued
CPU types while retaining the original authored target snapshot.

The legacy `native2026_select_received_cids` convenience helper composes the
primitives with the36800 filename/indexed-vector shape gate, but deliberately
does not consume `match.check_target`. Its empty-pruning results are host
transform controls, not evidence of a successful native CheckTarget workflow.
Actual engine callers use the split APIs and return failure before36800 when
`check_target` is false.

`native2026_node_logical_block_count(metadata, node_index=0)` exposes the exact
Control node+7c DWORD through the issued source metadata. Its source chain is
6370 internal node+98 →18030 exported node+2c →CF5c10 imported node+7c.
It counts logical blocks rather than deduplicated CPUs: two blocks sharing one
NewCID return2 even when node CPU count is1. Ordinary nodes return0, and runtime
pruning returns the surviving block count because111e0 updates native+98.
The accessor validates exact issued metadata, the original lease and node bounds.

`native2026_rebuild_current_cids_steps(metadata, target_indices,
unmatched_identifiers, unmatched_companions, general_parameters, *, configuration)`
models a reached3e710 body directly from current native state. Ordinary36800 does
not require a previous34e10 match. The inputs are exact issued metadata, current
M-wide D2A4 targets, current unmatched CID/companion byte tuples and the actual
General/configuration. D300 is neither an input nor a store of this operation.
The registered-match rebuild wrapper retains its receipt/metadata/General guards
and drains the same core.

The iterator yields frozen data, not live mutation permissions:
`NativeCIDRebuildOffset2026(value)` publishes D30C reset0 and each FOREST move
before the following fallible lookup; `NativeCIDRebuildTargets2026(indices)`
publishes the full target vector before projection;
`NativeCIDRebuildMetadata2026(metadata, operation, cpu_index=None)` distinguishes
`16ae0`, `16fb0`, `19300` and each `17280` commit;
`NativeCIDRebuildTargetStore2026(cpu_index, target_index)` follows its password
append; `NativeCIDRebuildComplete2026(selection)` alone denotes terminal D304.
The worker consumes the actual iterator/current yield identity inside its source
origin; the engine publishes metadata/proofs only at that authenticated point.

3ddf0 moves CID strings without moving their companion positions. CPU metadata copy uses the last old matching CPU in both branches;9
independently copies archive objects from the first old CID match. Logical pruning
follows CPU/archive reorder; individual target appends follow pruning. The live
unmatched vectors and authored count remain unchanged. Structural malformed input
rejects before the first yield; General/password failures occur at their actual
business step after earlier yielded writes. An empty desired CID with capacity
beyond represented active CPU rows currently rejects at the reached reorder
point: unused native records are not inferred from constructor defaults. That
capacity-tail branch remains unsupported pending its separate source proof.

The existing issued match now retains `cpu_maximum` from its validated native
configuration. Its registered wrapper reconstructs only the D2A4 tail proven by
34e10's initial all-M `-1` stores, so it drains the same capacity-aware core and
cannot bypass the empty-CID capacity boundary. Rebinding retains that capacity.
The ordinary source-state lane receives the actual full vector and never pads
caller state from metadata.
