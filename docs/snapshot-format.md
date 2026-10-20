# Native snapshot import, export and playback

`scripts.snapshot` implements recovered binary layouts without loading vendor DLLs.
It is separate from the authored JSON exchange replay in `scripts.replay`.

## File and record API

`parse(bytes)` / `load(path)` return `TableFile` or `TSEFile`; `dumps(file)` exports
native bytes. Both file classes have JSON-compatible `.to_dict()` inspection. `load` accepts
bounded regular files and rejects devices, directories and FIFOs before opening
their data stream.
Binary strings remain bytes in records and hexadecimal in inspection reports.
No character encoding is inferred. Playback defaults to reversible Latin-1 labels;
callers may explicitly select a different encoding.

FileManagerIT3 DM and DRS envelopes are little-endian `<IHH>` magic, version,
revision. DM magic is `0x80000002`, DRS is `0x80000001`. Each following table is
`<IH>` length, ID, payload: length includes the two-byte ID and excludes itself.
`parse_tables` / `encode_tables` preserve duplicate IDs, order and unknown bytes.
DRS record interpretation belongs to `scripts.drive_recorder`; its signal records
are different from the DM signal-item layout.

DM `0x8100` system information has a raw identifier, two CCmdString records
(two opaque uint16 core words plus a uint16-length byte string), and a final word.
`decode_system_information` / `encode_system_information` preserve these fields.
DM `0x8101` monitor buffers use `decode_monitor_buffer` /
`encode_monitor_buffer`: three uint16-length strings (name, exactly 16 information
bytes, description), three uint32-length frame/signal/ring subbuffers, marker,
labelled flags, selected IDs, comment and additional IDs. DM selected-ID count is
uint32; the corresponding TSE field is uint16.

`decode_frame_table`, `decode_signal_table`, `decode_ring_buffer` inspect native
subbuffers. `decode_signal_item` / `encode_signal_item` cover versions 1–4,
including PID, frame/bit positions, names, unit, selector, sign, coefficients,
precision, bounds, pattern entries and versioned extensions. Pattern tuples retain
`(identifier, label_bytes, match_value, extra_raw)` exactly. The first DWORD is a
shared pattern ID; symbolic matching uses the third field (native object `+0x1c`).
The extended tuple's last two DWORDs provide display thresholds (runtime `+0x64`
and `+0x68`); the earlier `minimum_raw`/`maximum_raw` fields remain separate bounds.
Version 1's absent extension retains native constructor threshold defaults 1/0.

## TSE monitor sections and editing

`TSEHeader` and `create_tse_header(header)` construct a fresh native versioned
prefix. Every input is explicit: kind, file type, version/revision, raw systems
mask and field 28, language, versioned byte strings, ECU IDs, feature IDs and
reserved bytes. Fields absent from the selected version must be `None`; legacy
reserved bytes must be exactly 80 bytes, and modern reserved bytes must be empty.
Legacy feature declarations must agree with `systems_mask`. The constructor and
reader share the same field/version tables. The prefix has zero body offsets;
`assemble_tse` supplies actual native body fragments and regenerates those offsets.
Header `file_type == 4` selects native DTC context mode 1; other values select mode
0 (GTSFileController `0x1009a568`/`0x1009a57d`). No vehicle metadata is inferred.


`parse_tse` recognizes `9a 53 db 12` followed by TSE, TMM or TMR and a zero byte.
It reads the original versioned index (`0x1000`–`0x102c`), string fields, per-ECU
entries and feature bitmap. Index values are **absolute file offsets**. Tagged
index entries carry the original ECU ID, which need not equal its list index.
Unsupported report-family sections remain byte-preserved and their feature IDs
are explicitly reported by `.to_dict()`.

The following original monitor families have bounded body codecs:

| Index family | Feature ID | Section type | Record codec |
| --- | --- | --- | --- |
| DataList | `0x2714` | `0xffffff05` | `TSEDataListSection` |
| DrvRec | `0x2715` | `0xffffff08` | `TSEDataListSection` |
| ATest | `0x2717` | `0xffffff07` | `TSEDataListSection` |
| DualData, global | `0x2726` | `0xffffff19` | `DualSection` |
| ATestD | `0x2728` | `0xffffff21` | `DualSection` |

`decode_tse_datalist_section` / `encode_tse_datalist_section` cover single-monitor
records through `0x1021`; `decode_tse_dual_section` / `encode_tse_dual_section`
cover dual records through `0x1027`. Version-dependent ID widths, selection pairs,
chart/view/configuration bytes and reserved areas remain lossless. ActiveTest
saved command descriptors have a bounded nested decoder,
`decode_active_metadata(data, version)`. Their bytes are retained in each record;
requests and responses are inspected, never executed by the snapshot module.

`tse_monitors(file)` enumerates recovered captures with family, record index,
ECU ID and native monitor records. `replace_tse_monitor_section(file, family,
section, ecu_index=0)` edits an **existing** recovered section and relocates every
later indexed offset. Unknown companion sections retain their exact bytes.
`replace_tse_datalist(file, ecu_index, section)` is the DataList convenience API.
`assemble_tse(template, ordered_fragments)` writes a complete native container
from the supplied versioned header and one native byte fragment per index entry.
It regenerates offsets from actual fragment sizes and validates recovered monitor
bodies. ECUInfo's section header and each EcuData record are separate fragments.
Vehicle metadata and declared feature bits come from the caller's template;
this API does not invent a vehicle profile or missing report-body semantics.

## Playback and plotting

`playback(file, buffer_index=0)` returns JSON-compatible signals, samples, raw
marker/flags, family and provenance. `monitor_packets(record)` reads native phase
0/1 packets from full, wrapped or compact ring images. Each packet retains its
little-endian uint32 `timestamp_raw` and frame bytes. `decode_packet_stream(data,
frame_layout)` also decodes an explicitly sized flat native packet stream; it
does not infer another container's framing. `monitor_samples(record)`
joins recorded signal metadata with those frames, subtracts the first native
standard value matching the PID, and applies the recovered integer conversion
and selector-aware `scripts.signal_display` consumer. Values include
`raw_bits`, `baseline_raw`, `raw`, `scaled_integer`, `display`, `kind`, `status`
and engineering `value`. Symbolic/unknown/unavailable values use `value: null`;
IEEE754 unavailable values are never exported as JSON NaN. Integer selectors
apply decimal precision; float selectors retain their native float scale.
Numeric `samples` feed `scripts.plot.sample_chart`; that chart uses sample index,
not guessed seconds.

Timestamp units, interpolation and cross-ECU clock alignment are not inferred.
Dual captures enumerate each ECU separately. Pattern/threshold labels, numeric,
hexadecimal, character, DTC, packed-time and float display follow the recovered
selector consumer. Unknown selectors remain unresolved. For float64 selector 29, the recorded monitor table and selected-sample details
pass zero for both auxiliary words to the native formatter. Playback reproduces
that display result and reports `display_words_raw: [0, 0]` and
`display_word_source: "native-recorded-monitor-zero-arguments"`, while retaining
the actual extracted `raw` separately. These zero arguments are caller behavior,
not a recovered 64-bit sample. The generic `render_signal(raw_words=(low, high))`
API handles explicitly supplied native word pairs; extended thresholds do not
provide that pair. The recorded DWORD extractor rejects widths above 32 bits.
Raw definitions and source bytes remain available.

The module has no device I/O. Host limits are 32 MiB per binary input/output, 100,000
native table entries or packets, **100,000 total decoded frame records**,
**100,000 total decoded signal values**, 100,000
expanded capture/metadata/display-work entries, and 4,096 TSE ECU-index entries.
The aggregate value, conversion work and repeated report text budgets are checked
before sample conversion/allocation. Aliased TSE index entries reuse immutable
records, rather than copying their buffers. Native writers bound accumulated
chunks before joining them. Larger recordings can still be inspected and
round-tripped.
These limits are host policy, not claimed OEM maxima.

## Compression

`compress` / `decompress` implement DataCompress_DT's five-byte original-size /
bytewise-OR header and LZSS: 4096-byte ring, initial destination `0xfee`, LSB-first
flags, 12-bit source, match lengths 3–18. The writer emits valid literal tokens;
it does not reproduce the original compressor's match-selection tree. References
into the native decoder's uninitialized dictionary are rejected, not guessed.

## Evidence and limits

Static Techstream 18 anchors: FileManagerIT3 DM reader/writer
`0x10001000`/`0x100020f0`, table reader/writer `0x10004a30`/`0x10004cb0`, monitor
reader/writer `0x100024f0`/`0x10002aa0`, system reader/writer
`0x10002ed0`/`0x10002f10`; DatMonCommon frame/ring/signal readers
`0x10002200`/`0x100033e0`/`0x100072e0`, SignalItem reader/writer
`0x10006e00`/`0x10006bf0`; DataCompress wrappers `0x10001ed0`/`0x10001f20`.
GTSFileController header/index readers `0x1009a500`/`0x10099b50`, absolute offset
calculators `0x10038a00`/`0x10039f60`, DataList record reader `0x1008e6a0`,
DrvRec wrapper `0x1008f2d0`, ActiveTest wrapper `0x10088290`, dual readers
`0x100a2b80`/`0x10087570`, active metadata readers
`0x100838a0`/`0x10083c10`/`0x10083ea0`/`0x10084310`. Recorded bit assembly
uses DatMonCommon `0x10002d20`, not the distinct live CommandCommon extractor;
its x86 DWORD shift wrapping is preserved. Standard-value lookup is `0x10002ba0`;
Techstream.exe call sites `0x4e287d`/`0x591e50` pass the SignalItem PID.

Independent Techstream 12 inspection confirms its header/index version gates
through `0x102a` and corresponding dual-monitor field sizes/thresholds. The DLL
bodies are not byte-identical; this is selected layout evidence, not blanket
version equivalence.

The supplied local artifacts contained no original recordings. Two independently
published original owner recordings were subsequently obtained for private
validation (native TSE versions `0x1006` and `0x1025`); neither recording nor its
vehicle identifiers are redistributed. Both parse/export and ordered-fragment
assembly reproduce their complete source bytes. The latter contains three
DataList captures with 214, 130 and 149 samples and 73 signals each; numeric and
symbolic display resolve, and a native comment edit reopens with equal playback.
Public tests use independently authored wire vectors, old-version branches, nested truncation,
corruption, compression overlap, byte-exact export, offset relocation, engineering
conversion, plotting and allocation-budget rejection. This is static native
format evidence plus authored verification, not original application acceptance.
Non-monitor TSE report semantics are outside this module. Float64 word
correlation and the timing gaps above remain explicit limitations; they are not
inferred from successful container checks. Physical behavior is unverified.

Run `python -m unittest discover -s tests -p 'test_snapshot.py' -v`.

Recorder ring persistence keeps native read accounting separate from the live
oldest-to-write seek span. A full saturated allocation can contain a final stale
partial packet when its byte capacity is not divisible by packet size. Playback
uses the native integer packet count and omits only that final remainder; compact
or nonsaturated partial packets remain errors. At an exact collision, persisted
full-image playback can therefore include a rotated older packet that the live
seek span excludes. The serialized header is preserved unchanged.

Native compact output with a positive timestamp complement appends a copy of its
last block. Its stored size, write cursor and written count can exceed the
original capacity while the available-byte field still describes the selected
region before the append. The decoder accepts this bounded normalized shape and
plays the complete stored packet stream, including the appended block. Pointer,
copy-source and aggregate output limits continue to apply. No time interpolation
or synthetic header field is introduced.

A phase-1 stream with two generator slots needs the proven live starting slot to
assign its alternating frame identities. The native serialized ring header does
not store that cursor. Persisted bytes alone do not establish that missing live
state; callers must not infer it from timestamps or silently label both slots as
the first frame.
For that unresolved persisted case, `monitor_packets` still returns every exact
`timestamp_raw` and `payload_hex`, with an empty `frames` list and
`frame_identity: "unresolved-native-slot"`. Engineering values that need an
unproven frame identity remain unavailable rather than receiving guessed data.
An unallocated native ring writes only its ten-byte version/revision/phase/block
header. The decoder returns those actual fields with `buffer_allocated: false`
and an empty image; absent capacity and pointer fields remain absent. Packet
playback returns an empty list. Eleven through thirty-seven bytes are truncated
allocated headers and remain invalid.
The snapshot 32 MiB limit applies to the complete supplied encoded payload. It is
separate from a standalone ring's allocation/image-byte limit: the ring envelope
alone adds 38 bytes, and outer records add their own metadata. Exports must fit
both bounds.

`monitor_samples` additionally follows the recovered GUI consumer for complete
packet blocks. Its packet slots share one read buffer, so each complete block
uses the last packet's bytes. The displayed timestamp is the native wrapped
unsigned 32-bit sum of the aliased timestamps divided by the block count; this
can differ from the last raw timestamp when the sum wraps. An incomplete ending
block has no GUI sample. This behavior does not change `monitor_packets` or its
raw timestamp/payload preservation.

For phase 1 with multiple slots, the GUI's reference to slot zero permits safe
conversion of fields within the first frame. Other frame fields remain explicit
`unavailable-native-frame` values with `raw_bits`, `raw` and `value` set to null.
The host requires every accessed byte to fit the actual packet; it never copies
an original out-of-bounds read. The GUI adapter rejects block counts above its
native eight-slot pointer table, while the raw decoder retains bounded packets.
