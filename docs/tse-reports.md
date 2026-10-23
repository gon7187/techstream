# Native TSE report bodies

`scripts.tse_reports` reads and writes the native GTSFileController report
sections inside TSE/TMM/TMR files. It uses the original binary framing and
version branches. It does not invoke the original program, contact an ECU,
extract attachments onto the filesystem, or substitute JSON for the file format.

```python
from scripts import snapshot, tse_reports

file = snapshot.load("capture.tse")
items = tse_reports.reports(file)
body = snapshot.tse_section(file, items[0]["offset"])
section = tse_reports.decode_section(items[0]["family"], body,
                                     context_mode=int(file.file_type == 4))
assert tse_reports.encode_section(section) == body
updated = tse_reports.replace_section(file, section, items[0]["ecu_index"])
assert updated.source == file.source
```

`ReportSection` contains `family`, `identifier`, `type_raw`, `version`, `records`
and `context_mode`. `records` contains immutable, ordered native structures:
integers retain their unsigned wire width, strings/buffers remain `bytes`,
fixed structures are tuples, and counted lists are tuples of structures.
Floating-point fields retain their IEEE bit patterns as unsigned integers, so
NaNs and other noncanonical representations round-trip exactly. No unproven
engineering units or text encodings are assigned. `to_dict()` renders buffers
as `{"bytes_hex": ...}` and preserves the same field order and nesting.

Each section starts with a little-endian uint32 identifier, uint32 raw type and
uint16 section version. The index determines its family; raw type values remain
available instead of being silently rewritten. Counted native lists use uint16
counts. Text buffers use uint16 byte lengths; explicitly recovered binary
buffers use uint32 lengths. All lengths must fit the remaining input.

`reports(file)` returns every present report with its `family`, `ecu_index`
(`None` for global), absolute `offset`, header fields and decoded `records`.
It gates interpretation on the native feature bitmap: absent feature offsets
can alias the next section. Aliased bodies of the same family reuse their
immutable decoded structures, and presentation has a shared aggregate budget.
`select_report_section(file, family, ecu_index=None)` returns `(offset, section)`
with the same feature/scope validation and header-derived context.
`replace_section(file, section, ecu_index=None)` edits an existing body and
relocates every later index offset. It preserves companion sections and aliases;
it rejects absent features, invalid ECU selection, and changed type/context.
Monitor-only DataList/DrvRec/ATest/ATestD/DualData and ECU index/container
operations are provided by `snapshot`, not duplicated here.

## Named rows, playback and attachments

`report_views(file, encoding="cp1252")` and `view_section(section, encoding=...)`
return named `captures`, `dtcs`, `parameters`, `systems`, `events`, `monitors`,
`images`, `vehicle`, `functions`, `error_reports` and `memory_captures`. The
caller supplies the native byte-string encoding; decoding
is strict and no locale is guessed. Rows retain `source_path` into the lossless
record. Capture dates preserve all eight serialized SYSTEMTIME words and expose
a local-wall-time ISO date only when those words form a valid date.

DDR normal and ADS side/main series associate the separately stored byte masks
by channel and sample position. `invalidity_raw` preserves
an available byte; missing positions produce `None` and have no
`invalidity_source_path`. `invalidity_check` follows
native `5eec20/5eec70`: zero is false, nonzero or missing is true. Invalid samples
keep `stored_display`, raw value, and sample-type `flags_raw`, but expose
`display=None`, `display_source="native-invalid-resource"`, and
`invalid_display_resource="DISPLAY_VALUE_INVALID"`. The UI must resolve or show
that resource explicitly, rather than displaying the stale stored text.
Native formatter `5ee8f0` replaces the text with that resource from `S319-04`;
its exact localized value is not guessed. `native_channel_suppressed` follows
`5eecd0`: neither side nor main mask contains a zero at that channel. The named
view retains suppressed rows for inspection. Flat normal ID3/modern ADS ID13
arrays, scalar-mask presentation, and the legacy ADS `1009` ID13 byte are not
generalized from this nested-series display consumer. The flat masks remain
preserved in the raw record until their separate presentation contracts are joined.

Ordinary parameter values use the actual saved display text. Extended values
use their native conversion descriptor and symbolic comparison keys, through
`signal_display`. The signal/DTC object bridge is visible in Techstream.exe
RVAs `a2a0`, `ac80`, `b3d0`, `e4a0`; descriptor pattern IDs are retained separately
from the actual comparison key. DTC rows preserve `freeze_frame_state_raw` and
`freeze_frame_number_raw`: native saved-XML parameter `36` (hex) is `FrameNo`,
copied through Techstream RVAs `10bd8e/10bd9d/10c97d` and `e4a0` to the
GFC `7e0f0` fields after the description. These fields are not diagnostic status.
Their numeric enums remain uninterpreted. `freeze_frame_data_check` exposes the
exact native predicate `freeze_frame_state_raw == 1`: CommandAPI RVAs `56ff7`
and `572d1` select the native `FreezeFrameData[TRUE]` log for that value alone.
The normal `57670` converter copies native `+30` through compact `+10`,
assignment `58770`, and the GUI `40b3d0` bridge. This predicate does not assert
that the stored freeze-frame array is nonempty or that a vehicle supports it.
`freeze_frame_marker` preserves the separate final string: GUI `40b816`
copies compact `+1c` to frontend `+bc`, read by GFC `7e66e`. Native CDTCView
`8d40bd` maps exact `!`, `!!`, `!!!` to bitmap IDs 174, 175, 176. Other
strings remain raw text; this field alone does not assert button availability.
Separate `status_markers` expose the
actual stored strings for current, pending, history and permanent; absent legacy
permanent fields produce `None`. The native wire order is current, history,
pending, permanent. Techstream header assignments at RVAs `5d2355–5d23eb`,
row assignments `5d6bf3–5d6cda`, vector insertion/copy `4ddc0`/`30df0`, and
the compact/frontend bridge `b7bc–b810` establish that order. These strings
are preserved as stored, without turning arbitrary marker text into booleans.
`status_flags_raw` retains the separate current/history/pending/permanent DWORDs
in that same order, with `None` for absent legacy permanent fields. Normal
CommandAPI `583b5–58438` sets each DWORD to `1` together with the corresponding
marker string `X`; GUI `40b7f2–40b810` copies them to saved offsets `ac/b0/b4/b8`.
Arbitrary saved integers remain raw. CDTCView column 7 additionally combines
three of these values with a selected provider mode; that separate mode-dependent
icon policy is not inferred from the stored flags alone.
Health-system rows expose stored names
and identifiers without treating the second identifier as an unproven status.

SysChk/FuelCon monitor-backed and Oscillo/AFO2Sn captures use the native frame table, signal
table and circular packet buffer through `snapshot.monitor_samples`. Samples
retain native timestamp values; no interpolation or clock unit is invented.
Names, units and symbolic labels come from the saved signal table. Playback
work and expanded named rows share the aggregate presentation budget.

`attachments(section)` returns immutable `Attachment(name_raw, stored_bytes,
stored_size)` objects. `unpack_attachment(attachment)` returns ZIP members in
memory, preserving member metadata and byte contents. The native stored size
selects the logical ZIP span; surrounding allocated bytes remain lossless in
the section. Native extraction is at GFC RVA `99230` (UNZIP32). The host rejects
multidisk, ZIP64, encrypted members, malformed central directories, count/size
expansion beyond budgets, oversized LZMA dictionaries before decoder allocation,
and CRC failures. Names are data only; no member path
is opened or extracted to disk.

Health system rows expose the derived numeric `ecu_group_type` from native
`GetEcuGroupType` (`6000b0`, named by diagnostic `4bcb10–4bcb37`). It uses the
low WORD of the second header DWORD: remainder 1/2 stays 1/2, a nonzero
multiple of three becomes 3, and zero becomes 0. Full header DWORDs remain
available. The numeric result is not mapped to invented enum names or DTC
status, and the separate group-name producer join remains open.

DDR report attributes expose `normal_logical_id` 159–171 as the normal
producer's slot names, each with its stored support DWORD (`present_raw`) and value DWORD (`value_raw`). The bridge
is `GetDDRInfo_DT.b680` → CommandAPI `514c1/52d30` → GUI `4a16f0/49f5e0` →
GFC `b1f30`. Values retain all saved bits, including unsupported entries; the
reader does not reapply producer masks. Physical units and business labels
are not inferred from these slot names. P5 can place logical 177's value
in the final normal-171 slot; the saved block carries no observed logical ID,
so the view does not claim which producer supplied it. The same native response
also binds `maximum_recording_count` (logical 103) and
`specification_number_raw` (logical 118) to the separate saved DWORDs.

Each present DDR normal or ADS pair also adds one `ddr_headers` KeyCycle row,
independent of its signal sample count. It preserves the unsigned value,
precision byte and separate invalidity byte with exact source paths. A nonzero
invalidity byte or negative signed value displays `-`; otherwise precisions 0–8
use the recovered sign-space decimal format and zero padding. Valid values with
precision 9–255 retain their raw fields and use `key_cycle_display=None` with
`key_cycle_display_status="source-semantics-open"`; the native high-precision
formatter behavior is not established. Missing pairs do not create rows.

Normal DDR slot 24 samples also expose `sequence_format_admitted` and the
evaluated `sequence_format_checks`. The view checks mask 21 first; for sample
index zero that result is final, and later samples check masks 0 then 1 only
while each preceding byte is present and zero. A missing byte fails with a null
raw value and source path. These fields describe reaching the native numeric
formatting branch, not a successful conversion or a plotted coordinate. The
association is by normal slot position and exact pair path, never by stored
signal identifier; sibling signals and ADS rows remain unannotated. Stored
sample text, raw values and flags are unchanged.

The existing per-pair normal KeyCycle header also carries a
`sequence_coordinate_plan` for the source-proved zero-step pre-sort subset. An
empty saved sample array has a derived empty plan. With samples, the plan is
derived only when the saved divisor is zero and every sample fails the normal
sequence admission checks; otherwise `points` is `None` and the status is
`source-semantics-open`. Derived points retain staging order and contain only
the proven zero coordinate, tag and source index. Raw counts, divisor, masks
and their source paths remain attached to the same header. This does not claim
general numeric conversion, final sorting, ADS sequence behavior or plotted
coordinates. Plan metadata, copied masks and points share the existing bounded
view budget.

Operation-history headers expose the six stored current-time fields (year,
month, day, hour, minute, second) and preserve the following metadata byte.
CommandAPI `23434–234c3` logs the same `GetAnalyzeWorkFactorApiRcv` fields;
Techstream `47d1f0` / `47db90` places them in the GFC operation-history header.
The view supplies the calendar components without assuming a timezone,
converting to an instant, or rejecting native zero/invalid calendar values.
Its stored content rows expose native `Contents`, `TimeInfo`, and `DispType`
fields together with all three saved strings; remaining metadata stays raw.
Its stored current-time information rows also expose `time_info_raw` and
`display_type_raw`, as named by CommandAPI `2354a–23581`, together with both
saved strings. `current_summary_display` separately follows the native ordinary
current-summary consumer for rows 0/1/2 (`c967ce–c96ba2`). An exact `0x8000`
in any of those three rows requires localized `STRING_QUESTION`; its display
remains `None` and `current_summary_resource` names that unresolved resource.
Otherwise bit `0x4000` produces literal `-`; rows 0/2 with format `0` use signed
32-bit decimal text, while row 1 with exact format `4` uses the native day/hour/
minute string and discards seconds. Unrecognized formats remain unresolved,
additional rows retain raw fields, and missing rows are never synthesized.
This current-summary policy does not define historical content-row units or a
universal display-type enum. Raw values, formats and stored strings remain intact.

`normal_coefficient_low_byte_raw` aliases the header metadata byte under the
source-proven normal P3/P4 interpretation: `CalcCurrentWorkFactorLsb` selects
logical group `0x18`, copies the observed coefficient's low byte to ordinary
receive `+54`, then CommandAPI `23468` carries it to the saved header. This
alias does not assert a timezone, validity flag, unit or exponent; the original
`metadata_byte_raw` key is preserved. Other provider variants remain separate.

Initial-selection rows expose the saved `selection_identity` and each actual
selection-choice label, with group/source path and its distinct native IDs.
Techstream RVA `5bc30` restores the `SelectCarTypeVin10ApiRcv` object.
CommandAPI `b9f65`, `ba021`, `ba0fe`, and `ba1e1` bind the fields to the
native response diagnostics: `vin_code`, `selection_name` with category and
selection IDs, `car_information` with its information ID, and `option_name`
with its selection ID. These additional `field` and named raw ID keys preserve
the earlier names, groups and `identifiers_raw`. The VIN text is retained
without normalization or a length assumption; category/selection enums are
not inferred.

Vehicle rows expose native CarType, Engine and both old/new ModelYear fields.
The bridge is Techstream RVA `75ad0`; native consumers at `160cac–160d93`
explicitly format those meanings. Both model-year fields remain available
because the native caller selects between them using its regional context.
Engine and the alternate year are present only after section version `100c`.

Error/TMR rows expose the native log identifier, event cause, caption and note, saved date/time strings,
local SYSTEMTIME and the stored Windows `GetTickCount` millisecond counter,
saved contact details, hotkey labels, saved-file directory, application product
version, communication-tool version, DENSO platform OS build and device
name/firmware/DLL/API versions. Image rows
retain their actual native source paths, including the owning report record.
Saved `settings` expose the vehicle-brand selector, font size, language selector
and the seven unit selectors for vehicle speed, temperature, weight, air flow,
air pressure, vapor pressure and fuel pressure. Their numeric selections remain
raw: no unit names or font-size unit are inferred. Techstream `82a228–82a538`
joins the actual named profile keys to `ER_SetAppVer`; ErrorReportLib
`6bda–6d0d` and `117a2` join those cached values to the serialized preference
block. The additional word after version `2004` remains
`additional_selector_raw`: the audited producer does not assign that word.
Date/time strings retain their original formatting. The tick counter retains
its native 32-bit wrap and is not interpreted as report age or elapsed time.
The communication-tool version comes from the named `ComToolGetVersion`
response; the platform build comes from `SOFTWARE\DENSO\OS` / `BUILD`.
They are saved diagnostic context and do not describe the running host OS.
The ErrorReportLib.dll producer/getter bridge uses RVAs `1136a`, `dc19`,
`9a70`, `116dc` and `117a2`; named profile-key sources are at `6a10–6bcb`
and `6d4f–70a6`. Its SHA-256 is
`dd9c35c5a769eb24f12285cadd1bb0efcd76faa70c65a9d34f508001642f6a09`.
The contact block is user/shop/dealer information; it is not labeled as vehicle
information. Its two numeric selectors retain the native `DealerType` and
`DefaultBrand` identities without assigning enum names. Directory strings are
displayed as stored data and never opened.
No original Error/TMR capture is available; these views have authored vectors
and static producer/getter evidence.

Device-version labels follow ErrorReportLib `fe9d/1dc3d` and the independently
recovered JLR provider's named DLL/API guards and firmware-output path at
`58e7a/59027/59118/591d9/59636` (monpj432.dll SHA-256
`2710726fdd174f32b5e703e310cfce047a663451edbb3e35ca0c8eeff6929413`).
Legacy/0500 branches preserve the same three output-buffer positions.

Memory-capture rows expose the actual saved label, block count, native versioned
block identifiers and byte sizes. Payloads remain lossless opaque bytes in the
codec. GFC provides count/set operations; GUI save paths are `218618–218642`
and `11c236–11c25a`. These metadata views do not claim a decoder for proprietary
RAM payload content. The distinct `DDRData` family is native vehicle control
history: `GFCAddVehicleControlHistoryData` at `b82d0` appends to the same root
`4c0` list read by `afa30`. Its common capture metadata and saved parameter
values use the shared named views. Specialized scalar meanings still require
the native producer/UI bridge; the index name does not establish database
resource semantics.

Named views currently cover shared DTC/FFD/signal/capture structures, health
systems, history event names, monitor graphs, vehicle fields and attachments.
Some global configuration/error-report field labels and native status enums still
require consumer evidence. Oscilloscope buffer identity is proven by GUI RVAs
`78fc2–78fed` copying GFC record offsets `40/48/50`, then `793b7/793e7/7941b`
calling the native FrameSizeTable, DatMonSignalTable and RingBuffer readers.
Their lossless codecs do not establish complete normal application report
presentation.

## Recovered families

All addresses below are RVAs in GTSFileController.dll, SHA-256
`4c769d8da3fb6747e12e2e6c8bae84e722dcbaa8aa14e79e467b27e77933855b`.
The section version is distinct from the enclosing file/index version.
The native index writer `680f0` assigns `MILMessage` to root index `70` and
`DDRData` to `80`. `MILMessage` contains message-screen and confirmation-screen
lists (`GFCSetMilMessageInformation` at `b67e0`, screen-count getters `b6820`
and `b6840`). Named `messages` rows expose body text, prefix, suffix, format
and category, preserving the two screen groups and their source paths.
Techstream converter `76000` copies all five fields directly; dialog consumer
`7e4ec0–7e4fde` composes the three text fragments. Controller `634c7d`
compares the category buffer to stored `Critical`, `Information`,
`Confirmation` and action-category strings. Selector `6360d2–636149` compares
the other buffer to `TEXT`; its caller chooses text or the native HTML dialog.
The host retains the exact stored format/category and displays the fields as
data. It does not execute message actions or render saved HTML. Both raw
buffers have native capacity 16 bytes; oversized spans are rejected. This
view has authored nonempty vectors and static consumer evidence; no original
MIL capture is present in the supplied corpus.
`DDRData` is the distinct capture structure read at `afa30`, including shared
parameter records. These names are not interchangeable.

| Scope/family | Feature | Native reader/body RVAs |
| --- | --- | --- |
| Global IniCarInfo | 2711 | 9a6f0, 9a800, 9aa50, 9aca0 |
| Global ConfCarInfo | 2711 | a1a70 |
| Global MultiPID | 2724 | a4460, 7fa20 (flavor 9) |
| Global FuncName | 2725 | 9c2e0, 9c370 |
| Global HealthCheck | 2712 | 9c730, 9c7c0, 9cdd0, 9d550 |
| Global TimeStamp | 271f | ae5b0, ae660, aeb80, aebe0, 7ea50 |
| Global ROBCommon | 2721 | aa4a0, aa560 |
| Global MILMessage | 271b | a1d90, a1e30 |
| Global CanBus | 2723 | 89640, 896e0, 89f50, 8a5b0, 8aa50, 8b190, 8b4b0 |
| Global DDRData | 272a | afa30, afae0, b1340, b1760, b2190, b2560 |
| Global ImgFFD / OpeFFD | 272e / 272f | a8580 / a8490, a8670, 98cc0 |
| Global ErrRep / TMRRep | 2718 / 2734 | 97cf0 / af8a0, 97e80, 98930 |
| Global MktMonRam / MktMonRamSSR | 2731 / 2735 | a22e0 / a2ab0, a23b0 |
| ECU DTCMon | 2716 | 8fd40, 8fe20, 7d680, 90d20, 90f60, 912f0, 918d0, 92e20, 93470, 93810 |
| ECU DTCP5 | 272d | 944f0, 945c0, 94e00, 95310, 95590, 957e0, 95a60 |
| ECU SysChk | 2719 | adf20, ae000, 8e6a0 |
| ECU FuelCon | 271e | 9af10, 9aff0, 8e6a0, 9b650 |
| ECU OpeHis | 2720 | a4500, a45e0, a4c10, a4f60, a55f0 |
| ECU ROB | 2721 / 2722 | aafa0, ab020, ab5d0, abce0, ac0a0 |
| ECU Oscillo | 2727 | a7a70, a2f50, a3230, a35d0, a37d0 |
| ECU ABSHis | 2729 | 86520, 87340 |
| ECU ICSHis | 272b | a0400 |
| ECU AFO2Sn | 272c | 88c60, 88ce0 |
| ECU PSDHis | 2730 | a9460, a9d20 |
| ECU PreFFD | 2732 | a8a60, a8b30 |
| ECU OpeInope | 2733 | a6470, assembly a6824–a6d10 |

The shared structural primitives retain native selector values and all their
payloads: common label/date/description (`80480`), ordinary/extended signal
metadata (`7fd30`/`80e50`), choices and scaling descriptors (`7fe90`, `80220`),
DTC structures (`7e0f0`), history values/parameters (`84990`, `84420`), and monitor
bodies (`8e6a0`). In particular, native signal mode 1 omits the wide identifier;
mode 2 includes its version/flavor-dependent uint16/uint32 identifier. The
HealthCheck selector controls its optional measurement block and ECU shape.
The DTC context branch is `int(file.file_type == 4)`, proven by header reader
`9a562–9a57d` calling setter `0e7e0`; it is not inferred from DTC contents.

Native reserved fields remain bytes, including ROBCommon's single 80-byte tail
after the complete list. ErrRep/TMRRep retain image names, length-prefixed image
bytes, status words, fixed strings and skipped legacy padding. They perform no
path-based extraction. OpeInope was decoded from assembly and cross-checked against decompilation
with the native stack probe explicitly modeled as `alloca_probe`.

## Bounds and evidence

Host limits are 32 MiB per binary input/output, 100,000 structural nodes and
64 nesting levels, plus an aggregate 32 MiB/100,000-node presentation budget.
Writers validate unsigned widths, exact tuple arity, fixed buffer sizes, field
limits and recursive aliases. Unsupported families/versions, trailing bytes,
truncation, invalid lengths and excessive expansion fail explicitly.
SysChk/FuelCon currently accept section versions `1000–1021`; other ordinary
families accept the recovered version branches through `1027`. Error report
branches extend through `2009`. These are host support boundaries; later
unobserved formats are rejected.

Two original private owner captures (file versions `1006` and `1025`) validate
seven actual sections: both IniCarInfo/ConfCarInfo pairs, DTCMon, HealthCheck and
MultiPID. Each section round-trips exactly; identity replacement preserves the
entire file. A resized configuration edit preserves all other report bodies and
reopens with relocated offsets. Captures and vehicle identifiers are not
redistributed. Other families have native static layout evidence and authored
vectors, rather than original recording coverage or original application
acceptance. No physical behavior is claimed.

Run `python -m unittest tests.test_tse_reports -v`. Tests include independently
packed native vectors, every byte truncation of a nonempty record for all 29
families, version/context branches, image retention, feature aliases, offset
relocation, invalid counts/types and aggregate budget rejection.

AllDTC XML imports use `parse_all_dtc_xml(data, native_file=False)` or
`load_all_dtc_xml(path, native_file=True)`. The latter reads a pinned regular
file with the shared size guard. Native file mode requires the UTF-16BE BOM
that the original loader removes before swapping each code unit. Ordinary XML
mode uses the XML declaration/BOM through the standard library parser. Neither
mode loads a DLL. DTD/entity declarations, element namespaces, more than 64 levels,
100,000 retained parser objects, and inputs exceeding the shared byte budget are rejected.
Malformed XML is rejected during opening; the native implementation postpones
DOM parsing until a query. No original AllDTC XML capture has been validated.

`AllDTCXML` implements host adapters for the nine exports: `open_xml_w`,
`open_xml_a`, `close_xml`, `get_parameter_length_w`, `get_parameter_w`,
`get_api_last_error`, `get_dtc_number`, `get_parameter_length_a`, and
`get_parameter_a`. Python returns replace output pointers and `ReportError`
replaces failed BOOL returns. A methods use CP932; callers supplying a native
ANSI filename must ensure its encoding matches that context. W methods return
UTF-16LE bytes including the terminator; lengths are bytes. A methods return
CP932 bytes including the terminator. Empty ordinary string length is zero. Empty `ManufactureInfo` reports W length
2 and A length 1; its transformed byte string stops at the first NUL.
The 20-component index vector applies a zero-based index to every path
component, including containers. An omitted vector contains zeros. Invalid
IDs, index vectors and insufficient output buffers fail explicitly. Errors
remain sticky across successful calls and closing: 1 buffer, 2 nonstring
length query, 3 absent node, 4 parameter ID, 5 closed reader. Host validation
failures without a corresponding native error assignment leave it unchanged.

The 118-entry schema preserves native field spelling, signed versus unsigned
32-bit decimal conversion, strict boolean tokens, and the special
`ManufactureInfo` double-hex/byte-transform/CP932 decoding. Its W length uses
the native encoded-length formula and can exceed the decoded string size.
Decimal overflow saturates at Windows 32-bit limits. Host decimal strings
longer than 128 characters fail before integer conversion. `get_dtc_number`
returns one `(unsigned_ecu_id, matching_dtc_count)` pair per ECU, comparing
the native XQL string value of `DTCTypeId` to the requested signed decimal representation.

`view_all_dtc_xml(reader)` returns the stored vehicle fields and ECU/DTC rows,
including `DTCDispValue`, `DTCName`, `DTCTypeName`, `DiagnosisTypeGridName`,
`StatusGridName`, and nested freeze-frame parameter names, units and values
when present. `stored_fields` retains the complete named XML element tree. View construction
shares a node/UTF-8 text budget across the vehicle, ECU/DTC rows and full tree;
it rejects excess before retaining the next output field. These are
saved labels, not translations or inferred numeric status meanings. This
import path does not prove the numeric status-column enums of binary TSE.

Native provenance: `AllDTCReadModule.dll` SHA-256
`b534fe7eabe4675623eccf828ef30513be34e7af1fe97a3fae9a68bd555a6bc3`;
export RVAs `1000`, `1050`, `10a0`, `10f0`, `1120`, `1160`, `1190`, `11d0`,
`1200`; schema `a050`; file conversion `13d0`; component indexing `1430`;
special string conversion `16a0`; W lengths `1850`; A conversion `19c0`;
typed output `1dd0`; query `20d0`; ECU/count output `2490`, unsigned ECU
conversion `2870`. Original code and binary-derived analysis remain private.

The native indexed-pattern selection is backed by a separate static audit of
Microsoft MSXML 3.0 version `8.110.10240.16384`, SHA-256
`1b1a845da98a658577882fc8a74eaea14b11300bd557231092c643a6fa6d4e11`,
obtained with its matching PDB from the [Microsoft symbol server](https://msdl.microsoft.com/download/symbols/msxml3.dll/559F3B06190000/msxml3.dll).
Although the documented method name is `getElementsByTagName`, this native
implementation prepends `.//` to the supplied pattern without escaping it,
then invokes its XQL parser. `DOMDocumentWrapper` RVA `c3ec0` forwards to
`DOMNode` RVA `54e33`; `54e88`–`54e9d` concatenate prefix RVA `9080` and
input, then `54eac`–`54eb0` select language 0 and create an XQL selection.
`parseSelection` RVA `66fbc`, branch `67050`–`67064`, maps language 0 to
`newXQLParser`, and language 1 to `newXPathParser`. No Microsoft DLL was run.

The host implements the fixed native schema subset: descendant search for
the first path component, child steps, per-parent zero-based positions and
first complete matching path. It does not accept arbitrary query text.
Query work has a shared bound of 20 times the element budget, and result
lists share the element bound. The ECU count adapter preserves the original
failure when several nonempty ECU-array parents cause its global count to
exceed the per-parent positional index space. The authored nested-document,
multiple-prefix and work-budget checks cover these branches. This establishes
the recovered reader's query contract for the audited MSXML implementation;
other MSXML binary versions and original AllDTC XML captures were not tested.
Unsupported XML declaration encodings fail with `ReportError`; ordinary XML
mode uses the standard library parser encodings rather than guessing a
Windows ANSI codepage.

The reader also ports the audited MSXML text getter rather than using raw
concatenation. For this CLSID, the factory table selects `CreateDOMDocument10`
RVA `725e0`, which calls `_createDOMDocument` RVA `24209`; its `setDOM(true)`
call selects the DOM **trim** mode. Ordinary text-node ends trim only XML
whitespace U+0009/U+000A/U+000D/U+0020; internal whitespace within a text
node remains intact. Boundaries between trimmed text nodes carry a single
pending space. Inherited `xml:space="preserve"` preserves text, with a local
case-sensitive override. CDATA retains its own preserve mode, including
empty CDATA boundaries. Returned CR and CRLF normalize to LF. A bounded
standard-library Expat builder retains text-node/CDATA boundaries and source
order; the combined element, attribute, text-fragment and boundary object
budget is 100,000, with a separate shared retained UTF-8 byte budget.

The `DTCTypeId` predicate follows the separate native XQL string comparison
path, which requests trim mode without the DOM `xml:space` context; CDATA
still uses its preserve visitor. Thus an ordinary padded `3` matches type 3,
even under `xml:space="preserve"`, while CDATA containing ` 3 ` does not.
Parameter reads use the DOM context instead. View leaf values use the DOM
getter; exact original XML bytes remain in `reader.source`. Native file mode
accepts one optional UTF-16 NUL terminator and rejects embedded NUL/trailing
non-XML content. Native provenance for text: DOM getter `30710` → inner text
`36fea` → XML-space visitor `374da`; PCData `44b70`, CDATA `73980`, shared
finalizer `2d910`, trim append `67e9e`, exact whitespace table `f5c8`, line
ending normalization `73a86`/`73b13`. XQL comparison `5a7e0` → `5f1c0` →
`getInnerTextStrip` `5f8fb` selects `DOMTrimVisitor`; it is not inferred from
the DOM parameter getter.

The ADS extended signal reader `85d30` includes the `85e10` sample list: a WORD count, followed by uint64 raw value, stored string, and BYTE type per sample. Empty lists still store their count. Values above 32 bits and the stored strings are preserved without inferred formatting.

ADS uint64 signals also use the named parameter view: identifier, name, short name, unit, raw selector/flags and full-width samples with their stored native display text. CommandAPI `06d80` and GUI `413bd0` establish the same metadata order as ordinary signals.

Health system `group_name` names the first stored string, following the concrete CommonECU `strGroupName` → Health220 producer and the same `461ed0`/`46e2c0` class copied into the saved Health list. The earlier `short_name` key remains as a compatibility alias. The separate active-object `+5cc`/`+5dc` workflow join is not claimed by this field mapping.

The current ErrorReportLib writer resets the additional preference WORD to zero in `136d0` (`13733`) through root reset `13b70`, then converter `117a2` fills only the preceding ten words. It does not copy the cached Distance choice into that word. The decoder retains arbitrary stored `additional_selector_raw` values for other authors and versions.
