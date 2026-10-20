# Work-factor history analysis

`scripts.toyota_analysis.DcmP5Analysis(profile, cache).run()` composes actual
selected metadata, support observations and DID bytes into immutable
`AnalysisResult` / `WorkFactorGroupP5` / `WorkFactorRecordP5` values. The cache is
`MonitorSupportCache`; its injected provider performs byte transactions only.
Imports and constructors never open a transport.

`DcmP5Analysis.from_communication(connection)` binds an actual
`NativeCommunication` with a concrete `NativeFrameController` and calls its
source-derived `disconnect(1)` after business execution, including failures.
`AnalysisResult.disconnect_status` preserves the cleanup result separately from
native business status; on an exception it remains on `provider.cleanup_status`.
The cache-only constructor performs the business scope and leaves lifecycle
ownership with its caller.

The selected management DB113 command `0xD7` must name
`GetAnlWkFctDcm35_DT.dll`. Other modules and build12 fail closed. Context identity,
source build, cancellation, deadline and receive limits remain those of the
selected cache. No support bitmap or analyzed record is manufactured.

## Recovered DCM35 behavior

- Query each selected DB272 DID with native `GetDataNoEnableList` flags3; retain
  status2 DIDs in selected order. No upper-page support gives `0x90040501`;
  upper-page support with no lower-page support returns an empty result.
- Read each retained DID using the first selected function `0xCA` frame, replacing
  bytes1/2 with the big-endian DID. Use the selected observed bus, Ext TEMP cache
  and skip the first three reply bytes. The nine native skippable read statuses
  are recorded individually. Other errors propagate.
- Divide the payload into 12byte records, ignoring an incomplete trailing record
  while preserving the full received payload. Find the first FF12 marker. Visit
  records before it in reverse, then records after it in reverse. With no marker,
  native leaves marker index0: record0 is therefore omitted. Additional FF12
  records are ignored.
- Resolve the big-endian opcode through selected DB274 `(DID, opcode)`. An absent
  opcode definition omits that record. Its original definition and bytes remain
  attached to every emitted record.
- A record with bytes2/3=`02 06` converts bytes4..10 from packed BCD, stopping at
  the first invalid byte and retaining the converted prefix with `time_valid`
  false. No calendar or timezone interpretation is inferred.
- For record byte2=`02` and byte10=`01`, DB275 selectors1..4 extract their literal
  inclusive bit ranges from byte11, then DB225 `(pattern,value)` resolves status
  text. Missing/invalid definitions fail, rather than inventing labels.

## Static source identities

All addresses below are RVAs in native build18. OEM binaries and disassembly are
private BYOD evidence, excluded from public source delivery.

| Artifact | SHA256 | Source entries |
|---|---|---|
| CommandCommon.dll | `07547a9e47378d37c3ef7d96c2f33f6c62c4151626d98d3f3ff03b7c74909de7` | `2dcd0` init; `2dd60` support; `2e020` read; `2e140` group; `2e2e0` records; `2e850/2e8e0` markers; `2e940` opcodes; `2eaf0/2eca0` network; `69c70/69e50` DID primitives |
| GetAnlWkFctDcm35_DT.dll | `f154e9b2fceede17af35cdb90148ccc9b33f030f7de8d66b00498873cc9eccf2` | `1010` Execute, skip-status list `10e8..1154` |
| CommandAPI.dll | `43913a3baeef678b70dd3f7a533575824d9d88e2acb61acb23702983e5b337f3` | `2d070` facade |

`dcm_marker` implements Common18 `2c650` (bytes4..7 only);
`rob_marker` implements `37ae0` (empty DID-list is not a marker, nonempty list of
empty/allFF DID values is a marker). `rob_marker_order` follows `37bb0/37dc0`: it retains additional marker groups
in the copied result. These helpers do not constitute DCM/RoB providers.

`rob_lsb` ports Common18 `37960`: multiply into the low DWORD before
signed division (zero divisor becomes1), retain DWORD result bits, and calculate
the rollover modulus with x86's masked shift count. The PhyData offset is unused
by this helper. Authored checks include negative divisors, overflow and width32.

`rob_timing` ports scalar Common18 `37fa0/380b0/381b0`: happened-time
accumulation stops at the first generation mismatch, passed-time accumulation
runs backwards and restarts across generations, wrap counts retain the maximum,
and every DWORD calculation wraps modulo 2^32. Inputs retain the original
record fields `+0xac/+0x13c` and selected current/modulus/generation values;
outputs map `+0xf4`, rewritten `+0xac` and adjusted current `+0xac`. It neither
decodes those fields from a diagnostic reply nor assumes wall-clock units.

## Recovered original18 RoB behavior

`RoBAnalysis(profile, cache).run(mode=1, current_flag=1)` uses selected DB113
command `0xD6` / `GetRoBP5_AnlzWkFct_DT.dll`. The immutable result retains its
native source hashes, selected context, language hash, current observations and
history groups. Its primitive provider returns diagnostic bytes only.

- If `current_flag == 1`, signals `19/1a/1b` resolve selected SignalGroup,
  SignalCheck, DatamonitorP5, PhyData and Unit rows. Exactly one CA template is
  patched with the DID; `CommCacheSndRcvExt` uses parameter0. The current-time
  host SYSTEMTIME is captured after signal1a, before1b. Selected Datamonitor
  DWORD24 references are eagerly checked, including unused selected rows;
  DWORD0 is not a language reference in this native class.
- After native Sleep(100), F3 enumerates work-factor IDs from reply offset2.
  Undefined DB272 IDs are omitted. Mode2 emits selected group metadata alone;
  mode1 reads F4, patches the work-factor ID, extracts unique history IDs from
  offset4, and issues F5 with the work-factor/history pair. These are direct
  extended transactions with parameter0. Native skipped errors are recorded;
  unhandled faults and host interruption propagate.
- F5 offset6 contains counted DID/length/value blocks. Malformed trailing
  entries omit that entire read. Zero count uses the native fallback scan from
  absolute offset7. Two consecutive allFF markers stop acquisition; malformed
  reads and skipped errors reset that sequence. Marker sorting preserves native
  default index0 when no marker occurs.
- Exactly two distinct, DB273-defined DIDs are required per emitted history
  record. Item types1..4 extract their selected inclusive bit ranges, apply
  low-DWORD multiplication and signed division, then resolve the actual Unit.
  Type1 resolves selected Pattern37 or produces native hexadecimal fallback;
  type2/3/4 retain named scalar/unit fields. Happened/passed/reset timing uses
  the recovered native DWORD arithmetic across every emitted group.
- The four native record value blocks correspond to type2, type3/passed,
  happened and type4. Missing blocks retain constructor format`0x4000`.
  `record.values` retains the three observed type2/3/4 blocks;
  `record.passed` is the transformed type3 value and optional`record.happened`
  supplies the third native block with format1 when present.
- RoB Execute does not call Disconnect. The concrete communication owner keeps
  lifecycle responsibility. An authored test runs the complete provider
  through `NativeCommunication` / `NativeFrameController` and J2534 bytes,
  then explicitly closes its test-owned connection.

RoB source SHA256 is
`3d6c8ad1d93d4690f88e8b0fc51a3ae3d7b9b4348e6077781b2a7b6988842c02`.
DT RVAs: `4060/38b0` Execute, `10f0` F3, `1410` metadata, `33b0` F4,
`17c0` F5, `1a40/32b0` byte blocks, `1f00/30d0` selected DIDs,
`2660/29f0/2b60/2e90` item/Pattern/physical/unit joins. Common18 RVAs are
`37120/37420/37500/37960` current observations and
`37ae0/37bb0/37dc0/37f70/37fa0/380b0/381b0` marker/timing.

Bus14 supplies the recovered WORD2a capacity65535 through the existing typed
cache/communication API without changing selected metadata. An actual
EthernetOperations fixture accepts a4100-byte F3 reply, including native
startup/discovery and caller-owned cleanup. The retained bundled12/18 CRT
formats NULL`%s` as`(null)`; selected null group/Pattern names preserve that
literal. Each recovered sprintf caller has a256-byte stack region. The port
rejects output of256 bytes or more rather than simulating undefined overflow.
For non-ASCII formatted text the caller must supply observed`ansi_encoding`;
there is no guessed ACP. Its narrow encoded length controls the bound. The
selected bus, source, profile, language and encoding cannot change while a
provider runs. Independent RoB source review and the actual CommandAPI RoB
outer composer remain OPEN.

## Recovered original12/18 DCM P4 Execute

`DcmAnalysis(profile, cache).run(mode=2)` requires selected DB113 command78
and `GetAnlWkFctDcmP4_DT.dll`. Module names in DB113 and inline DB272 display
prefixes are UTF16LE fields. The provider preserves the observed bus and selected
source/language identity throughout execution. Its native DWORD mode is distinct
from the public CommandAPI input byte: API0/1/2 selects native2/1/4.

Every Execute creates a fresh TEMP scope, reads the actual support-bit stream,
and creates the native P4 enabled-PID list. Mode1 reads five selected current
signals1e..22. Native PID acquisition faults become zero values with format4004;
metadata/physical/unit failures still propagate. Supported values use signed64
physical multiplication/division and a low-DWORD offset; a zero divisor leaves
raw input unchanged. P3 uses raw PID payload and generic bit extraction; P4
expands the observed supported byte positions and uses the distinct native DCM
bit helper.

Mode2 queries selected DB223 rows and hydrated wildcard DB20A groups. For each
PID61 group, four selected PID observations construct the native RAM frame.
PID reads use TEMP ordinary transactions with capacity255; A1 fixed RAM reads
are direct ordinary transactions. RAM count0 performs no reads; other bounded
counts read count+1 words. Native mode0/1 addresses advance2/4 respectively.
Any successful RAM word makes that capture successful; other faults remain
attached. If every capture fails, the last native status is returned.

The first FF4 marker divides two reverse passes; no marker preserves native
index0 omission. Zero and marker records are excluded. Each selected DB224 item
extracts its actual bit range, multiplies into a DWORD, optionally divides
unsigned and adds its DWORD offset. Pattern37 receives the lowWORD value.
Fixed records retain format0 even when the Pattern is absent. Typed output owns
all group/item definitions, raw bytes, addresses and individual RAM failures.

Native mode4 additionally requires explicit `DcmLog(directory, car_id)` inputs:
the Linux folder maps native CSIDL2e/Techstream/DCM, and `car_id` is the observed
shared9 WORD. No folder or vehicle ID is guessed. This branch always reads the
five current signals, orders selected DB223 rows by WORD18 using the original
qsort swaps (including equal keys), reads variable RAM, then orders captures by
WORD20. BYTE24 excludes invalid groups; BYTE25 controls record length.
The address width comes from the last selected Freeze bit width, using native
signed truncation. Group WORD22 and item BYTE36/Pattern status compose the rich
format WORDs. Variable item ranges outside the acquired record return C0040001.

The concrete journal consumes the active TEMP snapshot, preserving native
request/reply order, cache-hit deduplication and negative empty replies. It
retains at most nine older eligible timestamp files before creating the current
file, writes the native header and comma-separated TST/ECU hex lines (63-byte
limit), and removes the new file after a write/close failure. Filesystem failures
return90040f01. The input directory is a caller-selected output mapping, so this
has no implicit installation-directory write or external service dependency.
Authored checks include variable acquisition through the public rich consumer,
actual file bytes, qsort tie order, timestamp rotation and file-output failure.
Independent full variable-path source review remains OPEN.

The native fixed producer has source SHA256
`75eeffb791ee55c3a334288590e4e53a796a850111bc616ee192cd39d78e1db8`,
DT RVAs1010/1060/2fe0; Common18 RVAs2be70,2c150,2c3a0,2d420,
2c870,2d150,2b560,2cfc0 and2d9f0. Fixed and variable RAM primitive method
bodies were independently paired against original12, including direct callees
and imports; the fixed Execute43-byte wrapper,3141-byte business body and593-byte RAM wrapper were also paired. Original12 uses the same selected current/fixed algorithms, with the recovered embedded CDiagToolDb offset changing fromb8 tobc in build18. Its variable Execute has different cleanup/error code layout; the business branches and RAM/journal/qsort/hex helpers were separately reconciled before enabling it.
The variable primitive preserves56-byte chunks, odd word-address alignment,
TEMP cache and partial-record failures. Count255 is rejected because its native
BYTE loop cannot terminate.

Authored fixtures cover literal selected DDB/support/PID/RAM chronology and the
complete NativeCommunication/NativeFrameController/J2534 software route. A
fresh-channel test also reaches public `CommandAPI.get_analyze_work_factor_dcm`
and its saved/UI report adapter. Native flat output correctly omits rows with
fewer than nine items. The connection owner performs cleanup. These checks do
not establish physical hardware behavior.

The selected original18 `GetAnlWkFctDcm24_DT.dll` variant uses source SHA256
`65dee471c46438f8b097833eb9a1df90b252a5b7162fc7de473ef99b4e638b68`.
Its fixed path matches P4. Its variable path deliberately differs: four acquired
PID observations establish eligibility before RAM; at least one definition must
have BYTE24 exactly1 and a nonzero acquired RAM count. With no eligible group it
returns success without groups. With eligible groups it composes and journals
even if every RAM read failed, preserving empty groups and native success.
The authored lower-stack and public-consumer checks cover this behavior and
reject source12 before I/O. No build12 Dcm24 artifact is inferred.

`read_plain_p3_ram(cache, raw_frame)` separately implements the original12/18
PlainP3 A1 primitive. Each four-byte record uses two direct halfword reads,
with exact SID, echo and reply-length checks. A failed halfword discards that
record and skips its remaining reads; any complete record makes the returned
capture successful. The native wrapper preserves a zero trailing DWORD.
Its DWORD count loop permits255, unlike the DCM P4 BYTE loop. Authored checks
cover literal requests, partial and total failures, cancellation and256 records.
This primitive does not implement the ordinary work-factor business provider.

The selected `GetAnlWkFctBTP4_DT.dll` variant is implemented for both builds,
with SHA256 `96d54db1e4bc176ccc9e22820d2a5c9be00fd36e17ed6b16c971bbf9d279d880`
(12) and `4e748d7cf69550c06aea703d3d41e468773c492cf5ddf9472588df1f6a1e4def`
(18). Its current, fixed and variable business follows the separately reviewed
P4 paths. Its concrete file mapping must use
`DcmLog(directory, car_id, family="BT-03")`: native output is under
`Techstream/BT`, with `BT-03_` timestamp filenames and an additional
case-sensitive `.log` extension check during rotation. The authored checks
reach the real lower software stack and public92 consumer for both builds,
including native journal failure retention. Independent business review is open.

The original selected management command for ordinary work-factor analysis is
`0x6F`: the retained12/18 EU/JP/NA management sets select P3 by default and P4 for
specific ECU categories. BTP4 is selected under the separate DCM command `0x78`.
The ordinary current-time calculation also reads signal `0x18` as a conversion
coefficient; its history calculation differs from both DCM and RoB. Those
remaining source branches are not inferred from the implemented providers.

## Open behavior

`PlainAnalysis(profile, cache).run()` implements selected `0x6F`
`GetAnlzWrkFctP3_DT.dll` with phase3 metadata and the normal
`GetAnlzWrkFctP4_DT.dll` branch with phase4 metadata, on original12 and18.
It returns immutable `PlainAnalysisResult`, `PlainWorkFactorGroup` and
`PlainWorkFactorItem` values. The P4 Adjust99 branch is implemented.
The P4 TS4 and power-supply-control branches are implemented with actual
public-consumer checks on both builds.

The P3 provider builds the normal enabled-PID list, resolves current signals
`19/1a/1b` and coefficient signal `18`, acquires four selected PID observations
per DB223 definition, and reads the native RAM records. Its ordinary history
uses generic bit extraction, selected DB224 definitions, Pattern37 name/help,
and the raw Pattern WORD12 formatted as the reset row's decimal content.
It preserves native marker scan order, happened/passed triples, generation
changes, DWORD rollover and the final adjustment to current1a. It does not infer
time units. Partial native business status is retained separately from emitted
records; cancellation and selected-context changes propagate.

Both original versions have authored selected-DDB tests through the actual
NativeCommunication/NativeFrameController/J2534 software stack and caller-owned
disconnect. Twenty-six Common base-method bodies were separately paired across
the versions, including actual imports/callees and the selected database offset.
Public `CommandAPI.get_analyze_work_factor` and `plain_analysis_report` consume
these values. P3 never acquires the separate TS family; the facade preserves
its verified empty list and full constructor-default current timestamp metadata.
Fresh literal negative RAM replies exercise native status `0x90020321`, skipped
second-half reads, retained previous facade output and caller-owned cleanup.

The normal P4 path accepts selected DB223 WORD22 values0/3 and record lengths0/4;
it uses the actual support stream, P4 enabled list and generic bit helper after
PID expansion. It supplies native empty/zero/`0x4000` defaults for absent
type2/type3/reset metadata, retaining the last selected type2/type3 rows.
Its TS-current and TS-history calls are gated off by the actual selected modes,
so the API preserves the verified constructor-default TS carrier. Both builds
have real lower-stack, public-consumer, negative-reply and cleanup checks.

The P4 Adjust99 branch preserves failed RAM records as three `0x2000` rows,
reorders complete five-record blocks, marks the leading triple `0x8000`, and
rewrites digit runs in selected contents using the source opcode. It preserves
the native narrow-text bounds and requires an observed ANSI encoding for
non-ASCII contents. The bundled CRT span helpers were independently checked
in assembly. Both builds pass actual lower-stack and public-consumer checks.

The PSC provider uses P4 acquisition with strict base current/history metadata.
Its special adjustment path is selected by the last Freeze PID `0x29`; the
DB223 mode is retained as output and does not select TS acquisition. Missing
reset metadata remains an error, including on the adjusted path. Both builds
have actual lower-stack/public-consumer positive, native-fault retention and
cleanup checks for ordinary and adjusted PSC. P4 and PSC current acquisition
uses the selected phase3/4; their history acquisition always uses P4.

The P4 TS4 path acquires current signals `1c/1d` before ordinary current
acquisition, hydrates selected Freeze/physical/unit/pattern metadata and runs
concrete `SignalLSB`. Abnormal values or native metadata errors clear both
current timestamp components. History uses direct RAM records with the selected
BYTE length and rounded address stride, preserving marker order and separate
kind2/kind18 metadata. Missing components set `0x4000`; successful history rows
retain format8. Raw/status values remain separate from the CommandAPI renderer.

Both versions pass actual J2534-stack and public-facade tests at record lengths4
and5, including nonempty current/history timestamp metadata, numeric current
rendering, native `-TypeErr-` for reset selector0, source/cancel guards, previous
output retention after native RAM faults and caller-owned disconnect. The third
scalar is the native DWORD148, independently of the third freeze's raw list.
The original18 facade's unwritten extension tail retains constructor defaults.
Unknown P4 modes and invalid fixed-record lengths finish the native PID reads
and skip RAM; they preserve the native zero return instead of inventing history.

This is a partial business implementation, not closure of original12/18
work-factor exports. The original12 fixed provider `GetAnlWkFctDcmP4_DT.dll` source is
`d697f922c182ec4274bed1fd6939440b8cacffc21e0450cd44a6576d179702ba`,
Execute RVA `1010`; neither DCM35 nor RoB is inferred as a build12 fallback. Independent full DCM P4/24 source review and independent plain TS/Adjust/power-supply-control review remains
OPEN; the remaining RoB gaps are listed above. CommandAPI `compose_dcm35_analysis` consumes these typed values and
maps the recovered build18 application fields, including the first six BCD time
values/year+2000 and four gated network labels. The DCM35 explicit connection path includes native
`Disconnect(1)`; its authored J2534 test scopes initialization off with an explicit
host `no_init` selection so it proves business-to-transport-to-cleanup composition,
not physical startup timing. The typed output
above is the recovered DCM35 business data, not a claim that those missing
branches have executed. Physical transport and vehicle behavior are
PHYSICAL_UNCONFIRMED.

The owned authored checks run with:

```sh
python -m unittest discover -s tests -p test_toyota_analysis.py -v
```
