# Saved image and operation freeze-frame recovery

The overall leaf remains **OPEN**. TSS3, original12/18 LCS and original18 ADS
operation business producers and concrete saved-log lifecycles are implemented.
Generic original12/18 P4 image also reaches the actual selected BB saved facade;
canonical ADS DDR report acquisition and saved output reuse leaf49's provider.
TSS3/LCS/ADS operations execute through source-selected CommandAPI routes and first-scalar
projection plus logical native0x6c metadata fields. Independent source review
remains open. Five P5 image producer families are incomplete; no complete
Toyota or hardware equivalence is claimed.

## TSS3 operations

`capture_tss3_saved_operations(communication, packet_log, source)` accepts concrete
`NativeCommunication` and `DdrPacketLog` instances sharing one retained native
controller, plus an exact `SavedFfdSource` identity. It runs native log kind25,
NoBuffer connection frame0/settings1, selected function0x66 acquisition, native
Disconnect1 and log close. A logging failure replaces only a zero diagnostic
status. The native ignored Disconnect status remains separately visible.
Cancellation, selected-source changes and host resource limits propagate after
independent disconnect and log cleanup. A later host cleanup failure annotates
and preserves the original interruption identity. Construction/import opens no device and executes no OEM code.

`SavedFfdProvider.capture_tss3_operation_records()` executes the complete inner
producer under a local `temporary_scope(no_init=True)`:

- `AB 11` returns supported group WORDs. The fifteen native non-operation groups
  are skipped; a list containing only those groups returns native `90040501`.
- `AB 12 GROUP_BE` returns operation WORDs after a four-byte header. The producer
  sorts and deduplicates them with the original unsigned ordering.
- `AB 13 GROUP_BE OPERATION_BE` reads each actual payload. Nine native receive
  errors are suppressed and retained explicitly. Two consecutive record failures
  end that group's loop; a successful receive resets that condition.
- Only nonzero operation numbers fitting one BYTE and containing native values
  enter the native freeze list. Other operation numbers are still acquired before
  that output filter, matching the source.

A payload contains a six-byte prefix and count/DID/length/data groups. Native
zero-count handling scans entries starting at absolute offset seven. Zero DID or
length entries are skipped; the first duplicate DID wins within a group. Complete
records preceding a truncated record are retained. Only DID `0501` with at least
two bytes produces a big-endian WORD scalar. Raw replies, source identity and
selected-frame provenance remain owned by the typed result.

`Tss3SavedFreeze.native_values` represents the native `CCmdFrzFrmDat` multi-value
list. The original CommandAPI facade consumes only its first value. The operation
and group fields are acquisition provenance; they are not invented native freeze
metadata or display labels.

Source: original18 `GetTSS3OperationFFDP5_DT.dll`, SHA256
`8d8461cf1b1f9b9917919fa4ea366891e0867c2f3e82d56d1a27ae2990e38f86`.
Relevant RVAs: `32f0` outer Execute, `2790` full group/record producer, `10e0`
support query, `21d0` operation index, `1540` selector association, `15a0` payload
acquisition, `1a70` parser, `1f90` scalar projection, `20b0` zero-count fallback,
`30d0` group exclusion and `31b0` selected communication acquisition. The parser
uses bounded Python ownership where the original could dereference short input.

## LCS operations

`capture_lcs_saved_operations(communication, packet_log, source)` implements
original12 Execute RVA2740 and original18 RVA2800 with log kind19 and the same
concrete connection/disconnect/error lifecycle. Source identities are the exact
`LCS_SOURCE_SHA256` entries, never inferred from requests or diagnostic replies.

The inner `SavedFfdProvider.capture_lcs_operation_records()` first sends
`22 1F 01`, `22 1F 02`, `22 1F 03` using one fresh TEMP response cache with
`no_init=True`. Native extended receive checks only the positive service byte;
it does not compare the three declared expected bytes. Each later `AB11/12/13`
helper constructs a default cache: these stages use normal initialization and
uncached extended reads. LCS processes every supported group, including `2270`
which the TSS3 provider excludes. Index ordering, record parsing, first-DID wins,
`0501` projection, nine suppressed statuses and consecutive-failure behavior
share the source-reconciled native operation layout and typed report with TSS3.
The TSS3-prefixed result classes retain their public names for the existing
CommandAPI join; LCS adds no guessed freeze metadata.

Source: original12 `GetLCSOperationFFDP5_DT.dll`, SHA256
`70fd00da7f49e35cc0d23479e4ef6572859b8c044f99b1e1eba18bf90d10c24f`;
original18 same module, SHA256
`f9ed3d6ba96482c019f15ce83df937038f8fcef00947069c646b8c832a0a2db6`.
Main RVAs12 `2a70`,18 `2b30`; support query both `10e0`, record query both
`1620`, grouped parser both `1b10`, scalar projection12 `2010`/18 `2030`.
The private source packet retains both complete closures and original assembly.

## ADS operation phase acquisition

`capture_ads_operation_phase(cache, source, phase)` implements the actual18
RVA33d0 group/index/record business phase3 (`AB21/22/23`) and phase4
(`AB31/32/33`). It acquires each selected function66 payload through real
extended primitives with native65535 capacity. DWORD indexes sort and deduplicate
using the unsigned comparator corroborated at ASM RVA3360. Native output accepts
operation numbers1..EFFF after acquiring all indexed operations.

`ads_operation_groups()` retains eight-byte-prefix Ext DID records, including
four-byte big-endian lengths for DIDs6000..6FFF, absolute-offset9 zero-count scan,
first duplicate wins and0501 scalar projection. An empty parsed list ends native
parsing. The group membership function scans42 WORDs through adjacent vtable data;
the port preserves the literal range instead of substituting a plausible21-entry
business allowlist. Receive errors follow the same nine-status and consecutive
record-failure rules as the retained source.

Source18 `GetADSOperationFFDP5_DT.dll`, SHA256
`c5549207080aabc0a7d415caa610818fd0df4ca2afc78a14b3c5a6e1861d8bce`;
RVAs1010 Execute,33d0 phase producer,17b0 support,2cc0 DWORD indexes,
1cf0 record receive,23f0/2ae0 grouped parser,29c0 scalar projection,3b10
membership.

`capture_ads_saved_operations(communication, packet_log, source, key)` implements
Execute1010 with concrete native18 ownership: log22, NoBuffer frame0/settings11,
selected66 metadata, actual49 security109/10A, global/group readiness for1C08,
phase3, ChangeCommLogFile23, phase4, Disconnect1 and log close. The same no-init
cache flag remains active for security, readiness and both phases. The key is
explicit private BYOD input obtainable from49 `selected_ads_security_key()`.
No vendor key is embedded in authored code.

A missing/suppressed first phase still permits phase4. Successful phase4 clears
that first-phase status; a suppressed phase4 restores it. A log-switch failure
stops logging immediately but still executes phase4. The actual acquired phase
results and readiness/security observations remain owned by the typed result.
Seven concrete J2534 replay paths verify those branches and both actual output
files. They include a nonzero seed/key exchange checked against a public AES128
known-answer vector. Seven additional paths run through the actual DB113E0-selected
`CommandAPI.get_ads_operation_ffd()` route and JSON saved-report adapter,
verifying first-scalar projection,
append and native-fault retention. Native logical metadata includes reset WORDs
`(0,1,0,0,0)`, eight zero DWORDs, three zero BYTEs, three empty strings and an empty
display list. The nonzero conversion-core WORD at+1c comes from the native
constructor, with both12/18 corroboration retained by92. Independent source review
remains **OPEN**.

## ADS selected fields

`ads_ddr_value_definitions()` consumes the actual hydrated selected resource
facades: DB286 definitions, DB25A DID support mode and DB259 bit conditions.
`decode_ads_ddr_group()` associates actual observed DID payloads with those
resources and extracts unsigned64 values. The native support-bit mode reads the
preceding payload byte; predicate7 evaluates the actual condition DID and its
selected bit range. Unknown support modes disable the value rather than inventing
support. Definition and condition resource failures remain explicit.

Source: original18 `GetADSDDRInfoP5_DT.dll`, SHA256
`28a4474c71344970c3e9736af1d835215d0aac02d4f31cee832101981f1246df`,
RVAs `3170`, `3300`, `36c0`, `2ca0` and `9350`.
The selected field decoder is not the canonical full ADS DDR provider. Leaf49's
`capture_ads_ddr_report()` already implements the distinct complete18 acquisition,
decode, transforms and selected command-report fields;92 exposes it as
`selected_ads_ddr_report()`. Its actual saved TSE fixtures for1009/100a/1027 are
retained in `analysis/evidence/no-car-49/selected-producer-fixtures/manifest.json`.
Those include original typed64-bit fields and selected metadata. Leaf105 reuses
that existing provider rather than replacing its error/merge/format semantics
with the stricter selected-field helper above. The remaining sample invalidity
presentation review belongs to the saved-view consumers;12 ADS is unsupported.

## Generic original12/18 P4 image

`capture_image_p4_saved()` implements the `GetImageFFD_DT.dll` producer over
concrete communication, packet logging and the native RAM EndTrim reader. The
outer source sequence is Start1, invalidate A8 kind1, NoBuffer0/settings1,
information acquisition, E5/E6 security, EndTrim and Stop. Both originals retain
the connection; this producer does not add a Disconnect call.

Information acquisition hydrates ALL DB200 names before filtering selectors
2a..33. Each current row's WORD4 selects DB201, preserving duplicate-selector
association. Native requires ten rows, not ten distinct selectors. The producer
acquires raw support and the P4 enabled list before looking up DB20A. It evaluates
every support row before testing whether any information is unsupported. It then
reads the ten raw DWORD fields through selected function6b and validates image
flags2a/2b. Native PID byte expansion is applied before field extraction.

The security input is a private six-byte schedule read statically from authenticated
BYOD producer bytes. No schedule is embedded in authored code. E5 returns six
seed bytes; a zero seed skips E6. The sequential rotate/add key uses earlier output
bytes when the selected index precedes the current index. The unsafe native
seven-byte seed reply is rejected with A0040202.

RAM parameters preserve last-matching-selector and BYTE-truncation semantics.
The exact uncached EndTrim reader uses block size38, including its final short
request and FF-fill on post-I/O failures. Each raw record remains owned by the
typed result. Category178 projects bytes4:6 when trailer>=6; other categories
project bytes0:2 when trailer>=2. Short trailers produce FFFF. Host byte/address
bounds and cancellation remain explicit.

Ten actual J2534 replay branches cover original12/18 positive, failed RAM,
malformed RAM, cancellation and blocked logging paths. They exercise selected resources, support
stream, enable bitmap, ten ECU reads, security, EndTrim and real closed log files.
The retained channel is explicitly verified. Separate vectors cover nonzero E6
keys, selected duplicate groups and native support-error ordering. Ten additional
actual CommandAPI BB wire branches verify first-scalar projection, append,
native-fault retention,12 preserved extra fields and18 three reset DWORDs.
The JSON adapter excludes raw/security data and log paths. Four ASCII/P5-filename
mutations fail before transport or log I/O. Independent review remains open. P5 image is a
different selected filename and is not dispatched through this P4 producer.

## PCS operation acquisition

The source-bound `capture_pcs_operation_phase()` retains native DB256 order,
duplicates and BYTE-count truncation. Phase1 filters using membership in the
actual PCS enabled list and projects the native E1 reply scalar for freeze
numbers0d/0e/0f. Phase2 starts at number|f0 and decrements10; phase3 starts at
number|10 and increments10. Selected counts bound PID rows and repetitions.
Two consecutive receive failures end only the current repetition; successes and
the next repetition reset that condition. Later support expansion errors remain
fatal. Raw replies and expanded bytes remain in the typed result.

`capture_pcs_item()` uses the distinct PCS kind3 function0e support pipeline and
selected function11 data read. It does not alias the ordinary operation functione4.
Actual authored12/18 DDB tests consume52 `pcs_operation_pids(kind=1|3)`, its raw13
stream, native0f/0e requests and canonical DB256 rows before invoking the phase
and item consumers. These consumers only test enabled-PID membership, so they do
not discard ordering or multiplicity needed by another native list consumer.
`capture_pcs_saved_operations()` implements the complete12/18 outer: Start0,
invalidate A8 kind1, NoBuffer0/settings1, category-selected support predicate,
SignalGroup25→SignalCheck→Freeze→ALL operation numbers, ordinary freeze scalar,
versioned PatDisp match, phase1 append and phase2/3 count items. DB226 selectors
0a/0b choose repetitions;0c chooses the PID count. Native12 compares PatDisp WORD10
with the low WORD of the acquired scalar;18 compares DWORD4. Each canonical
resource query preserves native hydration and error ordering. The native partial
freeze is retained if a later counter/read fails. Logging stops independently;
the source retains its connection. Six actual lower-wire branches cover both
versions' positive, partial fault and cancellation paths. Six additional public
BA-selected92 calls verify append and retention of prior facade rows on a fault
after native partial output. Four ASCII/P5-filename mutations fail before I/O.
The saved JSON consumer excludes raw phases, matched values and log paths.
Independent review remains open.

## Remaining P5 image work

Common18 generic-image availability, SecLv49 security and all four formats of
specification/customization/information acquisition are implemented as typed
stages. Selected function66 supplies the actual communication metadata. Private
schedule bytes come only from authenticated BYOD Common18 bytes. Native explicit
security masks are checked; availability/customization follow the original
Ext helper's positive-service check without inventing a DID echo requirement.
Raw replies and their native header sizes, record lengths, addresses and counts
remain owned by `ImageP5Information`.

The generic18 bulk-record stage also acquires the real header and every255-byte
body chunk, preserving checksum, supported record types, signed DWORD DDR-header
filtering and the native NRC21/23 continuation/retry flags. It retains failed
primitive replies when the lower layer supplies them. Body reply lengths are
not tightened beyond the native positive-service check.

Original12 generic P5 uses the same verified seed/key wire exchange but its
own BYOD schedule (producer RVA1236C), five availability flags and format1-only
information parser. All seven record lengths must strictly exceed the header.
Original12 returns every failed body read, including NRC21/23; original18
continues only NRC21/23. Fatal body results retain the header scalar and native
status so the outer can preserve the original partial output.
Its bulk filter requires both DDR support values: equal scalar values compare
the second value and timestamp after masking to29 bits; other scalar values use
signed DWORD subtraction. Original18 does not consume that timestamp argument.

RC18 information acquisition now follows spec221103(format2), availability221126
(format1,two flags), security and encryption222031. TSS3 separately validates
all format5/7 spec fields, ten/eleven availability flags, security and encryption
222081. These typed stages preserve native failure precedence and explicit
version-specific bounds. Their indexed block business producers remain open.

Legacy PVM18 information acquisition follows security→seven availability flags→
format1 spec→customization2032/2033→information1102. The separate21CY stage uses two flags, a4-byte unvalidated first spec,
second1128 spec with two zero bytes and2031 encryption-method read. ADS18 follows five availability flags→canonical49 AES security→
spec1C07→information1C06. Both preserve exact DWORD-group/count associations;
no unverified record-type meanings are assigned to the copied groups.

The generic18 outer now executes through concrete communication, internal49
DDR and packet-log owners. The normal inner uses its literal support-only path
(no B1 data/RAM/catalog); the P5 inner acquires the full report and disconnects
only the shared controller so image acquisition continues. Final-catalog native
failures retain typed partial supports for the image filter. Per-record and
whole-image rewinds truncate the actual file; one retry keeps already appended
header scalars. Native image failure retains caller output in the92 facade.

The actual selected BB WCHAR route is checked through92→105→77/43→49 with
seven direct and seven public positive/fault/retry/empty/cancel branches, three
pre-I/O source guards, and four canonical BC/1BC support vectors. The observed
P5 first-support value3 reaches public fields(1,1,3); normal spec2 correctly
disables159..171 and yields(1,0,0). Source-corrected normal chronology explicitly
rejects B1/RAM overcalling. Independent full-provider review remains open.

ADS18 record-phase log retention now follows the source membership polarity:
regular records accepted by the first-DDR counter populate the per-group parent
set; linked extended records keep their raw send/receive bytes, while zero,
orphan and counter-excluded-parent records roll back to the preceding packet
offset. Extended rows add no freeze scalar. Three focused actual43/77/49
controls check these bytes and the existing suppressed-error rollback path.
The complete ADS image producer and saved outer remain incomplete. Original12
generic outer still requires its exact internal normal path. PVM, RC and TSS3
indexed image producers and saved outers remain incomplete. `ImageP5Request18` preserves caller BYTE numbers, selector and the two
native ECU-reference fields consumed by the DDR selector. Empty and duplicate
number lists remain visible. Original12 uses separate inline helpers and reads
all memorized images; original18 requires a caller snapshot-number list, filters
it against availability and consumes a separate format selector. The12 flow is
not replaced by18's nonempty-list guard.

## Evidence and checks

The private inventory covers four original12 and eleven original18 producer
images. Fourteen newly retained Execute/direct-callee closures contain 1053
source/body-hash-verified functions; ADS DDR and Common18 closures reuse the
separately retained leaf49 sources. Additional constructor-referenced virtual
methods and the six scoped PCS Common roots have now been recovered: fourteen
additional closures contain 906 body-hash-verified functions, with independent
mutation controls. The JVM slot was released. OEM code,
bulk resource text and keys stay private.

Run `python -m unittest discover -s tests -p test_toyota_saved_ffd.py -v`.
The checks include authored DDB selection and hydrated ADS conditions, exact
TSS3/LCS chronology, native parsing/filter/error branches, cancellation/deadline/source
checks and an actual43→77→105→49 chain over typed J2534 replay primitives that
writes and closes `TSS3OperationFFD.log` plus `LCSOperationFFD.log` for both12/18.
The original12 replay also exercises the native connection drain. Both TSS3 and
LCS lower cancellation tests combine a real receive interruption with a host
disconnect failure and verify the original exception and closed packet file. A blocked log directory proves that
business acquisition still runs and that the logging error reaches the result.
Ruff and Pyright are required for changes to these files.

Remaining complete consumer closures: ADS image, generic P5 image,
PVM image, RC image and TSS3 image. TSS3/LCS/ADS first-scalar facade routes are
exercised by actual selected DB113 EA/D0/E0→92→105→77/43→49 replay,
including append and fault retention. DB113 names use native UTF-16LE WCHAR40;
ANSI/ASCII mutations are rejected before transport or logging I/O;
logical metadata fields are asserted through the actual routes. Independent
source review remains open.
Physical ECU/adapter behavior is `PHYSICAL_UNCONFIRMED`.
