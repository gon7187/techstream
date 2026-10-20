# CommandAPI composition

`scripts.command_api` provides owned, typed results and explicit joins to the
native Python domain engines. Importing it opens no adapter, vehicle, DLL, or
network connection. It neither loads Windows code nor emulates x86 ordinals.

```python
from scripts.command_api import CommandAPI, CommandSource, CommandStatus, VinReply

# Identify the user's local original file without loading it.
source = CommandSource.from_file(command_api_path, version=18)
api = CommandAPI(source, cancelled=cancelled)
result = api.compose_vin(VinReply(CommandStatus(), 4, b"ABC"))
assert result.return_code == 0 and result.value == b"ABC"
```

`CommandSource` accepts only the separately audited original12 and18 identities.
The constructor validates the supplied identity; `from_file` actually hashes the
file. A caller-supplied identity is not proof that corresponding OEM bytes were
read. No2026 or cross-version fallback is inferred.

## Recovered result transformations

* `compose_vin(VinReply, previous=bytes) -> VinResult`: original12 RVA `0x92fa0`
  and original18 RVA `0xb4100`. Receive status selects the returned detail error,
  preserving the previous result on that branch. Success uses the unsigned
  16-bit reported length minus one; zero/one length clears the result.
  The CString copy retains bytes through its first NUL; only the first length-1
  bytes are checked for ASCII digits and letters. A later suffix remains
  unvalidated, including punctuation, as in the original. An invalid checked byte
  clears the result with native return code zero. No17-character policy or VIN
  checksum is added. Results own immutable bytes and remain valid after subsequent calls.
* `compose_vim_support(CommandStatus, support, previous=byte)`: original18 RVA
  `0xb3e60`. Success copies the low byte; errors return detail and retain the
  previous byte. Original12 has no reconciled matching route and fails explicitly.
* `compose_vim_information(CommandStatus, VimInformation, previous=...)`:
  original12 RVA `0x92ca0` and18 RVA `0xb3b60`. Six received unsigned16 values populate API offsets
  `+04,+06,+08,+0a,+0c,+10`; the last two occupy widened32-bit slots. Their domain
  names have not been guessed. Error preserves the previous owned information.

* `compose_active_list(...) -> ActiveFacadeResult`: original12 RVA `0x12420` and18 RVA `0x14420`.
  It copies the16-byte logical item fields, independently filters entry and
  group-member IDs in8000..9999 and40000..41999 unless caller mode equals1,
  skips NULL received entries, retains empty groups and original order, and preserves the previous lists and
  description on native error. Names remain owned byte strings; no ACP encoding
  is guessed. Host materialization has an explicit100000-item safety cap.

* `compose_translation(...) -> TranslationFacadeResult`: original12 RVA `0x8f8d0` and18 RVA
  `0xae620`. Success appends8-byte logical items to prior output; it does not
  clear the array. Each item owns the CString bytes and a received unsigned16
  attribute. Duplicates and order are retained. Native errors retain prior
  entries. No ANSI/code-page conversion is guessed.

`CommandStatus` deliberately preserves native status separately from returned
error: a nonzero status with zero detail retains output and returns zero, as the
original branch does. It is not rewritten into a made-up error code.

Host validation rejects truncated pointer extents, embedded NULs crossed by a
VIN's claimed length, unsupported source identities and values outside native
ranges. Native C++ may read outside its CString for malformed inconsistent VIN
lengths; this host failure is a bounded policy, not claimed native equivalence.

## Concrete domain joins

These execute concrete engines rather than operation-name callbacks. Most joins
still preserve domain results rather than closing the entire original plain-export
contract. The `get_analyze_work_factor_*` methods additionally apply their
individually recovered source-specific result transformations.

| Method | Concrete engine and result |
| --- | --- |
| `get_pcs_operation_ffd` | Original12/18 selectedBA generic P4 PCS producer/logging and first-scalar/reset-row facade; selected P5 remains separate |
| `get_image_ffd` / `get_image_ffd_p5` | Original12/18 generic P4 and separate P5 selectedBB producers, scalar/reset-row facade and18 support fields |
| `get_analyze_work_factor` | Original12/18 selected6F P3/P4 normal+Adjust+TS/phase4 PSC providers; separate ordinary/TS result families |
| `get_ads_image_ffd` / `get_rc_image_ffd` | Original18 selectedE1/EB image producers; entry clear, first-scalar rows and separate support-field projection |
| `get_diag_code_p5` / `get_diag_code_p5_12` | Separate original18/12 selectedAC fullP5 domain producers and owned0x4b4/0x228 DTC/FFD facade rows;18 explicit log14 attachment lifecycle |
| `get_vin` | Original12/18 command51 selected module dispatch,8b/86 wire chronology and typed native VIN facade |
| `selected_can_vin` | `ToyotaSession.vin_multi`: selected count/data descriptors, receive-only continuation, then typed VIN composition |
| `selected_active_tests` | `ActiveTestCatalog.list`: typed selected tests with support probes |
| `selected_active_initialization` | `ActiveTestCatalog.initialize`: typed `ActiveTestInitialization` with support and initial-value probes |
| `selected_active_run` | `ActiveReplay.run_test`: recorded Init/start/status/stop chronology and guaranteed provider cleanup |
| `selected_clear_dtc` | `ToyotaWorkflows.clear_dtc`: actual selected late workflow and its report |
| `selected_monitor` | `run_monitor_commands`: actual DMCI setup/start/read/stop, raw `MonitorPacket` tuple |
| `selected_ddr_samples` | `capture_ddr_record_samples`: actual selected RAM reads and `DdrRecordSamples` or native skipped record `None` |
| `get_analyze_work_factor_dcm` | Selected78 P4 original12/18 and DCM24 original18 fixed/current/variable acquisition, followed by flat/rich/current field transformation |
| `selected_dcm_p5_analysis` | `DcmP5Analysis.run`: raw typed business acquisition |
| `get_analyze_work_factor_dcm_p5` | Selected D7 provider acquisition followed by recovered original18 facade result composition |
| `get_analyze_work_factor_rob` | Selected D6 provider CA/F3/F4/F5 acquisition followed by original18 RoB facade result composition |
| `selected_ddr_report` / `selected_ddr_p5_report` | Actual selected normal RAM / P5 DID acquisition, metadata transforms and typed command report |
| `selected_ads_ddr_report` | Actual selected ADS security, ready/behavior/history exchanges, metadata transforms and typed ADS command report |
| `selected_ddr_saved_log` / `selected_ddr_p5_saved_log` | Actual native saved packet-file lifecycles around the respective full command reports |
| `selected_translation` | `TextResources.translate`: source Unicode and full resource provenance; native ANSI bridge remains OPEN |
| `selected_recorder_group` | `NativeDrsExecutor.execute_group`: actual DRS branching over primitive backend calls |

The active, workflow and DDR joins reject mismatched source/database versions.
Each concrete provider still owns its support rules, deadlines, state, cleanup
and provenance. `close()` closes only this coordinator; it never closes an
injected engine owned by another caller. Cancellation is checked before and after
provider execution; callers must also configure provider cancellation/deadlines
for interruption inside a provider call. There is no generic operation-name
callback that can assert success without executing the engine.

## Selected original12/18 VIN route

`get_vin(communication, previous=bytes)` reads selected DB113 command`0x51`.
Both independently checked CGetVINSnd constructors supply this command ID.
DB113 stores its filename as UTF-16LE WCHAR40. Exact `GetVIN_DT.dll`,
`GetVIN_CAN_DT.dll` and `GetVinPSA_DT.dll` routes are accepted.
The ordinary variant reads exactly one selected function`0x8b` frame, takes
count from reply byte2, then executes selected function`0x86` through the shared
native multi-receive stream. It requires at least the requested count and uses
only that many replies. The CAN variant executes86 and uses only its first
reply, after the native multi-receive stream has completed. Neither route is a
hardcoded universal VIN request.

The ordinary and CAN variants strip three bytes per selected reply, then remove zero bytes only in the
first three positions of the combined payload. The result passes through the
recovered VIN facade transformation. Native faults retain the previous value;
source mismatch, unknown producer, cancellation and unsafe native scratch-buffer
extent fail explicitly. The host caps the zero-terminated scratch payload at254
bytes because the original fixed buffer is255bytes. This is a bounded host
policy for the native overflow branch. The PSA variant executes one selected function`0xea` frame, requires a payload
after its two-byte prefix, and only copies it if its first byte is nonzero. It
does not use the other variants' three-position zero filter. All three producer
pairs have independently hash-bound instruction/import-role parity checks across12
and18, with actual J2534 primitive tests for each source version. Import/startup still performs no device I/O.

## Selected work-factor application routes

`get_analyze_work_factor_dcm_p5(provider, previous=...)` executes a concrete
`DcmP5Analysis` selected by DB113 D7, then `compose_dcm35_analysis`. Native
business errors return their code and retain prior output. Host failures and
cancellation propagate. DCM time fields retain six bytes/year+2000, and the
four network labels remain gated by their native validity flag.

`get_analyze_work_factor_rob(provider, mode=1, current_flag=1, previous=...)`
executes a concrete `RoBAnalysis` selected by DB113 D6, then
`compose_rob_analysis`. Original18 `GetAnalyzeWorkFactorRoBAPI` RVA `2fb90`
copies group DWORD display ID, WORD data ID and source name. Each record copies
operation WORD, label, four 16-byte value blocks, help and help WORD. The blocks
are type2, rewritten passed time, happened time and type4, in that order.
Happened time has empty name/unit and format1 when calculated. An uncalculated
block retains constructor defaults: value0, empty labels and format`0x4000`.
The current time scalar uses the provider's adjusted ticks. Calendar output
copies SYSTEMTIME year/month/day/hour/minute/second; it omits day-of-week and
milliseconds. A nonzero receive status preserves all prior facade fields.
The RoB provider retains channel ownership; the facade does not disconnect it.

`get_analyze_work_factor_dcm(provider, mode=0, previous=...)` executes the
concrete selected command78 P4 provider, with separate original12/18 source hashes. API modes0/1/2 map to native2/1/4;
other BYTE modes map to0. Flat output replaces the prior flat list and includes
only records with at least nine items: four low BYTEs followed by five low
WORDs. Rich mode2 appends groups and their owned names/items to prior groups.
Current five WORDs are replaced only when five source values exist; validity
is zero if any source format contains `0x4000`. Other output branches retain
prior fields. Native faults retain all previous output. Original12/18 P4 variable mode4 runs the actual selected RAM producer and its
explicit `DcmLog` journal owner before rich transformation. Original18 selected
`GetAnlWkFctDcm24_DT.dll` uses its separately identified producer; its different
eligibility and RAM-failure behavior remain in that concrete producer. Native journal errors retain prior facade output; journal paths
are excluded from the public analysis report.

`analysis_report(result)` adapts the typed analysis facade results to a JSON-compatible
saved/UI document with operation name and CommandAPI source identity. It
includes only public facade fields: no received payload, selected profile path,
security key, DID raw bytes, physical definition or driver data. Unicode labels
retain source text; an ACP encoding has not been invented. The adapter performs
no filesystem write or network request. The application decides the output file.

The authored RoB integration test runs selected metadata through actual
`NativeCommunication` / `NativeFrameController` / injected J2534 byte operations,
then through the facade and JSON adapter. Faults, unchanged prior output,
source mismatch, metadata-only output, cancellation and host exception identity
are checked separately. The DDR owner's actual ADS wire fixture also consumes
`selected_ads_ddr_report`, including source/cancellation rejection before I/O.

## Selected plain P3/P4 and phase4 PSC work factor

`get_analyze_work_factor(PlainAnalysis(...), previous=None)` selects the actual
command6F P3, P4 normal/Adjust or phase4 PSC provider in12/18. `compose_plain_analysis` follows original12
RVA15750 /18 RVA23250: native success replaces groups/current/calendar and
coefficient; native failure preserves previous output. Each0x24 group owns
identifier/display-type DWORDs, PID BYTE, name and0x1c items carrying address,
opcode, content, name, raw value, unit and format. Pattern metadata is retained
as decimal text in the CPU-reset item content, matching the actual sprintf.

The P3/normal/Adjust/PSC branches never write TS groups/current. Their result explicitly includes an empty TS
list and the native timestamp constructor defaults: five DWORDs zero, three
zero scalars and three reset0x6c metadata rows with conversion core1. Both
original DataLib receiver/timestamp resets and empty GetValue(0) were checked
statically. `plain_analysis_report` emits those fields, excluding RAM captures,
definition bytes and local paths. Actual selected serialized12/18 metadata and
43/77 J2534→P3/P4-normal→public facade→JSON checks pass, with source/cancellation checks
before further I/O and prior retention on native fault. P4 also accepts the
source-defined Adjust99 branch. Separate phase4 PSC
normal/PID29 branches have actual both-build public positive/fault/cleanup
checks. Empty P4 definitions return C0040101 before current acquisition.
Independent ready54 acceptance covers P3; P4/Adjust/PSC and acquired TS remain
outside that acceptance. PSC phase3 business remains OPEN.

The acquired P4 TS4 branch has separate typed groups/items and timestamp fields.
`PlainFacadeFreezeMetadata` follows ConvertFrz06ad0's three strings, conversion
table and12-byte raw/display/status values; it does not reuse P5 label-ID fields.
Timestamp scalar3 comes from native DWORD148, rather than the third freeze's
first value. Reset/empty freezes preserve the existing constructor-default
schema, while a received zero value still produces a rendered entry. History
selector0/width0 follows native `-TypeErr-`. Actual both-build43/77 positive,
RAM fault retention, cancellation/source guards and variable-length TS checks
pass in the106 cohort; independent TS acceptance remains OPEN.

## Selected original18 P5 diagnostic facade

`get_diag_code_p5(workflow, requested_types, freeze_flags,
 native_cancel_value=..., log_control=0, packet_log=None,
 include_attachment=False, previous=None)` requires an actual
`ToyotaWorkflows.from_communication` context and selected DB113 command`0xac`
filename `GetDiagCodeP5_DT.dll`. It invokes the full domain producer, including
its normal, predictive and Subaru decisions. Authored real J2534 fixtures cover
normal CD/CE/CF acquisition through10 signals, three timestamps, odometer and
six BCD absolute components; predictive CF and copied signed-index BYTE;
Subaru26b snapshot and Subaru stored113; partial CF fault retention and log14.
Normal-stored flags4 now has real43/77 CD→D0 public-route checks in12/18,
covering FF set and nonFF reset of stored-all after the source-correct producer
and merge fix. Separate focused primitive77 cases cover new and existing DTCs.
Complete independent branch acceptance remains OPEN.

`compose_p5_diagnostics(status, state, previous=...)` applies original18
`GetDiagCodeP5API` RVA`68c20`. Success appends owned DTC rows. Native errors
preserve previous rows, except `0x90020706`: this logging error still copies the
received rows and returns zero. The rows retain diagnostic type, status, code,
three labels and IDs, snapshot lists, existence flags, stored-all state,
main signals, three timestamps, odometer and six absolute-time blocks. Main
PID8000..9999 and40000..41999 are omitted. Native block flags gate the respective
metadata/value copies; absent blocks retain their constructor defaults.

Each signal owns its full logical conversion metadata, patterns and16-byte
value items. Main selector12 reverses bytes using the selected bit width before
rendering and stores the transformed raw value. Special timestamp, odometer
and absolute-time blocks retain their raw value. The signed native time index
is exposed as its copied unsigned BYTE. Float64 rendering receives the two
literal zero extra words passed by these native call sites. Unicode source
labels stay Unicode; no host ACP is guessed. Display widths outside1..32 and
materialization above100000items are explicit bounded host failures. NonASCII
character selectors4/32 require an observed ANSI encoding; without that context
the facade raises a host error instead of guessing a Unicode character.

When `log_control==1`, a concrete original18 `DdrPacketLog` bound to the same
controller is mandatory. On ordinary success, explicit `include_attachment=True`
reads the closed `MarkMonRam_SSR.log` into an owned attachment with native ID;
failed file-open resets that attachment. On native logging error, the previous
attachment remains. The native temporary file is removed after the branch.
The adapter retains channel ownership. Attachment size is bounded at64MiB.
`p5_diagnostic_report` emits only the typed DTC/FFD rows, return code and source
identity; raw attachment bytes and local paths are excluded from JSON.
`get_diag_code_p5_12(workflow, requested_types, freeze_flags,
 native_cancel_value=..., previous=None)` is the distinct original12
RVA53b70 route. `P5FacadeDiagnostic12` owns only the logical0x228 row through
BYTE224; `P5DiagnosticFacadeResult12` has no attachment. The sender has no18
log-control field. `compose_p5_diagnostics12` appends only on native zero and
preserves prior output on every native error, including0x90020706.
`p5_diagnostic_report12` emits a separate versioned schema. Original12
ConvertData@20 preserves raw values and returns-TypeErr- for selector12 and
unsupported26+ selectors. Selector19 uses the original12 two-digit minute
format (`02:05`); original18 uses `2:05`. Shared supported numeric/pattern conversions retain
their source metadata; no18 endian pre-step is applied. Actual serialized12
DB113/management/ECU/language→43/77→full producer→0x228 rows→JSON covers normal
FFD with three timestamps/odometer and predictive CF, previous append,
transport fault retention, host exception identity, cancellation and source
mismatch. Independent complete branch and display review remains OPEN.

## Saved operation routes

`get_tss3_operation_ffd(communication, packet_log)` selects DB113 command`0xea`
and exact `GetTSS3OperationFFDP5_DT.dll` in18.
`get_lcs_operation_ffd(...)` selects command`0xd0` and
`GetLCSOperationFFDP5_DT.dll` separately in12/18.
`get_ads_operation_ffd(communication, packet_log, key)` selects command`0xe0`
and `GetADSOperationFFDP5_DT.dll` in18. Filenames use the native UTF-16LE field.
The concrete105 providers own actual connection, security, readiness, phase
acquisition, packet-log switching, disconnect and error precedence. The ADS key
is explicit BYOD input and never appears in facade output.

`compose_saved_operations(source, acquired, previous=...)` copies only the first
native scalar of each nonempty received freeze. Success appends to prior output;
native errors retain it. Group/operation IDs from acquisition are not guessed as
native SignalItem metadata. Output `SavedOperationFacadeFreeze.metadata` retains
the recovered logical0x6c row fields: five WORDs, eight DWORDs, three BYTEs,
three empty strings and the empty display-info list. `SAVED_OPERATION_*_OFFSETS`
retain their original identities. The conversion core WORD at`0x1c` remains1;
the other recovered scalar fields are zero. Native C++ pointers/vtables/padding
are represented through safe Python ownership, not a Windows memory ABI.

`saved_operation_report(source, result)` exposes those fields as a JSON-compatible
saved/UI document with source identities. It excludes keys, security exchanges,
raw replies, frame provenance and log paths. The105 authored fixture executes
actual J2534 bytes through selected12/18 metadata, full producers/logging and
these routes, including first-value projection, append and fault retention.
Malformed ASCII filenames are rejected before I/O or log-directory creation.

## Generic original12/18 image FFD route

`get_image_ffd(communication, packet_log, schedule, previous=None)` accepts only
selected DB113 command`0xbb` filename `GetImageFFD_DT.dll`. The native category
query may select `GetImageFFDP5_DT.dll`; that separate producer is rejected
before I/O. The six-byte BYOD schedule goes directly to the concrete generic
P4 producer and is never serialized.

`compose_image_p4(source, acquired, previous=...)` follows original12
RVA`68d40` and18 RVA`7f8c0`: one reset0x6c row per acquired native freeze,
its first scalar only, appended to previous rows. Native faults retain all
prior output. Original18 additionally copies three receive DWORDs, which the
generic P4 producer leaves at their constructor values zero; original12 makes
no assignment to those later fields. `ImageFacadeResult.native_fields18`
retains this version distinction. Raw RAM images, security exchanges and local
log paths are excluded from `image_ffd_report`.

The producer owns actual selected metadata/support/security/RAM and packet-log
lifecycle. Both native generic variants retain the connection; no extra
Disconnect is introduced. The P5 route below has separate source/lifecycle rules.

## Generic original12/18 P5 image FFD route

`get_image_ffd_p5(communication, packet_log, schedule,
 ImageP5Request18(numbers, selector, ecu_info), previous=None)` requires selected
BB `GetImageFFDP5_DT.dll`. Caller numbers/selector retain their BYTE fields.
Each ECU reference owns the actual DWORD native ID and BYTE state; native1BC
with state1 selects the P5 inner target, otherwise the normal BC target.
The method executes the concrete selected producer, packet-log rollback and
Disconnect1. Empty caller numbers return nativeC0040001 before acquisition.
Original12 requires `request=None`: its native API supplies only the selected
ECU ID, and the producer acquires every available snapshot. It has no18
numbers/selector input and does not copy the later three public DWORDs.

`compose_image_p5` appends only acquired nonNone header scalars, preserving
native retry duplicates. Outer native errors retain all prior public output.
Original12 success preserves the prior later-field tuple. For18, inner DDR failures are ignored by the native image business; even if they
retain support/filter provenance, the fresh receiver's three public DWORDs stay
zero. Inner success copies `(1, first_support.present, first_support.value)`;
this is first170/P5CSV110, not a recording count or the second support object.
`image_ffd_report` excludes raw headers/bodies, security, requests and log paths.

Authored real43/77 public-route fixtures cover image success, retries, checksum,
header/body faults, empty selection, cancellation and source/module guards.
Canonical retained-controller inner normal/P5 fixtures cover zero and nonzero
first support `(1,0,0)` / `(1,1,3)`. An earlier normal-inner fixture overcalled
full DDR; it is superseded by the source-correct support-only normal1F70 trace.
Independent full source acceptance remains OPEN. Original12 actual retained internal normal helper→image→public consumer
verification passes the current spec2/6/7/8 fixture matrix; independent review
remains OPEN.

## Original18 ADS image FFD route

`get_ads_image_ffd(communication, packet_log, key, AdsImageRequest18(...),
previous=None)` requires selected E1 `GetADSImageFFDP5_DT.dll`. The original
18 databases select category1DC; all three original12 databases have no E1 row.
Caller numbers and ECU references retain their native fields. The optional
caller support object maps the provided flag/present/value fields and bypasses
internal DDR acquisition. Keys stay private to the concrete acquisition.

The public API clears the existing output list and three DWORDs before command
execution. Success replaces rows; a native fault returns an empty list and
zeros. `compose_ads_image` projects only the first scalar of each nonempty
freeze into a reset0x6c row. For internal DDR, first-support presence copies
`(1,0,first_support.value)`, including retained support after an inner error.
Absent support and caller-provided bypass leave `(0,0,0)`. This source path
does not copy the generic ImageP5 support-present DWORD. The separate
`ads_image_ffd_report` excludes acquisition bytes, security and local paths.

## Generic original12/18 PCS operation route

`get_pcs_operation_ffd(communication, packet_log, previous=None)` selects native
DB113 command`0xba` and exact `GetPCSOperationFFDP4_DT.dll`. The category432
`GetOperationFrzFrmDatP5_DT.dll` route is rejected before I/O. Both names and
categories were checked in all six original12/18 NA/EU/JP management databases.

The concrete PCS producer performs its selected support/metadata/phase/logging
workflow. `compose_pcs_operations` copies only the native first scalar to one
reset0x6c row per successful freeze and appends previous rows. A native error
retains the previous facade output even when the producer acquired partial
freezes before failing. `pcs_operation_report` excludes match provenance, raw
phase data and local paths. Native12/18 provider identities remain separate;
this does not implement the selected P5 PCS producer.

## Remaining source contracts

All182 original18 plain exports (162 statically imported) and all156 original12
plain exports remain inventoried privately with exact PE hashes, RVAs and actual
constructor/destructor/dispatch imports. Static imports alone do not prove data
layout, consumer semantics or operation implementation. The individually recovered routes above do not establish complete application
coverage, native Windows memory ABI or frontend dispatch closure.

The remaining software gaps include other selection/application facades, acquired TS/PSC phase3 work-factor and original12 generic P5 image acquisition verification, normal/P5 DDR plain-export outer layout beyond the typed command report,
remaining ADS/TSS3/PVM/RC image and operation freeze-frame families,
remaining analysis source families, complete customization/behavior/CAN-bus facades and
native result-list ownership across active and monitor calls. Existing low-level
providers must not be substituted for those missing business operations. The
12/18 lanes remain separate; matching names do not establish equivalence.

Run the authored check with:

```sh
python -m unittest discover -s tests -p test_command_api.py -v
```

Physical vehicle/adapter behavior remains `PHYSICAL_UNCONFIRMED`.

Public P5, plain, saved-operation and image report DTO boundaries require exact
nested classes and immutable native extents before serialization. Derived
dataclasses cannot add private fields through `asdict`; source identity is
checked against its construction snapshot at every operation boundary.


## Original18 RC image route and paused verification

`get_rc_image_ffd(communication, packet_log, schedule, RcImageRequest18(...),
previous=None)` selects EB `GetRCImageFFDP5_DT.dll`, category138D in all three
original18 management databases; original12 has no EB entry. Independent static
checks resolve API9c600 and the same exported receiver Clearb0e20: prior rows
and the three later DWORDs clear before execution, including native faults.
The first value of the first acquired header block becomes a reset0x6c row.
Internal first-support presence copies `(1,0,value)`; provided support leaves
zeros. `rc_image_ffd_report` excludes raw blocks, security and log paths.
The concrete producer's direct wire tests pass; the newly added EB public route
awaits its final105 consumer recheck at this pause.

An earlier live original12 generic P5 image consumer check failed its expected
inner-DDR status0 assertion with `0xA0041001`. Owner105 corrected the fixture
spec metadata; the final focused local rerun passes its spec2/6/7/8 direct/public
matrix. The native outer still ignores numerical inner failures. See the exact
paused scope and hashes in `analysis/evidence/no-car-92/HANDOFF-20261021.md`.
