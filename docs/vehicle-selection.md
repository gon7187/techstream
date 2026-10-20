# Offline vehicle and ECU selection

`VehicleCatalog(region_directory)` reads `Toyota.ddb`, its language database and
original ECU resources through the bounded database parser. It never opens a
vehicle transport. All original names and associations come from database keys.
The demonstration databases contain authored synthetic vehicles, not a copy of
Toyota definitions.

```python
from pathlib import Path
from scripts.profiles import VehicleCatalog

catalog = VehicleCatalog(Path("runtime/demo/Techstream_DB_NA"))
rows = catalog.selectable_vehicles()
selection = catalog.resolve_vehicle(rows[0]["row"])
# If status == "needs_option", display choices and append the chosen key3.
selection = catalog.resolve_vehicle(rows[0]["row"], answers=(1,))
systems = catalog.vehicle_systems(selection["vehicle_name_key"])
profile = catalog.build_profile(
    systems[0]["category"], vehicle_name_key=selection["vehicle_name_key"]
)
frames = profile.command_frames(0x10)
```

Choose a row using its `categories` and `category_keys`; the category labels come
from CategoryMaster and VehicleCollectItem. The native regions expose different
category sets. Do not assume every region uses brand/model/year/engine. Option
answers are integer `key3` values in the returned choices, not displayed labels.
Missing, ambiguous, extra or cyclic answers fail explicitly. `selectable_vehicles`
applies the native VehicleSet registration filter; pass the actual caller's
`registered_sets` to the constructor when available.

`vehicle_systems` follows VehicleName → EcuGroup (type 1) → InstallingEcuList →
EcuCategory. Selecting an ECU resource explicitly does not establish its physical
presence. `build_profile` can also load a category directly for offline inspection.
The optional vehicle key validates the registration policy and category association
before recording selection provenance.

`frame_records(function_id)` preserves the selected function, communication and
settings records and database hash provenance. `command_frames(function_id)`
returns bounded `CommandFrame` objects. `records(slot)` returns ECU rows with the
selected exception overlays. `pid_bits()` resolves PidBit variable identifiers
from the management variable table. Numeric conversion, snapshot and session
consumers share the same MSB extraction helper, including native unsigned wrap
and the narrow cross-byte x86 truncation behavior.

`signal_checks(signal_id)` selects the first native SignalGroup row by its byte
key and resolves its SignalCheck group. `signal_pids(signal_id)` preserves
PID IDs in selected source order, including duplicates. `dtc_signal_checks(code)` adds the original
DTCGroupRetrieve first-row join. Missing resources and empty key groups return
distinct native errors. `dtc_freeze_records(code)` selects the first Freeze row
for each check PID across the native byte-selector wildcard, retaining duplicate
check rows and their order. Each `SelectedSignal` includes the source check,
Freeze, optional selected physical metadata and database-hash provenance. A
missing physical row remains `None`; it is never interpreted as supported.

`protocol_info(observed_bus_id)` resolves the first selected ProtInfo record for
the profile category and observed bus. Its native comparison keeps the full bus
key: `0x107` does not match stored byte `7`. Version 12 records are 24 bytes with
the bus at +22; version 18 uses 28 bytes and +24. The selected raw record carries
the native driver selectors at +6/+8.

`multi_pid_records(parent_pid)` resolves selected MultiPID links (slot26),
preserving their native child order and flags. `active_comm_mode(active_record)`
resolves the optional PSA slot60 record using the ActTest signal ID at +56; its
byte +2 supplies the SID override. Native PSA explicitly tolerates an absent
table or empty group, which return `None`; malformed tables still fail.

`comm_pid_records(logical_id)` and `comm_rid_records(logical_id)` resolve the
management DB136/DB158 descriptor groups by WORD +16, retaining target-ECU and
support fields for the consuming operation. These keys are logical descriptor
IDs, not ECU category IDs. Selection does not assert support. CommPid records
are 44 bytes in versions 12 and 18. The recovered 36-byte CommRid table belongs
to version 18; version 12 has neither the exported CommRid interface nor a
slot88 resource in the original regional catalogs, so that layout is rejected.
`comm_did_records(logical_id)` resolves DB13E using WORD +0, retaining its
24-byte target rows in versions 12 and 18. Its key layout differs from the
CommPid/CommRid layout; the helpers do not interchange these descriptors.
`signal_lsb_records(pid)` resolves optional DB227 (slot39), a 20-byte selected
table keyed by WORD +8 in both versions. The native caller treats an absent
resource or empty key as no override; both return an empty tuple. Malformed
records still fail. The consuming monitor applies observed support and reply
checks before changing coefficients.
`signal_did_lsb_records(pid)` performs the parallel optional DB240 lookup by
WORD +10, preserving its DID at +8 and selected 20-byte rows.
`ecu_function_details(function_id)` selects management DB11B by category/function
and retains every detail WORD +8. `timer_records(timer_id)` selects management
DB119 by category/timer and retains its raw DWORD +0 value. Both apply selected
exception overlays. Absent resources and present empty groups remain distinct;
the consuming operation decides its first-row/count and timing behavior.
`records(2)` exposes selected SupFreeze rows: each is four bytes with the frame
number at +2. `records(55)` exposes eight-byte PidAdditionFrame rows keyed by
PID byte +4, with frame reference WORD +0.

`carb_mode_info(bus, p5=False)` implements the recovered version 18 base-cache
alternate context with ProtInfo WORD +8; `p5=True` selects the distinct P5
producer using WORD +20. Both apply CARBInfo exception overlays and preserve
missing-table versus empty-group errors. Version12 producer behavior is not
inferred from the version 18 implementation. `default_diagnostic_mode` retains
its own WORD +20 predicate and also applies the selected CARBInfo overlays.

## Native selection and exception contracts

`VehicleContext` exposes the native decision key without inventing meanings for
opaque scalar fields. `VehicleContext.from_native_key` imports the original
forty-byte scalar structure with separately supplied identifier buffers, never
following process pointers. `from_identification_fields` reproduces the normal
and extended EU identification buffer transforms, including the original 0x30
subprefix adjustment. `matching_vehicles` implements legacy, New, EU and NewEU
matchers, selected-field masks, scalar comparisons, native EU suffix trimming and
rolling prefix precedence. `VinVehicleContext` carries category, variant and
eleven literal native attribute bytes. `VinVehicleContext.from_vin` copies the
first eleven bytes of the original seventeen-byte VIN as the native caller does;
`matching_vin_vehicles` and
`resolve_vin_vehicle` support the VIN decision table and its option tree. This
interface preserves those bytes without case conversion or vehicle-name guesses.
The optional VIN `collect_key` applies the caller's collection-key filter.

`ExceptionResolver` evaluates ExceptionFindId predicates and ordered process
records. Conditional processes require caller-supplied support/frame evaluators;
default processes additionally expose protocol-context probes.
`default_diagnostic_mode` constructs their alternate context from ProtInfo,
CARBInfo, CARBPhyAddr and selected EcuCategory records. `evaluate_default_probe`
implements native support flags and saves/restores diagnostic context even when
a support probe fails; callers supply mode storage and actual observations. The result IDs
feed `build_profile(..., exception_ids=...)` and `vehicle_systems`.
`correspondence_rows` retains native sorted default rows and ordered replacement,
insertion and deletion, including first-matching-row-only deletion behavior.

`check_pid_support` accepts selected Freeze/PidBit/frame definitions, observed
PID/DID length maps and an injected `exchange(request) -> reply`. It resolves all
three PidBit selectors, request patches, response prefixes and support fields.
Native timeout codes `0x91010009` and `0x90020323` return false; other errors
propagate. It opens no device and owns no timeout or cancellation policy.

`protocol_candidates` joins ordered ProtJudge entries to selected category
protocol fields. `protocol_resume_index` resumes after the current candidate.
`check_protocol_cache` implements native cache/probe ordering and records failed
probes through injected providers. `lookup_connection_cache` evaluates decoded
native connection records against the selected request and mask/check. Empty
request templates use their stored support result. A cache hit preserves the
original routine's rolling protocol variable, initially zero; it does not infer
protocol from the candidate. `resolve_protocol_vehicle` feeds an observed
protocol selection and seventeen VIN bytes into VIN/options selection; ambiguous
matches return `needs_vehicle` for an explicit definition choice.

## Active-test support providers

Selected records expose ActTest (slot11), Pattern (12), MultiDid (33),
DataMonitorP5 (62), DataIdForAct (67), ActTestP5 (68), DataIdBitForAct (69),
DataIdPanelSupport (70), RoutineActTestP5 (71), RoutineStatus (72),
PatDispVariable (73), and DataIdBitForRAct (142). Table absence and a present
empty key group remain distinct; consumers decide which native calls tolerate
an absent optional resource.

`check_active_support` evaluates the P3/DK command gate.
`check_active_support_p4` evaluates the separate P4 support-cache bit gate using
`check_bits(pid, start, end)`. `check_did_bit_support` preserves the OldBody versus
ordinary bit-check membership distinction. `check_panel_support` evaluates the
selected panel comparison against injected function0xCA replies.

`check_p5_active_support` accepts already selected DataIdForAct rows, observed
enabled DIDs, and per-ECU signal-support/DID-length caches. It preserves native
function0xCA request patching, byte scanning, function0xC9 extra-bit checks,
and the protocol21 missing-length WORD underflow. The record mode is applied
after raw cache reads/writes. `check_routine_support` uses observed RID membership;
`check_subaru_routine_support` instead resolves the routine's extra DID-bit
reference and observed enabled DIDs. `check_subaru_active_support` uses its
extra bit reference directly, without an enabled-DID membership gate. Each routine family requires a separate
cache. These helpers never synthesize an enabled PID, DID, RID, or positive
transport reply.

## Evidence and boundaries

Static instruction anchors in KgpDataCtrl/CommandCommon include:

- Correspondence indexing: `0x1004cb27`, `0x1004ccb7`, `0x1005b3c6`.
- Vehicle matchers: `0x100514c4`, `0x10051f60`, `0x10052c7c`, `0x1005371e`;
  VIN matcher: `0x10055693`; EU suffix trim: `0x100544a9`.
- Installing ECU join: `0x100169e0`; function/frame/settings: `0x1005e120`.
  Native settings are taken from the first selected function row for every frame.
- Pid support: `0x1005e660`, `0x1005f100`; bit extraction: `0x1009bf8a`.
- Registration filter: `0x100751b0`, `0x100752e0`, `0x10075510`.

Original v18 corpus validation covers all three regional catalogs and 1,422 DDB
files. Reachable normal vehicle option trees contain no cycle, dangling branch,
missing terminal name or protocol-fallback terminal. This is a corpus property,
not permission to invent fallback behavior in other databases.

Native decision keys and supported identification buffers are imported literally.
The general option API rejects a terminal with neither a vehicle key nor a next
group. The original registration traversal also fails on such a zero-group
branch; none is reachable in the original normal catalogs. The separate native
protocol-cache fallback is available through the methods above, with observed
cache/probe/VIN data supplied by the caller. It never fabricates a positive
connection or VIN. Runtime context storage and transport observation providers
must be connected by the application before live automatic selection. The original vehicle transport, registration
state and ECU observations remain external inputs. Every physical result remains
`PHYSICAL_UNCONFIRMED` until checked on a vehicle.

DDR resource banks use `profile.ddr_records(slot, *keys)` after selected ECU
context. Monitor and InvalidCondition accept one key; Address and Trigger accept
two, following native contiguous group lookup. Version12 Trigger rows are 32 bytes;
version 18 rows are 36 bytes. Unsupported old-version bank aliases fail explicitly.
`comm_info_can_records(key)` reads plain management DB10E rows of 28 bytes and
returns the first contiguous WORD8 group without exception overlays.

`comm_info_iso_records(key)` applies the same plain-table group lookup to DB10F,
using its native 56-byte rows and WORD4 key. Selected ECU DB226/slot38 and dynamic
DID DB251/slot81 records are available through `records(38)` and `records(81)`.
Both layouts are proven independently for versions 12 and 18.

P5 DDR Header/Case and Behavior resource classes are explicitly limited to the
recovered version 18 factory. Their registered table IDs remain distinct; selecting
one does not imply support for a different DDR specification or wire producer.
`custom_sign_records(kind)` and `custom_item_records(key)` expose native management
DB114/DB115 groups after exception overlays. The custom-sign flag offset differs
between versions 12 and 18; the parser applies the matching layout.

`data_id_bit_records(reference)` selects DB23F support-bit definitions and
`data_id_bit_variable(row)` resolves the selected row's native variable reference.
The caller receives the exact raw layout: 12 bytes for version 12 and 16 for
version 18. The accessor does not reinterpret version 12 selector fields as the
newer layout. Selected diagnostic-code DB205 defaults retain their original
order, including deliberately unsorted original tables.

`communication_support_records(reference)` selects management DB130 by its
support reference, rather than the target ECU field. `communication_settings(id)`
implements the exact-one DB11D lookup used by native SetCommSet.
`direct_frame(frame_id, settings_id)` follows the NoBuffer metadata order: query
DB111 and resolve every send/mask/check reference in its first contiguous group,
then require exactly one selected settings row. `behavior_frame` follows the
separate behavior-code path: accept the first settings row from a nonempty group,
then resolve DB111. Function-based `frame_records` retains its settings-first order
and rejects an empty first send frame. These methods retain raw records and
provenance; they perform no transport operation.

`dll_records(command_id)` implements DB113's explicit native fallback: prefer the
selected ECU category; if that group is empty, return the first selected row for
the command. An absent command remains empty. This lookup describes the selected
native operation and does not certify that the corresponding operation is ported.

`function_frame(function_id)` follows the separate native function-only lookup:
the first selected DB112 row and its DB111 frame, without requiring settings.
`validate_frame(selected)` reconstructs the corresponding producer from the
current profile and checks raw records, decoded bytes and source context. Cache
and transport consumers must call it before accepting a selected frame; copying
a provenance string does not make a frame from another resource valid.

`ecu_function_info(function_id)` selects DB11A by category and function, whose
query field differs from its overlay ordering field. `mode_wwh()` applies the
native function `0x27` presence check, returning false on native query errors.
`dtc_status_records(type)` retains the complete unsigned diagnostic-type key and
raw mask/expected bytes. `ffd_bit_records(reference)` and `ffd_bit_variable(row)`
use DB250's separate freeze-frame bit definitions and eagerly validate every
selected variable reference before returning a row.

`pid_bit_records(reference)` and `pid_bit_variable(row)` expose DB208's first
contiguous selected group with eager variable validation. The separate
`communication_settings_first(id)` accepts the first row of a nonempty settings
group, as packet-cache initialization requires; it does not apply timer defaults
or change the exact-one contract of `communication_settings`.

`work_factor_records(slot, *keys)` uses the native staged contiguous lookup for
Pattern37, P5 Signal114, RoBItem115, Operation116 and Network117. Pattern37 is available in
both recovered versions. The four P5 tables are registered only in version18;
version12 selection fails explicitly, including when an authored table happens
to have compatible bytes. Raw selected records and exception overlays are retained.

For native vehicle-context producers, `catalog.collect_item_records(level, value)`
and `catalog.vehicle_brand_records(vehicle_name_key)` retain the plain DB12E/143
groups and duplicate counts. Their names come from DWORD0 in the selected
management language table. `catalog.ecu_group_records(selection_key, kind,
exception_ids=())` applies DB105 overlays and staged WORD4/BYTE11 lookup. Its
selection key is the explicit shared vehicle context, not the ECU category. The
caller owns native shared-state updates and the response-list chronology.

DKISO `records(20)` uses the recovered FreezePid layout in both versions:
eight-byte rows, unsigned BYTE4 key, WORD0 exception and BYTE6 overlay flag. The
supplied original regional ECU databases contain no slot20 payloads; native
geometry and authored selected-wrapper checks establish this implementation,
without claiming original row coverage.

WorkFactor query accessors also apply native eager text resolution to every
selected row, including secondary labels. An invalid string-directory reference
returns `A0030102` before consumer count or display processing. Raw `records`
access remains a metadata operation; it does not perform these query projections.

`rob_data_id_records(reference)` selects DB25A/slot90's native WORD2 group. Both
versions use eight-byte rows and WORD0 exceptions, but the overlay flag is BYTE5
in version12 and BYTE7 in version18. The accessor retains the original fields.
RoB Item115 uses the version18 WorkFactor query path with WORD4/BYTE18 keys and
eager DWORD0 name resolution. No saved-history association is inferred here.

`rob_bit_records(reference)` / `rob_bit_variable(row)` query DB259 in both recovered
builds, preserving the first contiguous WORD0 group and eagerly validating every
selected WORD2 variable. `ddr_behavior_records(record_id=None)` queries DB286
(all selected records or a WORD36 group), including every DWORD24 label.
`ddr_behavior_code_records(behavior, first=None, second=None)` queries DB285:
WORD-only lookup stops after its first group; the full WORD32/BYTE40/BYTE41
structure scans the entire selected index. Its native three-label setter overwrites
the first two statuses, so only the DWORD16 label controls query failure. These
DB285/286 producers require the recovered version 18 factory. They provide
metadata to the ADS workflow; they do not certify that workflow or physical I/O.

`work_factor_signal_records(reference=None)` (DB223) and
`work_factor_item_records(reference=None)` (DB224) expose all selected rows or
the first native WORD-key group in both recovered builds. Signal names use
DWORD0; Item resolves DWORD12 then DWORD16, with only the second status checked.
Pattern37 and Operation116 likewise retain the native second-label status
precedence. A failed earlier lookup can leave a null label for its later getter;
query success does not guarantee that every label pointer is available.

`freeze_records(pid=0x100, logical_pid=None)` hydrates all selected DB20A
DWORD48 names. A selector above 255 takes the native wildcard branch and scans
all rows matching WORD56; a byte selector uses the normal first-contiguous-group
lookup. `operation_freeze_records()` returns all selected DB236 rows; passing
a selector retains its BYTE7 lookup. `pcs_operation_pid_records(selector)` reads
plain DB256 four-byte records by their first contiguous BYTE3 group, retaining
the PID in BYTE2. No correspondence overlay is applied to this plain table.

`comm_ecu_records(selector)` queries DB226 by WORD0 in the selected ECU database.
`pattern_records(reference)` queries DB20E by the versioned family key: WORD4
in the 20-byte version12 row, WORD12 in the 24-byte version18 row. Every selected
DWORD0 label is resolved before returning any row. Rows remain in their original
version layout: the PCS consumer compares signed WORD10 in version12 and DWORD4
in version18. The query API does not normalize these fields.

`catalog.build_protocol_profile(category, exception_ids=())` binds a
`ProtocolProfile` from the first selected management DB110 category row. Native
ChangeCommIF accepts a positive row count, including categories with an empty
ECU filename. This context resolves real management protocol/communication
records and validates selected frames; it has no `database` or ECU `records`.
Its `ecu_database_sha256` is explicitly `None`. A bound `VehicleProfile` inherits
the same management producers and supplies its actual ECU database hash.

The factory preserves native category-label hydration: it resolves DWORD60
for every selected category row and returns the last lookup status, matching
the original setter. Empty filename does not authorize an invented ECU resource.
Final ECU data acquisition still requires `build_profile` and an actual ECU file.
Original EU categories491 in both recovered builds resolve bus0x21 and eighteen
management function groups (twenty-three frames each) without opening an ECU file.
These static checks do not replace automatic-selector lifecycle, cancellation,
or communication fault verification in their workflow consumers.

`pid_records(pid)` performs native DB206 FindDbItem1 on BYTE2, retaining its
first contiguous group. The incoming DWORD key is compared without byte
truncation. The native SHORT limit applies to the filtered group passed to
ResRecords.SetData, not to the total selected table index: 32,768 total rows
with 128 rows for each PID can be queried, while a single 32,768-row PID group
fails with `A0030110`. Native PID string and variable setters are no-ops. The
support caller retains responsibility for issuing this query after its bitmap
step, in the original per-candidate chronology.

`raw_matching_vehicles(context)` exposes the native DB129 match and EU prefix
score replacement before registration or option traversal. The existing
`matching_vehicles` retains catalog policy. Manual commands can therefore apply
their own source-bound non-display transition after the actual raw query.
`category_master_records()` returns native DB12F ALL rows (eight bytes, level
WORD4 and information ID WORD6). It eagerly validates every DWORD0 label,
matching SetRecString; GetCategoryName later reads the cached pointer rather
than performing a deferred language lookup.
