# Selected Toyota workflows

`scripts.toyota_workflows.ToyotaWorkflows.from_profile` binds a selected
`VehicleProfile` to injected `exchange(ecu, request)` and explicit
`WorkflowObservations`. Construction does not open an adapter. The ECU name,
native identity, observed bus and function cache belong to one selected target.
An absent cache differs from an explicitly observed empty cache.

`ToyotaWorkflows.from_communication(communication, observations=..., limits=...)`
binds the actual `NativeCommunication` runtime and retains each original selected
frame through literal request patching. It shares that runtime's concrete support
cache, checks source-build/bus identity, and charges primitive sends/receives to
the workflow budget. It requires a `VehicleProfile` with a bound ECU database;
management-only `ProtocolProfile` instances are rejected before workflow setup.
A supplied typed backend can therefore run the complete
profile → workflow → native Common → frame transport path without an adapter.
The authored test verifies the resulting CAN header and payload and channel
cleanup. Transactions lacking selected metadata fail explicitly. Raw receive-only
continuations and global address-mode switching still need their proven native
context bridges; this factory does not invent them.

Implemented methods currently cover plain, Mazda, PSA, P4 and VGRS DTC clear,
plain, DK and P4 absolute-freeze availability workflows, and legacy multi-freeze
availability, V2 multi-freeze availability, PSD availability, P4 multi-freeze
data, the P5 active-test metadata producer, and plain/ICS02 P4 operation-freeze data.
Each-freeze P5 and operation-freeze P5 also have concrete original18 export
lifecycles through the retained native controller and file logger. This
module is not yet a complete replacement for the original wrapper inventory.

Plain clear selects timer1 and function1. Mazda uses category `0x394`, function
`0xF2`, and each function row's own communication settings. Its explicit native
send-only callback receives the seven original arguments; returned statuses are
retained even though this original wrapper ignores them. A later malformed row
does not undo an earlier send.

PSA follows its observed reset feature flags and first-reply mask checks. P4
selects detail `0x57`, the exact fallback status set, and function `0x102`.
DifferentAddress and P5 FunctionAddress select different protocol fields for
their CARB physical-address join. Mode callbacks preserve get, selected mode
construction, installation, frame selection and restoration order. Forward
operations share the workflow budget; restoration has the session's separate
bounded cleanup budget and still runs after cancellation. The explicit 16-byte
mode seed supplies the reserved word the recovered native producer does not
write; the implementation does not invent its value.

VGRS reads KWP DTCs before clearing and sends function2 only when `C1555` was
observed. Plain absolute-freeze availability selects signal4 and SupFreeze rows,
reads the selected raw field for each native frame number, checks function
`0x18` reply bytes3/4, and resolves the matching original PatternDisplay label.
Missing resources, unmatched groups and native errors retain their distinct
failure paths. Timeout/unsupported-status omissions follow the original
availability wrapper rather than fabricating an available frame.

P4 availability requires exactly one signal-group/check/Freeze definition.
With no observed PID-position cache, it sends the data request first, then uses
the concrete `MonitorSupportCache` send/receive stream to discover positions.
Explicit observed positions retain the native cache-hit path. It uses the full raw value with the original
`0xFF` pattern fallback. DK uses its separate freeze primitive, status request
byte1 and reply bytes2/3; its native ordering bytes are `0xFF`, `0xFE`, then zero.
Those ordering bytes are reported without assigning an invented temporal label.

Legacy multi-freeze availability selects functions `0x71`, `0x73` and conditional
`0x72`, falling back to the exact observed function-tree entries when a frame
group is absent. It consumes the first nonzero masked response byte. The final
function6 request combines the selected high nibble with the supplied alias low
nibble. Native timeout leaves the comparison word at its explicit initial
`0xFFFF`; the report preserves that distinction from an observed DTC value.

V2 uses the concrete selected multi-info producer and descending high nibbles.
PSD uses the actual raw support stream, per-frame supported-PID bitmap and
selected active Freeze definition. `load_psd_label(path)` statically reads the
fixed native label only from a SHA256-verified supplied original12/18 module;
`WorkflowLabel.authored` marks test labels as synthetic. No module executes.

`multi_freeze_p4(signal_ids, alias, frame_filter=b'')` selects exactly one Freeze
per signal ID, builds physical/unit/pattern metadata before reading frames, and
walks ascending high nibbles. The optional filter compares full encoded frame
numbers. Individual native communication faults follow the recovered omission
set. Samples preserve raw values, native indices, resolved display and explicit
unresolved status. Matching raw category4 LSB definitions use the concrete
`SignalLSB.p4` producer over the same selected support cache. This Freeze consumer
retains its changed threshold value, unlike the separate live-monitor producer's
later overwrite. Missing metadata is an error. The shared LSB helper is undergoing
its own source and corpus verification.

`active_test_monitors()` discovers actual supported DataIds before selecting
DB23E monitor rows. Native special parents require their MultiPID children;
explicit optional children retain the original exception. Its metadata follows
the separate native2940 producer, with no live-monitor alias or PatternDisplay
substitution. Unassigned native members retain their offset names in
`native_fields`. Empty physical groups use the proven native numeric defaults;
empty unit groups retain the preceding record's unit. These cases are reported
as partial, including their native default provenance.

`operation_freeze_p4()` selects the original category366/170 SupOperationFreeze
query, signal37 probe and exact PatternDisplay match. It distinguishes fatal
probe errors from individual omitted measurements and suppressed auxiliary
errors. Kind4 PID discovery, raw support bits and functionE4 requests run through
the selected support cache. Auxiliary result flags retain native member offsets
instead of invented business labels. A helper timeout performs the original
explicit `SendInt` with a NULL request; its returned native status is ignored,
and the original timeout is preserved. Metadata follows each successful data
read. Signal41, when present, determines whether an operation is included.

`operation_freeze_ics02()` uses all five original plans, with their separate
probe/measurement groups and control bytes. It performs raw PID support checks
without substituting the plain wrapper's enabled-PID bitmap. Selected management
category rows4000..4004 provide the original output labels; they do not change
the communication target. Category469's bit18 of PID16 selects the separate
six-signal auxiliary branch. Its native field210 excludes the two explicit raw
sentinel tuples. Auxiliary short errors preserve unwritten samples explicitly.
The main ICS02 branch accepts native error `A0040202` and uses its proven
constructor-initialized raw value0, with that provenance and partial status.
The native signal35 short-error path reads an absent MultiData entry; the host
reports this unsafe native state as a failure instead of inventing a sample.

`WorkflowObservations.source_version` selects the original algorithm family;
it is not inferred from DDB format. The reconstructed late workflows select explicit source12
and source18 paths where audited. Native12 P4 clear uses the plain timer/function sequence;
ICS02 has four plans and no category469 extended branch, whereas native18 has
five plans and the extended branch. Native12 saved-log selectors/lifecycle remain
fail-closed pending reconstruction; its original DLL has no routine-ID branch.
Full owned-scope and independent acceptance remain open.

Run authored checks with:

```sh
python -m unittest tests.test_toyota_workflows -v
```

These tests verify selected metadata and literal injected wire behavior.
Physical behavior remains `PHYSICAL_UNCONFIRMED`.

`replay_workflow(profile, recording_path, cancelled=..., psd_module=None)` uses
the strict `techstream-toyota-workflow-v1` recording format. Its selected context
binds the ECU/management hashes, category row, selected exceptions, explicit ECU
label, native identity, bus, original build, host limits and function cache.
Native mode, send-only, support send/receive and ordinary PDU events share one
chronological cursor. Every supplied native argument must match, including the
selected function/communication/settings rows. PDU records also pass the shared
`NativeReplay` validation. Missing events, trailing events and native faults
produce failed reports; cancellation remains explicit. Cleanup mode restoration
consumes its own recorded event even after cancellation. No callback contacts a
device. PSD accepts an explicitly chosen local module path from the caller;
recordings cannot supply arbitrary source paths.

Reports include `status`, `error`, remaining event count, source provenance and
input paths for guarded export. Input hashes identify bytes actually loaded;
native errors are not converted into success. Authored fixtures are marked
`authored_synthetic`, captured recordings `recorded_unverified`.

To create a production demo without importing tests:

```python
from pathlib import Path
from scripts.profiles import VehicleCatalog
from scripts.toyota_workflows import create_example_files, replay_workflow

inputs = create_example_files(Path("authored-workflow"))
profile = VehicleCatalog(Path(inputs["region_root"])).build_profile(42)
report = replay_workflow(profile, Path(inputs["recording"]))
assert report["status"] == "ok"
```

The creator refuses to overwrite existing files. This authored clear-workflow
example contains one recorded PDU transaction and no device access.

`selected_absolute_pid_plan(contexts)` and
`selected_absolute_routine_plan(contexts)` resolve the original logical saved-log
components against selected management rows, target filters and actual support
queries. `contexts` maps `(category, bus)` to separately retained
`ToyotaWorkflows.from_communication(...)` instances. Their selected management
source, exceptions and original build must agree. The PID selector cache uses
native category `0xD4`, bus `0x12`; routine targets require native category type
`0x14`. Missing target contexts fail before their data requests. The selected
CommPid and CommDid functions require exactly one frame; routine CC/D7 helpers
use the first selected frame.

`absolute_pid_logs(logs, contexts=...)` and
`absolute_routine_logs(logs, contexts=...)` execute these plans. Each
`SavedLogInput(number, metadata)` snapshots bounded JSON metadata at construction;
duplicate raw log numbers retain the first entry. Reply caches are isolated by
selected target and frame, then reset for each log. Matching request bytes across
different ECU contexts never merge responses. The entire operation shares a
bounded host deadline and primitive-call budget. Routine phases select native
`NoInit` and restore both communication flags after failures. PID phases use the
native normal flags. A masked PID-selector failure still reads the components
before omitting the log. A routine wire or BCD failure omits its log. Reports
retain the omission phase/native status and mark the result partial. PID BCD
failures remain fatal, matching their separate native branch.

`execute_absolute_pid_logs` and `execute_absolute_routine_logs` add the native
original18 `StartCommLog(3)` → connection check → selected data → `Disconnect(1)`
→ conditional stop lifecycle. They retain one shared deadline/budget across the
connection and selected support/data phases. Bind a concrete `DdrPacketLog` to
the retained `NativeCommunication` first; its explicit common-documents root
controls the actual `AbsoluteTimeStamp.log` file. There is no successful logging
or connection callback substitute. The single-context `replay_workflow` format
does not advertise these multi-context operations; use their typed APIs with
actual primitive replay backends.

`parse_each_p5_reply(reply, requested_number=...)` parses the native EachP5
self-describing DID records. `analyze_each_p5_reply(state, reply,
requested_number=...)` applies them to the concrete `P5FreezeState`, including
selected support, physical definitions and rendering. The decoder retains valid
preceding values and native existence mutations on later malformed data or
metadata failure. Duplicate DID entries retain their first value; missing DID
bytes are never filled. `each_freeze_p5_core(state, requests, begin=False,
create_diagnostics=False)` supplies the GetDiagCodeP5 outer consumer with its
separate existing-diagnostic semantics: it does not create missing DTCs or mutate
existence. The standalone default creates DTCs and existence as Each1CD0 does.

The concrete normal core uses selected functionCF, first aggregate communication,
the ten native masked statuses, fallback of the complete request list to
individual record numbers after a first masked/zero-count response, and later
request pruning. It mutates caller-owned typed request numbers, retains captured
frames, and finishes all communication before analysis and timestamp sorting.
Flags are restored after faults and cancellation. Original18 bus14 uses the
native extended65535 receive bound; original12 retains its separate default.

`predictive_freeze_p5_core` implements the standalone D0 phase: fourteen base
probes, DTC filtering, sixteen probes for each matching base, temporary concrete
Common diagnostics, timestamp sort and the native merge. This D0 format is
separate from GetDiagCodeP5's predictive CF format. `merge_p5_diagnostics`
retains existing PID metadata, native replacement/append behavior, and the
original source-index/destination-index defect: unsafe native indices fail
explicitly instead of reading outside a list. Predictive header placement is independently assembly-verified: record number,
three DTC bytes, an ignored header byte, then count. No status meaning is
assigned to that ignored byte.

`each_freeze_p5(diagnostic)` composes normal, predictive, or selected Subaru
snapshot data phases, then applies normal-base display ordering, timestamp flags,
native result pruning and selected-DTC output. Input record lists are explicit
observations. With `log_enabled=True`, the original18 export wrapper performs conditional
`StartCommLog(0x14)`/`StopCommLog` through the concrete bound file owner, producing
`MarkMonRam_SSR.log`. `False` preserves the native disabled flag path. Each does
not add the separate operation/saved-log connection or disconnect sequence.
Original12 Each Execute has no logging imports or conditional flag; its explicit
`log_enabled=True` host option is rejected instead of inventing a native call.

`operation_freeze_p5_core()` implements the separate operation-P5 data phase over
actual `NativeCommunication`: selected function66, four native constant setup
requests, AB11 operation discovery, AB12 sorted unique snapshot discovery and
AB13 DID data. It preserves separate normal/NoInit flag scopes and the native
nine-error omission/two-error-stop behavior. `parse_operation_p5_reply` decodes
DID0501's first big-endian WORD, retaining first duplicate DID data and preceding
values on malformed tails. Snapshot0 and IDs above255 are read but not appended,
matching the original consumer. These records retain their proven raw WORDs and
native blank metadata; no engineering unit or scale is inferred, and their
status is partial. The method requires a concrete native context. `operation_freeze_p5()` adds the
full original18 log0/check/data/disconnect1/conditional-stop sequence and writes
the actual `OperationFFD.log`. Start failures still permit the body; an existing
body error wins over logging errors; stop runs only after a successful start.
The returned report preserves ignored disconnect status. Cancellation and
budget failure still release the retained channel and close the logger with a
fresh bounded cleanup deadline. The file lifecycle retains the source build. Original12 Operation uses its own
verified Execute38C0 and the same four initialization constants. Its count0
parser exits immediately without further DID records, retaining only preceding
values; original18 rescans from fixed offset7. The parser's explicit
`source_version` parameter preserves this functional difference.

Original OperationP5 helpers rewrite mask/check lists along with literal AB and
setup requests. Common extended exchange ignores those lists and checks positive
SID only; therefore these writes do not change lower primitive arguments. The
port retains the selected frame's actual settings/source validation and sends
the exact rewritten request bytes through that concrete Common path.

Native normal Each request/diagnostic lists accept3FFF groups only for selected
original18 bus14, matching the actual CE producer. Other contexts retain3FF.
The concrete freeze state binds that bus observation and rejects later mutation.

Both V2 and MultiP4 use the recovered signed circular high-nibble mapping:
10/20→1/2,30..F0→-13..-1,zero→0. V2 descends and skips zero-high frames;
MultiP4 ascends through zero and retains signed native sample indices. The
independent original-PE jump tables verify all512 byte inputs across the two
helpers; unsigned nibble loops are not equivalent.

Saved full Execute wrappers require one actual `NativeFrameController` shared by
all selected target caches. Create the selector through `from_backend`, then use
`selector.share_context(profile, ecu, bus_id=..., first_request=...)` for targets.
Separate controllers are rejected before logging or communication. Actual two-ECU
PID and routine regression cases exercise both physical addresses, mode3 logging,
one connection and one final disconnect with no retained channel ownership.

The concrete factory retains the exact `NativeCommunication` on its ToyotaSession.
Counted CAN diagnostic continuation uses its selected receive primitive, preserving
ComSet timeout, source/bus flags and native capacity; it does not send an empty
request. Initial Common retry consumption reduces the receive continuation budget.
The focused composed check uses serialized original12/18-format authored databases,
actual frame transport and a primitive J2534 backend; it covers ordinary/extended
packets, timeout, retry exhaustion, fatal status, partial metadata and cancellation.

Native12 active-test monitor selection always uses the normal enabled-DID
producer. Native18 selects the Subaru producer when category flags masked with
`0xe0` equal `0x20`. The native12 and native18 metadata, optional-child merge,
unit retention and LSB bodies otherwise have matching instruction structure;
three serialized selected-input factory controls exercise these branches. The
selected device_kind8 fixture writes C8 without a startup write; this is a
wire observation, not an assertion that the active API sets NoInit. Independent
device_kind4 control includes startup1001 before C8.

Native12 MultiP4 retains the signed ascending frame-index loop and includes the
zero-high-nibble frame. Its byte mapper is checked against all 256 inputs read
from the pinned original PE tables. Composed original12/18-format authored DDB
cases use the real support producer and frame controller for normal, masked
error and cancellation paths; raw5 maps to engineering10 in both builds.
