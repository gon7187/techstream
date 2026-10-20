# Native active-test metadata

`scripts/active_tests.py` reconstructs selected native List and Init metadata.
It accepts a real `VehicleProfile`; it never opens an adapter or infers support
from a test name, model name, or the presence of a database row.

```python
catalog = ActiveTestCatalog(profile)
support = catalog.observed_support(
    family,
    protocol=selected_protocol,
    pid_lengths=observed_pid_lengths,
    did_lengths=observed_did_lengths,
    enabled_dids=observed_dids,
    enabled_rids=observed_rids,
    check_bits=observed_support_bits,
    exchange=bounded_exchange,
    pid_support=selected_pid_support,
    routine_probe=selected_routine_probe,
    sa_finalize=selected_sa_finalizer,
)
tests = catalog.list(family, support=support)
reader = catalog.initial_value_reader(session, positions=observed_p4_positions)
initial = catalog.initialize(
    selected_test.family,
    selected_test.signal_id,
    support=support,
    read_value=reader,
)
```

Import `ActiveTestCatalog`, `ActiveSupport`, `SAFinalizer`, and `SAKeyMaterial`
from `scripts.active_tests`. Build support for the selected family. The `p5`
list contains ordinary P5 and routine tests; each result identifies its actual
family. `old_body` and `sa` have List exports, with no separate Init export in
this family. Select the actual Init module independently for those protocols.

`ActiveSupport` also accepts explicit providers directly. These are injection
boundaries for captured observations or bounded communication, not default
successful stubs. Missing required providers fail. `observed_support` binds the
recovered algorithms in `scripts.support` to selected PidBit/DidBit,
DataIdForAct, DataIdBitForAct, DataIdPanelSupport, and routine support records.
It retains separate ordinary and Subaru caches. Its DID-length cache starts
with the supplied observations; it does not replace a known length with the
native missing-length sentinel. Rebuild the binding when selected context or
observations change. The caller must serialize use of one binding and transport.

The exchange callback must enforce its own blocking timeout, cancellation,
exchange budget, and deadline. The session initial-reader and SA finalizer
provide these checks through the selected `ToyotaSession` policy. Python cannot
interrupt an exchange callback which ignores its blocking timeout.

## List contracts

| Family | Selected tables | Native behavior |
| --- | --- | --- |
| P3 / DK | ActTest 2/11, DidBit 2/9 | Observed enable-list lengths, native mode, optional selected bit request |
| OldBody | ActTest 2/11, DidBit 2/9 | Old-body membership policy, with observed length gate retained |
| P4 / SA | ActTest 2/11, MultiDid 2/33 | Parent/child membership and optional-child flags; suppress child entries |
| P5 ordinary | ActTestP5 2/68, MultiDid 2/33 | Native ordinary/Subaru DID gate; parent requires supported children |
| P5 routine | RoutineActTestP5 2/71 | Native ordinary/Subaru RID gate |

P4 patterns 20/21 require that the two support bytes are not both supported;
patterns 22/23 require both. Both checks execute, and their bit boundaries wrap
as native unsigned words. A parent with only unsupported optional children is
suppressed. Missing referenced child metadata fails instead of indexing outside
the selected array. P5 preserves the first parent-or-child match in native
MultiDid order. The combined P5 list sorts by the ordinary row's word 44 or the
routine row's word 56 (v12: word 54), using the native pairwise exchange loop. This is not a
stable sort: entries A(order 2), B(order 2), C(order 1) become C, B, A.

Names resolve actual language IDs. Legacy short names are byte C strings, not
UTF-16. Proven ASCII is decoded; unknown code-page bytes remain available as
`short_name_bytes` with `short_name=None`. The host bounds the inline prefix at
20 bytes and rejects an unterminated prefix instead of reading numeric fields.

## Init contracts

Database version 0x0100030C uses the recovered v12 layouts; version
0x0100032F uses v18. Other active-metadata versions fail explicitly. V12 PatDisp
is twenty bytes: group word 4, press/release words 10/12, support reference
word 14 and mode byte 18. V18 PatDisp is twenty-four bytes: group word 12,
press/release dwords 4/8, support reference word 18 and mode byte 22.
V12 RoutineP5 is sixty bytes: every v18 field from offset 32 onward moves
back two bytes because the later Subaru bit-reference word is absent. Its
order is word 54 and support mode byte 58. V12 ListP5 uses the ordinary
DID/RID paths; it does not select the later Subaru branches.


Legacy ActTest92 uses initial/max/min dwords at 20/24/28, initial-read mode at
84, and limit-read mode at 89. Initial mode zero explicitly produces zero;
mode one reads Freeze84 referenced by word 58. Limit modes 1/2/3 read selected
Freeze rows referenced at words 76/78: mode one updates the maximum, mode two
updates the minimum, and mode three updates both. P3 and DK use GetEcuDataP3; P4 uses
GetEcuDataP4 and the explicitly observed support-position cache.

P5 ActTest64 uses initial/max/min dwords at 0/4/8, initial-read mode at 57,
and limit-read mode at 60. Initial mode zero reads the selected active value;
mode one keeps the stored constant. Limit words 48/50 select DataMonitorP5
rows for the maximum/minimum respectively. The current-value PID is either explicit word 54 when byte 61 is one,
or the first monitor matching flags, wire DID and bit boundaries, excluding
PIDs 7000 through 9999. Its support is separately observed.

`initial_value_reader` selects actual profile function 0x6B for legacy reads
and 0xCA for P5 reads. Legacy values use native affine GetValue and retain
unsigned DWORD results. P5 reads retain the selected raw bit value. A completed
native communication failure leaves the stored limit/current constant;
cancellation, deadline, missing caller inputs and invalid host return types
remain visible failures. Each read receives its own bounded native-call budget.

All Init families join ActTestPattern 2/12, PhyData 2/13 and Unit 2/15.
Ordinary families join PatDisp 2/14. Returned controls include button size,
key-operation pattern, invalid-key flag, maintenance/continue/lock times,
precision, signed physical coefficients and the unit function. Text/help IDs
remain literal IDs; they are not guessed language strings. Legacy panel support
uses CheckDidBitSupport; P4 uses the ordinary membership-checking variant;
P5 uses CheckSupportPanel. Every display entry retains its actual press/release
values and independently evaluated enabled state.

Routine Init takes its maximum from DWORD0 and minimum from DWORD4.
All scalar initial values, limits and integer display press/release values are
materialized as signed 32-bit values after native reads. The public native API
takes signed `long` (`J` in its exported signature), and the Init diagnostic
labels print these DWORD carriers with `%ld`. This interpretation applies to
every scalar, including wholly negative intervals; it is not inferred from
minimum/maximum ordering or physical `sign_mode`. The original selected record
bytes remain unchanged as provenance. Fresh native response constructors set
bit length and graph bounds to zero. Init does not derive bit length from an
active row, and does not reinterpret a data bound as a graph bound.

Routine Init additionally joins PatDispVariable 2/73 for labels, inputs and
buttons, and RoutineStatus 2/72 for completion/failure patterns. Variable
references resolve against the selected management variable table. Only the
input group evaluates panel support; the other groups preserve native disabled
flags. Scalar button values reproduce native DWORD shift-count wrapping.
The last button group's first press-variable length controls the final selected
D7 status probe. Command/output/button-mask references at row words 40/42/44
are exposed as bytes for `routine_arguments_p5`. The routine specification ID
is retained separately. No command or mask is invented.

A missing database table differs from a successful empty key group. Missing
required tables fail with native A0030107; native successful empty groups retain
empty/default metadata. Missing selected test/read rows fail with C0040101.
Invalid native modes fail with C0040102 or the recovered support error code.

## SA exchange and local key material

Construct `SAFinalizer(profile, session, material)` and pass it as
`sa_finalize`. Material can be explicit `SAKeyMaterial` or loaded with
`SAKeyMaterial.from_library(path)` from the user's original
`GetActTstLstP4SA_DT.dll`. The extractor reads at most 57,345 bytes, verifies the
exact recovered v12/v18 build's SHA-256 and reads two instruction operands. It never
loads or executes a PE file. Public source and tests contain no original
operands or key vectors. Material has no value-bearing representation or report.

Only a nonempty SA list invokes finalization. The finalizer selects the actual
EB frame and performs its seed exchange. Native communication failure, short
reply or zero seed completes without an EC dependency. Only a nonzero seed
selects and validates the EC frame, derives the response in memory and patches
its two argument bytes. The native final communication result is ignored;
host cancellation/deadline/budget failures propagate, including after I/O errors.
No seed, key-bearing request, response or material is appended to session traces.
The key/library must be supplied before any exchange.

## Evidence and verification

The source is static Techstream 18 and 12 analysis. The following RVAs describe
v18: GetActTstInit / InitDk / InitP4
entry RVA 0x1030 and their metadata helpers at 0x1950 / 0x1610 / 0x1990;
InitP5_DT 0x1030, 0x1C20, 0x1D10 and 0x27C0; RoutineInitP5_DT 0x1030,
0x1520, 0x1610, 0x1C60, 0x2040 and 0x2260. ListP4 0x1190, ListP5_DT
0x1090/0x1710/0x1AF0/0x2070/0x2230, OldBody 0x1180 and SA 0x11A0/0x19D0
establish list ordering, support and lifecycle. KgpDataCtrl GetMonShortName
0x5FA4 returns the raw prefix; CommandDataLib 0x73EB0 consumes a byte C string.
Original disassembly, hashes, decompilation and corpus outputs stay in ignored
private evidence; no original DLL, database bytes or key material is bundled.

`python -m unittest tests.test_active_tests` exercises authored layouts, exact
joins, all families, native communication faults, cancellation/deadlines,
unsigned boundaries, variable groups, support-cache observations, SA phases and
key extraction rejection. The private original default-context corpus covers
1,369 profiles: 12,926 initializations each for P3/DK/P4, 3,356 P5 and 1,595
routine, using explicitly authored unavailable-read/unsupported observations.
The v12 default-context corpus additionally covers 1,002 profiles: 12,023
initializations each for P3/DK/P4, 1,557 P5 and 215 routine. Both complete with
zero initialization dependency errors. The v12 display consumers at P3
0x1B75, P4 0x1BE3 and P5 0x1ED1 establish the older word-sized values; the v12
routine consumer and ListP5 establish its sixty-byte record and shifted fields.
These checks verify static metadata paths without claiming live support or execution.
Physical ECU applicability and end-to-end adapter behavior remain
`PHYSICAL_UNCONFIRMED`.
