# P5 freeze state

`scripts.freeze_p5.P5FreezeState` associates actual DID observations with the
selected P5 freeze definitions. Construction requires a selected profile, an
explicit original Common source build (`12` or `18`) and that profile's concrete
`MonitorSupportCache`. The source build is independent of DDB format. The state
exposes the exact source SHA256 and checks the canonical seven-part selected
source identity before processing or exchanging data.
It binds the observed cache connection bus at construction and rejects changes.
The diagnostic/request group limit is16383 only for original18 on bus0x14;
original12 and other or unobserved buses retain1023. The capture byte and value
retention budgets apply independently.

`add_diagnostic` resolves the selected P5 DTC metadata. `analyze_single_data_id`
accepts a typed `P5Value(value, index, kind)`, literal payload and the actual
`P5DataIdObservation` list. `analyze_record` performs the native record-number to
FFD-type/index conversion. The low-level analyzer does not create an absent DTC.

Support uses the FFD/SSR DID at DM62 WORD56, rather than the normal monitor DID at
WORD54. Mode0/2, the native preceding-byte mode1 check, optional DB250 support
variables, first DID matches and PID support caching follow the original base.
The native PID list preserves duplicates. Ignored support errors remain visible
in `ignored_errors`; they do not create data. Unsafe native out-of-bounds ranges
fail at the host boundary.

FFD metadata resolves the actual label, required physical and unit definitions,
display selector, bounds and complete pattern low/high words. Each metadata
construction creates a fresh concrete `SignalLSB` over the same support cache.
Its changed DM DWORD12 threshold is retained. Ordinary monitor metadata is a
different native object and is not substituted here.

Diagnostics retain raw main signals, three special timestamp lists, odometer,
absolute components, existence flags and normal/extended record numbers. Main
raw values survive rejected special sentinels or invalid BCD components. Later
errors retain earlier native mutations. `sort_display_order` follows selected
DM table order. `sort_multi_data_by_timestamp` implements the sixteen literal
FFD groups, required timestamp triplets, companion filtering, linked swaps,
first-match reindexing and signed-byte wrap. Original18 additionally propagates
the six absolute component lists. Original12 has neither those components nor
the category190/191 selector49/timestamp4A branch.
Both originals advance the timestamp sort window's cumulative end for singleton
groups while retaining its start until a group has multiple entries. The next
sort can therefore include the preceding singleton; that literal behavior and
its full bubble-pass count are preserved.

Original18 Subaru snapshot uses `P5SnapshotRequest(code, numbers)` and
`comm_execute_snapshot`. It selects the first actual functionCF frame, patches
the DTC and request number, and uses the concrete extended communication cache
primitive. The ten native tolerated statuses remove the affected number;
other failures preserve successful prior captures and propagate. Cancellation,
finite deadlines and exchange budgets come from the shared cache.
The native frame's default receive capacity is4096 bytes. An oversized reply
returns tolerated `A0040202`, removes that request number and preserves prior
captures. It cannot count toward the separate16MiB host retention budget.
The separate `native_cancel_value` models the command's observed cancellation
DWORD: literal1 returns `A0040003` before each snapshot exchange. It is not a
device identifier; other values do not select that native branch.
`analyze_snapshot_received` parses actual captured bytes using selected DB23D
lengths, records partial tails, resolves DTCs when requested and invokes the same
concrete FFD state algorithms. Original12 Subaru is rejected because that native
subclass is absent. `init_freeze_data` clears captured frames while retaining
support and diagnostic state.

`dataclasses.asdict(diagnostic)` produces a serializable representation.
`signal.metadata.render(value)` adds the source-derived display result; raw
values, FFD kind and time index remain available independently.
The shared display helper accepts widths1..32. Wider native FFD extraction
retains the exact DWORD shift-wrap result and original width; it does not
silently truncate that width to obtain a display string.
Host retention is bounded to16MiB captured payload and65535 values per diagnostic;
each association reserves up to three value slots before mutation. Diagnostic
histories retain the latest65535 entries and expose list snapshots.
The capture boundary test fills the complete16MiB with4096 valid4096-byte replies
and rejects the next capture without dropping any earlier response.

Original18 Subaru stored FFD uses `comm_execute_stored()` and
`analyze_stored_received()`. Function113 first sends the selected literal request;
a tolerated error or response shorter than four bytes selects numbered requests
1..254. A numbered tolerated error or short response ends collection. A fatal
error preserves all previous captures. The native frame count is
`len(state.snapshot_frames)`; `stored_numbers` retains the corresponding request
bytes. Native initialization clears frames while retaining this number list and
the caller's sticky success indicator.

Stored analysis parses each record's number, response DTC and DID count from the
actual bytes and selected DB23D lengths into a private diagnostic stage. Failed
stage analysis leaves the public diagnostic list intact. `set_stored_confirmed`
selects the first zero-valued DID101F signal's index, or the index derived from
the greatest extended number, and changes only the first matching sample per
main/timestamp list to type1. It then sorts and merges the stage using the native
asymmetry: existing extended numbers remain, timestamps and odometer append or
replace empty metadata, and existing PID positions determine local append bounds.
Unsafe native out-of-range merge positions raise a host `SessionError`.

The snapshot analyzer's `create_diagnostics` corresponds to the native final
ULONG's nonzero branch. It creates DTCs named by the response and sets existence
flags; it is not a DTC filter. Each wrappers pass `bool(selected_code)`.

Validation uses authored resources and literal wire observations:

```sh
python -m unittest discover -s tests -p test_freeze_p5.py -v
```

The implementation remains under independent source review and wrapper
composition checks. Whole leaf87 G2/G3 acceptance remains open until those
checks are complete. No adapter or vehicle execution is implied by these
offline tests.
