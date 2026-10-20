# Variable-drive monitor provider

`DM_ActVariable_DT.dll` is selected for raw category phase4 when the observed
Attribute(3,31) is true. It has separate behavior from `DataMonitorPhase4.dll`.
The ordinary P4 producer must not be used as its fallback.

The recovered C260 active command producer is implemented in
`scripts/monitor_variable.py`. `selected_variable_active_operation` resolves the
selected DB229 variable-drive row, DB20C pattern and management DB111 frame. The
result retains the full service byte in the producer frame. The 7800 caller
passes output+1 and length-1 to active_test_start, so native command10F carries
only the body and the unchanged repeat field.
`VariableActiveRuntime` binds this selected body to the actual DMCI packet
serializer. Stop110 has a separate cancellation-free cleanup budget after a
failed or cancelled native start, and retains its selected identity when source
context changes. A cleanup failure is attached to the primary exception.

The frame interpreter rejects opcodes11/12/13 and emits
zero for unrecognized instructions. In particular it does not inherit the PSA
Mode35 extension. The low7 phase returns its two-byte command before pattern
repeat assignment; the codec returns `None` for that unchanged field and the
selected producer requires an explicit retained repeat observation.

Application source selection is explicit through
`VariableMonitorSource.for_build(12|18)`; database layout does not select the
application build. `from_path` can additionally bind a privately imported module
and revalidates it before command production. The two supported module SHA256s
are 340dd411bd94b409bb44b7cb318e83c80aa39ff94e4030c1f1a9a802774ad13b
and e6f6b82e41f8c2689835a25e13d35fed21b45ea44bfb2f9199edfd8192b759a6.
Both builds use C260 for this operation; their imports, database object offsets
and diagnostics differ and were inspected separately.

The D140..D4E0 measurement arithmetic and CF40 proportional allocation are
also ported with explicit mode/bus dispatch and native DWORD behavior.
The 74B0 multi-target bus policy permits distinct low-nibble2 buses, requires
identical other buses, exempts voltage category68, and joins only the low WORD
of caller exclusions.

Basic Freeze/MultiPID descriptor construction and A1/polling packing are
implemented as separate variable-drive entry points. Native01440 always tests
ANY supported bit across a range; normal P4 instead uses a different test when
BYTE77 is1. The shared packing helper is used after applying this exact
variable-drive distinction, and the original descriptor bytes are preserved.

The selected voltage child uses the original five-byte descriptor and explicit
calibration state. Its native interface GetError remainsFFFFFFFF in both imported
builds; source8610 retries construction until zero. The offline host bounds that
retry with deadline, cancellation and attempt budgets, preserving it as a host
failure without fabricating a native error or voltage samples.

Flag9 has its own typed `SelectedVariablePacketMonitor` and selected packing
path, including ISO buses; it does not inherit the ordinary A8 CAN-only guard.
Native2510 invokes
CreateEnablePidListExt(kind1), then tries mode1, cached mode2 and pair fallback.
Its six packing/selected-range/trigger/pickup helpers match the retained P4 helpers after
explicit diagnostic relocations; `check_packet_helpers.py` verifies these bodies
and mutation controls. This shares the native codecs without changing provider
dispatch. Basic1170 also enforces its seven exact observed bus identifiers.

The actual DMCI capture decodes the error buffers and applies the variable
callback mapping before returning packets. Native603/608 errors still run the
independent10E/108/104 disposal sequence. Active10F/110 native status maps to
A0050441 with the original structured status retained as its cause; host
timeout, cancellation and context failures remain distinct.

`check_variable_monitor` implements the selected single7/multi42 CheckStart
entry and signed CF40 allocation. CheckStart measures targets independently;
runtime74B0 applies the separate bus compatibility check. The resulting typed
measurements feed `selected_variable_runtime_target`, which binds the actual
selected connection, raw EntryCommSystemInfo parameter and native signal/frame
buffer with its allocated capacity.

`variable_dmci_lifecycle` constructs the variable CAN/ISO interface and IDMap
directly. It accepts the distinct basic and flag9 children and never inserts
the normal P4 SetNegCount114 or SetInterruptSendTiming116 commands.

The concrete device4 wire helpers use the native buffer identifier (category),
not the mapped diagnostic request address, for GetMonitorData. Both original
DataListIF polling threads load that key from buffer DWORD+468 and match reply
keys against the same field. `run_variable_multi_dmci` takes typed selected
targets, an explicit controller connection and the actual `NativeVimClient`.
It sends one CAN/ISO create and connect, per-target IDMap/Mode setup, one global
start, then category-keyed GetMonitorData and independent stop/disconnect/delete.
Authored12/18 vectors cover two categories sharing request address7E0, ignored
native IDMap failure, setup/start/stop/data error separation, source mutation,
host TimeoutError identity and cancellation. Unknown/repeated reply keys are
rejected by the host parser. The public helper requires the nonempty controller
first. The runtime and concrete normal25 factory additionally accept the actual
absent-controller registration through `VariableNullController(profile,
connection, source_build)` and `null_controller=...`. Its selected management-only
`ProtocolProfile` needs no ECU database: mode80 has no producer, allocation,
monitor buffer or GetMonitorData key. CAN/ISO construction uses this controller;
8A30 emits its IDMap before the real target IDMap/Mode setup. Captures and rings
remain aligned to real targets; `native_slot_categories` exposes physical order
and `get_fault(0)` returns zero for the unallocated NULL slot. Source context and
the native three-slot limit include the controller. Device8 NULL plus two
communication targets exceeds the two-entry MultiMon map (A0050425); NULL plus
one has no entry event and receives the explicit pre-I/O host adaptation
E0000102 instead of reproducing the native null dereference. Both builds have
strict authored device4 wire and device8 rejection checks. Voltage combinations
and native thread equivalence remain OPEN.

`VariableDmciWorker` owns the same literal device4 transaction as a cooperative
worker: setup executes during start, each acquisition step performs one10D,
and stop closes the generator's independent10E/108/104 disposal path.
`VariableMonitorRuntime` accepts the actual `NativeVimClient` with observed
`connected_device=4` and an explicit first-slot `controller_connection`.
Its existing typed command queue sends actual10F/110/113 between data polls;
native command failures retain their mapped status and do not abort otherwise
valid acquisition. Host timeout objects remain unchanged. Actual category-keyed
packets feed the same allocated rings and native DM export as the device8 path.
Data from a reply is copied before error callbacks, as in the native poll thread;
valid same-batch packets remain exportable after a native fault or host cancel.
The worker retains all callback notifications and the exact number of trailing
NotifyEnd observations in `completion_count`; this does not invent Windows
handle or thread equivalence.

`VariableMonitorRuntime` composes the concrete device8 BASE worker for one
total slot, or MultiMon for two or three total slots. MultiMon accepts one or
two non-voltage entries; voltage68 contributes to the native constructor choice.
The voltage slot's unavailable imported interface fails through the bounded
host retry above.
Actual packet captures feed allocated native x86 rings, preserving overwrite,
serial0/1 images and DM export metadata. CAA0/CB00 native slot faults are kept
separate from host deadline, cancellation and storage-budget failures.

`start`, `step` and `stop` additionally expose bounded cooperative acquisition.
`enqueue(11|12|96, selected_operation)` returns a separate
`VariableCommandResult` with completion, native status where available and the
original exception object. Commands execute at the concrete worker's next
selection boundary; they never silently start acquisition. Wrong-state commands
complete with90050405 before I/O. Malformed selected arguments complete
withC0050001; host uncertainty retains its exception type and no fabricated
buffer fault. Stop independently closes the concrete lower channel and completes
queued commands that were not serviced. `close` also stops an active runtime.
This is an explicit host scheduling policy, not Windows event/thread equivalence.

The authored18 joined-factory test now uses the actual support communication,
25 normal factory and93 BASE worker. After the first data packet it produces
command96 from selected protocol metadata, then command11 from selected
DB229/20C/111, and command12 before outer Stop. Actual primitive frames are
08/48,30-body/70 and30-end, followed by channel disposal and native DM export.
The test retains original partial-ANY metadata: a1-byte frame with endbit15 is
exportable as raw DM, but the safe display decoder rejects its invalid recorded
signal range. Static DCF0 in both original builds proves that the original
producer checks only the first supported byte and does not clamp the end bit.

Command96 is a distinct monitor-system slot. `selected_variable_system_operation`
implements7AE0/C6D0: service08 plus the low signal byte, padded with five zeroes
for bus families1/6/7/9. The113 consumer receives the body without08.
The actual J2534 system event transmits08 and accepts48. Native113 failures map
toA0051401, while host errors retain their types. Packet running modes reject
this command withC005100D. MultiMon retains its source system-slot priority;
an uncleared system slot can prevent data progress and exhaust the host budget.
Active7800 uses the native mapped request identity, including ISO address bits.

Runtime7EC0 selects its child from the controller category's BYTE72, resolved
by the explicit command ECU throughA6E0. CheckStart66E0 instead reads each
target's flags. Both selected basic and packet factories accept explicit
`controller_category_flags`; no target profile is rewritten to select a child.

`selected_variable_recording` binds an already selected target to the actual
writer2/0 DRS serializer. Group11 contains variable CAN/ISO setup and start;
group12 contains stop and disposal. Device8 recording uses this DMCI route.
Static CreateDrs writer vtables resolve87's virtual18/1C to
`CFileWriter::WriteStart/WriteEnd` in both original builds. Their patched
nested lengths match the finalized group serializer. The selected enable mask
is validated and serial mode is forced to1; caller protocol/session selection
and the complete87 queue/error chronology remain separate unfinished work.

Full provider coverage remains **OPEN**. Cooperative11/12/96 and the normal25
factory join have authored positive and failure evidence; the complete exported
controller also requires command9/10/56/87 dispatch, command87 multi-entry writer
failure precedence and outer mode7 metadata, complete voltage combinations, and
independent complete original12/18 source review. Current tests do not establish
all of those branches or Windows thread/event equivalence.

Run the authored synthetic checks with:

```sh
python -m unittest discover -s tests -p test_monitor_variable.py -v
```

No OEM binary is executed; tests open no device or network connection. Physical
behavior remains PHYSICAL_UNCONFIRMED.
