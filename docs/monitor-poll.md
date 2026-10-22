# Normal direct polling

`selected_normal_poll_worker` binds an explicitly selected source12/18 P4 or P5
monitor plan and selected connection to `NativeFrameOperations`. Its optional
`communication` argument admits the exact source-bound `NativeCommunication`
owner after a serialized context handoff. Retained routing is limited to normal
P4 BASE/Packet and P5 plans; Variable, MultiMon, A8, Dual and instrument branches
keep their distinct controller seams. These direct workers require observed
device8; device4 selects its separate native DMCI
interface. P4 uses the
shared `DirectJ2534Worker`; P5 uses `NormalPollingWorker`. Construction
and import perform no I/O. Calling `run(n)` explicitly invokes the injected
J2534 primitive backend and returns `NativeRecorderCapture`; its packets use the
shared monitor packet grammar and can feed the existing DM/recorder consumer.
P5 accepts the PSA lower CAN class only when native selected metadata requires
it (bus family2 and ECU low flags14). This lower class is independent of the
normal P5 business controller and intentionally has no tester7F request.

P4 uses the same `CCommEventDM` implementation as the recovered normal P3 worker,
not a similar-name substitute. P5 uses the shared concrete `P5MonitorEvent` for
DID22, DTC19 counts, RID31 payloads, pickup and cycle storage. P4 retains bytes
not overwritten by a short response; P5 clears storage after each complete
cycle. The completion response supplies the host tick, rather than a driver
message timestamp.

The worker preserves native ordinary-send flag6=0 (lower initialization mode1),
clear-RX1, receive argument5=0/flags100, selected functionA7 timing with1000/200
fallback, per-request retries, source filtering and service-specific error
notifications. Source18 additionally records receives at ticks at or beyond
2,000,000,000 and preserves its category20 routine NRC24/33 substitution.
Routine abnormal observations pause acquisition and retain the raw notice.
P5 bus14 uses the source18 65535-byte receive allocation; other branches use4096.

Dynamic cleanup consumes the separately registered11A list of all slots cleared
by the selected producer. It never substitutes the dynamic read-ID list.
Stopping executes selected functionD4, patches its two DID bytes and invokes
concrete Common communication over the same owned channel. Native best-effort
statuses are retained in `clear_results`; metadata lookup failures are retained
in `cleanup_error`. Cancellation does not skip channel release or clear cleanup.
A transport adopted by another owner between construction and start is rejected
and left untouched.

Deadline, monotonic clock, call, packet and byte limits are explicit host policy.
Callbacks are limited to clock/cancellation observations and an optional packet
consumer; none claims that a native business stage succeeded. Exact source build
is a plan field, independent of the DDB format version.

The normal factory arbitrates active, monitor-system and data slots in native
priority order. P4 uses the shared concrete active/system event classes. Its
ordinary A1 packet event preserves mode6/mode1 setup order, separate partitions,
E2 assembly and A3/receive-drain cleanup. This ordinary packet event is separate
from the flag9 A8 controller.

P5 active events retain their end-command queue, deduplicate stop commands,
revisit timed IO controls while allowing data polling, and track the native
two-entry RID list in source18. Source12 checks routines without that RID
filter and still filters source IDs on bus-family4; source18 accepts bus4
responses without that source check. Routine normal/abnormal and before-drive stop-status checks
retain notices; monitor-system replies use their separately selected source ID.
Stop attempts every retained end command even after negative replies. Native
stop-error notifications set the disconnect flag; host cancellation still runs
end commands and D4 clears over the owned channel before disconnect.
Category68/999 instrumentation and Dual have separate controllers. The shared
P4 worker supports explicit selected oscillator registration; normal caller
flag selection belongs to its source-bound caller, never inferred from P3.
Real adapter/vehicle equivalence remains `PHYSICAL_UNCONFIRMED`.

Source anchors: DataListIF18 RVAs23a50/23aa0/29320/29c30/2a490 (P4 events and
worker), cc40/d8a0/dc80/121e0/12f80/13110 (P5 events, worker and cleanup), and
DataListIF12 e170 (P5 worker). The normal P4 switch was checked against the
cached annotated assembly because its decompilation omits switch arms.

Check:

```sh
python -m unittest discover -s tests -p test_monitor_poll.py -v
ruff check scripts/monitor_poll.py tests/test_monitor_poll.py
pyright scripts/monitor_poll.py tests/test_monitor_poll.py
```

`NormalOscilloscopeSelection` is the normal P4 caller's explicit category999
selection. Passing it to `selected_normal_poll_worker` binds the selected
instrument profile, four channel IDs and concrete oscillator provider before
start. This follows normal P4's category999 setup into `set_measure_mode`, which
sets the native flag at98. It never infers that flag from a P3 selection. The
selected P4 Packet worker therefore uses the timestamped single zero-sentinel
Dsti read, while the base worker uses its separate drain operation. Normal and
instrument packets remain separate captures; stop retains the native final
reverse-time instrument capture.

`selected_variable_single_worker` follows DM_ActVariable's8610 constructor,
which selects the **base** worker for one non-voltage target even when its
selected child uses an A1 event. Event grammar is shared native DataListIF code;
worker selection is explicit. Its A1 responses use host ticks and do not enable
the Packet worker's burst, interrupt, A3 or receive-drain path. The separate
variable controller owns its start/stop queue; this factory inserts no114/116
ordinary P4 lifecycle commands. Child modes 2/100 are rejected exactly where
native8A30 rejects them with C005100D.

`MultiMonitorPollingWorker` implements the separate DataListIF MultiMon
controller for one or two non-voltage entries under the variable outer
controller. It is not the Dual business controller. Selected entry category,
bus and raw entry DWORD plus the exact IDMap fields must match the concrete
`NativeMultiMonOperations` registration. One lower channel serves all entries.
Data acquisition rotates after each completed target cycle. An active request
temporarily selects the first target, then restores the previous data target.
MultiMon does not apply the ordinary worker's source-ID filter. Stop sends the
native30 end request before disconnect1, including after confirmed host
cancellation; uncertain driver outcomes retain lower resource-fault handling.
Each target retains its own packets, metadata, timing and allocation limits.
Native start ignores Connect/Entry scalar statuses; `setup_results` retains
them and subsequent acquisition produces the native event error. Unknown I/O
outcomes still raise and enter the lower resource-fault path.

Native MultiMon overrides pair setup only. An A1 setup inherited from the base
class does not populate MultiMon's per-entry event pointer; native start then
dereferences that null pointer. The host rejects this combination before I/O
with E0000102 instead of reproducing the native memory fault. This is a deliberate
bounded adaptation of a source-confirmed invalid combination. The outer
variable controller can have three slots including voltage; it cannot create
three native non-voltage entries. Category68's supplied native voltage
interface has its separate source-confirmed initialization failure contract.

Additional source anchors: DM_ActVariable18 8610/8A30 and DataListIF18
2d0d0/2d170/2d1c0/2d340/2d690/2dc60 (12:
23760/23800/23d20); normal P4 dc50 category999 and DataListIF2a620
`set_measure_mode`. Private evidence records exact source hashes and the native
null-entry adaptation separately from successful acquisition.

With a retained owner, construction snapshots lower and channel ownership;
`start()` rechecks the selected source and controller context before I/O. The
worker uses the retained outer controller and preserves its native state. Thread
entry applies the lower's native temporary-config predicate. A cold lower stays
closed until the first actual SendProc performs its usual lazy setup. P4 restores
temporary config and returns the borrowed controller to the parent. P5 restores
temporary config before disconnecting that same controller with the source
release/fault flag; parent cleanup remains idempotent.
