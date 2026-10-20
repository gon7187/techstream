# Native Dual monitor

`scripts.monitor_dual` implements the recovered Dual monitor thread as a
cooperative, bounded runtime. It does not open a device or execute vendor code.
Providers receive actual selected requests, rather than a callback that supplies
finished monitor samples.

The public entry points are `DualTarget`, `DualMonitorRuntime.configure`,
`start`/`step`, `request_stop`/`stop`, `run_packets`, `drain`, and `close`.
`configure` consumes the selected `MonitorSetup` produced by `data_monitor`:
P4 command `10A`, or P5 `119`/`10B`/`11A`/`11C`, with optional native `112`
composite pickup descriptors. Mode A1 command `109` belongs to a
different native provider and is rejected. The setup's interface field is the
native request/address key; the target's `command_id` is the separately selected
ECU/category key passed as the first driver-send argument.

The constructor accepts a `MonitorProvider` for literal `ReceiveExt` calls and
a `native_send(ecu, NativeFrameSend) -> uint32` primitive. The concrete selected
route supplies `NativeDualTransport` as provider and omits `native_send`: the
runtime passes its actual deadline and cancellation function directly into the
recovered lower transport. Sends use the full
seven-argument `SendIntExtDualMon` ABI. An observed connected-device value of `4`
with a selected protocol whose high nibble is `20` selects
`SendIntNoInitNoSession`, as the native `SendProc` does. The shared six-argument
monitor send primitive is not substituted for this ABI.

Optional `driver_control(DualControl) -> uint32` exposes `ConnectDualMon`,
`EntryCommSystemInfo`, and `Disconnect`. Registration requires each target's
explicit selected `entry_parameter`. Native ignores these return statuses; the
runtime retains them in `control_observations`. Without this primitive, the
caller owns the already-established transport lifecycle. Monitor stop keeps the
connection; explicit `close()` performs an idempotent destruction disconnect under
its own bounded release deadline, including after main/stop failure.

`NativeDualPrimitives` adapts one typed `J2534Backend` to the control operations.
Successful writes require an explicit confirmed count of one; a status-only
`None` result cannot establish success. It preserves the literal native
`Open(6,0,0)` selector: zero selects standard `PassThruConnect`, not a claim that
the physical line runs at zero baud. Control and lower message codecs join by
their complete `PASSTHRU_MSG` bytes.

`NativeDualTransport(control, operations, plans_by_ecu)` requires that same
backend, explicit matching application build, driver/device/diagnostic context,
and lower `native_variant="dual"`. `NativeFrameOperations` borrows the actual
control channel with `configured=True, owned=False`; target selection rebinds
its selected profile/plan without another connect. Actual `SendIntExtDualMon`
uses fixed initialization mode `2` and ignores parameter6 in both builds
(native18 `13e10`, native12 `f920`); `SendIntNoInitNoSession` also uses
mode `2` and its distinct no-session flag. Parameter7 remains
the native clear-RX argument. A fresh channel generation handles reuse of the
same numeric channel ID across acquisitions. Source, plan, policy and lease
checks surround lower callbacks before any packet reaches a ring.

The seven states retain their native numbers:

| State | Operation |
| --- | --- |
| 0 | Select an active-test or monitor request |
| 1 | Recover the selected session and send |
| 2 | Receive, filter native source address, validate and store |
| 3 | Map transport/parser failures to the native event error |
| 4 | Stopped/waiting |
| 5 | Start native DstiOsc measurement |
| 6 | Report native DstiOsc failure and stop |

Target-local P4/P5 request ordering and retained storage come from
`MonitorEvent`/`P5MonitorEvent`. P4 retains the unfilled tail of a short cycle;
P5 clears its packet storage after completion. A target rotates only after its
whole request cycle completes. Active-test operations temporarily select target
zero, then restore the monitor target. A timed active-test wait permits monitor
traffic while its native deadline has not elapsed. The third IDMap argument is
retained as a raw field; `50`/`1000` are not scheduler periods.

Packets remain separate by target. `DualPacket.native_bytes` contains the native
little-endian timestamp DWORD and packet payload. There is no timestamp
alignment, interpolation or conversion between ECUs. `DualRing` refuses
capacity overflow instead of silently dropping packets. `run_packets(n)` returns
packets in completion order, requiring `n` packets from every target; a native
routine stop before that goal is an explicit host failure with retained notices.

`selected_dual_cache` obtains the first frame for each selected native command.
P5 recovery uses the actual selected `DD`/`D1`/`D2` frames. Missing selected
frames fail explicitly. Dynamic setup accepts the `DynamicPlan` from the shared
packer and the selected profile's `D4` frame; it validates the read IDs/lengths
against the configured monitor. Recovery sends every clear request and, if any
clear exchange succeeds, every definition request. Command `11A(request_id, WORDLE bytes)` stores the complete ordered list of
successfully cleared slots, including slots unused by the current definitions.
`dynamic` requires that list through `11A` or its explicit `clear_ids` argument;
read IDs are not substituted. Shutdown clears this full list again. An `11A`
without definitions obtains selected D4 metadata from `NativeDualControl` or an
explicit D4 cache entry before transport startup. Statuses ignored by the original recovery helper are not
misrepresented as ECU success.

`DualActiveEvent` builds native P4 service `30` and P5 services `2F`/`31` from
selected command bodies, preserves delays and stop-item identity rules, and
implements native positive-reply state changes. The runtime retains faults and
routine/start/stop notifications separately from packets.

The optional `OscProvider` exposes native command, parameter and buffer-read
primitives. Startup/stop parameter order follows the recovered source.
`OscSetup` derives the native increment from the actual parameter-10 mode byte
using the original `SetSamplingRate` table. Its rollover/fraction arithmetic is
the native arithmetic, not a conversion invented for monitor timestamps.
Oscilloscope samples have their own ring and are not aligned with ECU packets.

Host policies bound state steps, primitive calls, elapsed time, retained bytes,
requests, packets and queues. Cancellation is checked before and after provider
calls. Native cleanup gets a fresh two-second deadline and independent primitive/byte
budgets after acquisition failure or cancellation, including an expired main
deadline. Pending starts are discarded before stop requests. Cleanup driver
timeouts are capped to its remaining deadline. A secondary failure is retained
in `cleanup_error`, preserving the original failure. Host exceptions in active-test
stop do not skip OSC shutdown or dynamic-DID clears; each independent stage uses
the same cleanup deadline and budgets. OSC final command `1` is attempted even
when its preceding stop primitive raises. The first failure remains primary and
later host failures become exception notes. These exception paths are bounded
host cleanup policy, not recovered native exception handling. Native nonzero stop/clear
statuses that the original flow ignores remain structured `cleanup_failures`
observations; they are not evidence that an ECU stopped successfully. A failed cleanup must be
resolved with `stop()` before a restart. This is a host safety policy, not a
claim about original Win32 scheduling. Blocking-I/O cancellation still depends on the injected provider's
ability to return within its timeout.

Acquisition `auxiliary_exchanges` remain intact during cleanup. The independent
`cleanup_exchanges` history retains the latest cleanup exchanges within its own
byte/item limits, with evictions counted by `cleanup_trace_dropped`;
`cleanup_failures` describes the retained failed exchanges. Diagnostic retention
cannot consume the fresh cleanup I/O budget or prevent later OSC shutdown.

The authored tests exercise literal wires, all seven states, retries, native
errors, malformed inputs, target collisions, unmatched sources, cancellation,
repeat acquisition, native ring overflow, lifecycle registration, dynamic
recovery and DstiOsc rollover. They do not establish physical behavior or an
unverified equivalence between Techstream versions. Hardware remains
`PHYSICAL_UNCONFIRMED`.

`version=12` and `version=18` select proven original differences. Version 12
rejects P5 DTC setup, has no NRC `24`/`33` synthetic routine reply, and checks
routine normal/abnormal status without version 18's active-RID filter. Version
12 checks only extended-session reply byte 3, even when the helper reports an
error; version 18 first checks status and accepts positive SID `50`. Version 12
also redefines dynamic DIDs after failed clears; version 18 requires at least
one successful clear. The
application build must be selected explicitly by the concrete control bridge;
DDB format alone does not identify that build. The legacy standalone runtime
defaults to 18, and rejects a concrete bridge selecting another build. Both
original binaries have seven outer states and seven send arguments. Version12
`SendIntNoInitNoSession` has a BYTE length, so this host implementation rejects
requests over255 bytes before sending; version18 uses a USHORT. The extended
Dual send uses a USHORT in both versions. Private static evidence records
the original hashes, export entries, switch tables and complete annotated
assembly; it does not rely on assuming same-RVA functions are equivalent.

Native thread exit selects target zero and sends its selected `D1` frame after
P5 active-test stop-kind errors or P5 shutdown send/receive/parser failures.
Version 18 additionally exposes `set_security_release(first_target_id, bool)`;
a true flag requests the same exit-session exchange. Native ignored exchange
statuses remain observable, and final driver disconnect is still attempted if
selected `D1` is unavailable or fails.

`NativeDualControl` executes the lower KGP lifecycle through the existing
`RecorderBackend.invoke` J2534 primitive contract. It requires selected profiles,
typed targets, observed driver/device/diagnostic properties, and explicit
`source_build` and `source_identity`. Pass the same object as `driver_control`;
the runtime supplies its actual deadline and cancellation context, including
the independent cleanup budget. The backend owns driver/module initialization;
the bridge owns its actual channel, returned by `connect(protocol_id=6,flags=0)`.
Importing or constructing the bridge performs no I/O.

Each target binds selected identity, management hash, category record and
exception context. A bound VehicleProfile also retains its actual ECU hash;
a management-only ProtocolProfile retains None for the absent ECU resource. The bridge checks that identity and selected application
context before and after callbacks and before reading live cleanup metadata.
A changed source prevents communication through the old context. Cleanup still
attempts to release its owned channel and reports the original source error;
it does not send a default-session request from the changed source. Nonfinite
clock samples are rejected even with an externally supplied finite deadline.

Entry selects the actual ProtInfo and CommInfoCan records, translates the native
configuration list in order, retries the first failed configuration without
parameter `2A`, creates the device4 pass filter and native flow filter, and
handles the bus22 five-byte fallback. Two targets with different relevant
configuration values cause the selected configuration to be written before
each send. The latest native ignored failures remain in bounded rolling
`observations`; full diagnostic history never prevents channel release. A failed channel
release retains ownership and raises a host error; a retry cannot silently
replace an unreleased channel.

The lower close follows the actual class pre-initialization flag, independently
of P4/P5 category. Dual constructors initialize `preinit_d1_suppressed=1`;
mode-2 sends do not clear it, so normal P4 close also sends no D1. An explicit
zero enables the selected D1 helper. P5/PSA outer close with flag0 restores
suppression before that helper; flag1 preserves its existing value. Missing
helper metadata or native status does not prevent the actual channel release.
The outer thread's independent P5 exit-session exchange still applies.

The entry parameter is the complete native DWORD stored by the registration
helper; it need not equal the selected physical or diagnostic address. Protocol
header addresses still come from selected protocol metadata.

Typed primitive host boundaries retain the actual connect, filter and successful
disconnect outcomes before cancellation/deadline is raised. A before-I/O
boundary changes no ownership. Missing confirmed message counts and unknown
backend exceptions poison the control, retaining its channel for bounded
`close_resources(deadline=..., cancelled=...)`; that operation releases only
resources and emits no session requests. A confirmed boundary can retain the
channel for a caller's explicit protocol stop. Lower transport poison propagates
to its control, preventing a later ordinary disconnect from sending D1.
`Disconnect(0/1)` also performs the native category14/15 outer session policy:
native12 directly compares service families; native18 Dual uses its virtual
family comparison, while Multi's virtual comparison always returns zero. An
incompatible family sets service10, sets request state1 in18, and reconfigures
the existing selected target before the lower close. The flag0 suppression
write is separate from the request-state transition.

`NativeDualControl(source_variant="multi")` selects the distinct native Multi
constructor and three-argument registration, using `ConnectMultiMon`. Its
tester7F metadata is mandatory even for phase20. Shared configuration and
refresh logic retain the native optional2A retry; special CAN and functional
filter cases reuse the exact lower selected-filter algorithm. The lower Multi
close uses selected58 on low-A protocols and the bus1C finish helper; it does
not substitute the Dual D1 policy. Ambiguous duplicate category keys are
rejected as a host policy even though native registration can retain them.

A control has one lower owner. Construction validates all plans before binding
that owner; a second owner is rejected, and identity checks surround callbacks.
A confirmed new channel generation resets the released lower object to its
native constructor state before adopting the new borrowed lease, preserving
host logging and cancellation bindings.

The private actual-input harness executes18 source-bound cases across both
builds: selected25 support/cache and metadata, direct/dynamic/RID and paired
plans, typed42/43 driver chronology, complete target-cycle ring bytes and the
NativeMonitorPacketReader consumer. Native12 retains its actual direct-DID
dynamic fallback; native18 recovery and shutdown clear the full two-ID list
although only one registered ID provides payload. RID selection remains on
target0, and target streams retain separate timestamps.
