# Flag9 CAN packet monitor

`scripts/monitor_packet_a8.py` implements the distinct original12/18
`DataMonitorPhase4` data-list provider constructed by `FUN3360` for selected
category flags whose low five bits are9 and observed protocol low nibble2/8.
It does not call the normal phase4/6 `pack_p4` producer.

`selected_packet_a8_from_cache` consumes the caller's existing operation budget
and cache without resetting its deadline. `selected_packet_a8_from_exchange`
constructs that cache and delegates to the same implementation. It runs the actual selected
`CreateEnablePidListExt` support operation through `MonitorSupportCache`.
Despite the flag9 provider's short name, this native call is **not** the
separate `CreateEnablePidListA8` helper. Fixed-packet fallback uses the concrete
`PacketFrameCache` A2/04 → E2 → A3 transaction and requires the same selected
source identity. Mode1 success does not issue a packet-cache query.

The selected producer joins actual Freeze84/DB206 rows, native supported PID
lengths, shared composite layouts and named signal metadata. Its own result
contains source build12/18, selection identity, frame sizes, pickup spans,
packing decisions, original attempt codes and concrete DMCI commands. Shared
P3 low-level packing primitives are reused only for the independently recovered
matching algorithms: ascending PID A1/01 plus FF fillers, cached A1/04 frame
partitioning and ordered pair descriptors. The selected provider and runtime
remain distinct types.

The P4 wrapper's supported setup modes are preserved literally. Mode1 generates
109 setup with A1/01, timeout3000, 10C start and 10E stop. Modes10/20 generate
10A with data types0 and1/6 respectively, retry count3 and parameter8 FFFFFFFF.
The native data-list object can produce mode2 or100, but the recovered P4
controller's setup switch rejects them with C005100D. The vtable mode getter
returns the selected mode directly; the implementation preserves this failure
rather than translating it into a different successful mode.

`PacketA8Event` implements the separate `CCommEventPacketDMP4` single-descriptor
A1/A2/A3 path. An E2/01 payload must have exactly the selected raw length;
E2/06 may contain additional bytes. Other E2 identifiers fail E0000104.
This differs from PacketDMP3's sequence-based E2 grammar. Shared packet-base
acknowledgment, scheduling, shutdown, queue budgets and resource ownership are
provided by the existing typed direct worker. Pickup uses the independently recovered PacketDMBase bit-copy algorithm: it
reloads the source byte on crossings and treats an original offset-1 as zero
fill. This differs from the normal P4 event's mutable-copy quirks. The native
zeroed timestamp prefix remains0; receive time is passed separately to the
packet writer. The paired two-descriptor normal phase4 producer remains with
its own owner.

`selected_packet_a8_worker` binds this event to selected
`NativeFrameOperations` and the concrete J2534 worker. Pair modes10/20 are
accepted by `NormalPollingWorker`. `packet_a8_can_lifecycle` and
`run_packet_a8_dmci` provide the actual device4 CAN101/phase1 DM107/111/114
lifecycle, packet polling and10E/108/104 cleanup. GetMonitorData uses the
registered monitor-buffer category (`setup109/10A` argument0), independently
of the CAN request address in argument1. Both original builds are checked on
the actual request bytes and reject replies keyed by the CAN request address. Source12 requires selected
ProtInfo24; source18 requires ProtInfo28. Device8 direct and device4 DMCI remain
explicit choices; device8 with an observed non-null recording writer follows
the same CAN DMCI constructor branch, selected explicitly with `recording=True`. All I/O is injected and no device is opened by import.

The authored tests cover original12/18 selected inputs, actual support request
bytes, mode fallbacks/errors, malformed packet lengths, P4 pickup behavior,
source/cache mismatches, cancellation, concrete J2534 positive/fault cleanup,
and actual DMCI serialized requests through packet consumption and cleanup.

The direct factory also accepts the distinct `ExtendedCanOperations` lower
class for low-nibble8. It validates the selected `lower_frame_plan`, including
raw protocol5 and wrapped protocol6, while requiring the actual extended CAN
class. The pure GetCommFrame export continues to reject low8. Authored tests
exercise both original12/18 builds through each lower class, successful packet
consumption and fault cleanup; build12 lower-body equivalence remains under
the lower transport owner's independent review.

Burst receive timestamps follow original12 runtime `1ae0` and original18
`1d50`: J2534 microseconds are converted to milliseconds with the native
uint32 wrap accumulator before reaching the packet writer. The selected direct
consumer tests include0/999/1000/1234/1234999 microseconds. The packet's zeroed
internal timestamp prefix is independent of this receive timestamp.

Acceptance remains OPEN pending independent source review and root
normal-router composition. Auxiliary trigger descriptors use the recovered DB213/112/111 joins, force the
native pair fallback and append their actual request and frame layout. The
controller parses the descriptor list in order; later1/21 or41/61 descriptors
overwrite their corresponding pair fields. A13 descriptor fails C005100E.
This uncommon path remains subject to independent source review. No car, adapter, OEM code
execution or live support observations were used. Hardware is
`PHYSICAL_UNCONFIRMED`.
