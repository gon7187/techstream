# Direct P3 J2534 monitor workers

`monitor_j2534.py` implements the native P3 base, Packet, DK KWP and
two-system Century event and worker paths over `NativeFrameOperations`.
Importing the module opens no adapter and executes no vendor code. Driver
results are explicit typed observations of actual J2534 primitives.

`selected_packet_frame_cache(communication)` binds the native cached DPID query
to an existing concrete `NativeCommunication` and its selected controller.
`NativePacketPrimitives` maps the actual `SendInt` ABI (ECU category, BYTE
request length, timer, selected bus, initialization flag, clear flag), BYTE
`Receive` capacity/argument5 and `SetJ2534InterruptMode` to the lower operations.
It borrows the owner's channel, absolute deadline, cancellation and primitive
budget; the owner closes the channel. `PacketFrameCache.from_profile` selects
the first native ComSet1 record or the native 1000/200/2 defaults. The concrete
12/18 regression runs A2, sequence wrap completion, A3 and timeout drain through
authored J2534 observations. Caller factories supply this cache to
`LegacyCheckTarget` together with `packet_ecu=profile.category` and
`packet_protocol=communication.bus_id`.
Passing `monitor_session` validates the selected application/vehicle/build and
routes the native A3-send-failure disable-list update to that shared session.

Use `monitor_legacy.selected_phase3_native_worker` for a selected base, Packet
or DK KWP producer. Use `selected_phase3_century_worker` for the two selected
Century systems. These factories bind the selected source identity, request
and response map, diagnostic address override, native A7 communication timers,
setup retry count, frame table and signal metadata. A selected plan from a
different source is rejected before transport activity.

`DirectJ2534Worker.run(count)` starts acquisition, obtains native packets,
performs the protocol stop sequence and closes its owned channel. A failed
acquisition retains its original exception while bounded cleanup attempts the
active-test stop or Packet A3 sequence. A pre-existing channel remains owned
by its caller. Clocks, absolute deadlines, step count, queued observations and
serialized packet bytes have explicit limits. The recorder byte budget includes
the four-byte timestamp of every packet.

The native controller class and communication event are distinct.
`native_worker_class="base"` retains BASE scheduling, host timestamps, error
dispatch and shutdown even with an A1/A2 packet event: variable monitor8610
constructs the BASE controller for a single device8 target. The default retains
normal P4 D850 mode-based selection of the Packet controller. Only that Packet
controller enables burst/interrupt operations, timestamped packet reception and
the A3 timeout drain. Event response grammar remains selected independently.
BASE may be constructed with no events and no I/O for native mode80. Its caller
defers `start()` until an actual active/system registration needs acquisition.

The worker composes acquisition cancellation with each owned lower operation's
existing callback and restores that callback when releasing ownership. Confirmed
host cancellation or deadline expiry permits a separate bounded protocol stop;
an uncertain backend operation remains poisoned and receives resource cleanup.

The event contracts retain native details:

- Pair requests use services 01 or 21; types 2 and 3 append 01. Short responses
  preserve the previous bytes, and no invented PID echo check is added.
- The type-6 PID-1 response has its native one-byte response header. Service 13
  appends a last-item DTC request for the pair event.
- Packet A1 validates the literal E1 descriptor echo. A2 accepts E2 data;
  cached DPID 4 emits the previous retained cycle before copying a wrapping
  frame. A3 stop and the final native empty-buffer status retain their ordering.
- Packet burst mode uses actual SET_CONFIG parameter 10400. ISO interrupt mode
  uses 10500 followed by 1000B with the selected ISO WORD at offset 52;
  clearing interrupt output uses 10501. The CAN and J1850 interrupt slots are
  native no-ops.
- Successful base/Packet reception resets the retry counter before source
  filtering, including a reply from another source. Oscillator errors retain
  their earlier separate status check.
- Packet error notices use the parsed reply event after successful reception,
  the NRC service byte for negative replies, and the selected event after send
  or generic lower failures. Receive dispatch never changes the selected slot.
  Packet faults also call `disable_packet_ecu(category)` when a shared selected
  session consumer is supplied; native E00001CC preserves its exception. The
  caller must feed that shared list into subsequent CheckStart exclusion.
- A Packet auxiliary DTC descriptor remains in the inherited native queue.
  The normal A2 cycle does not advance to it; the port does not invent a
  separate DTC sampler.
- DK KWP has its own active-test response-width behavior and direct disconnect
  on stop. It has no base-worker oscillator or version-18 receive-time-log path.
- Native active stop appends its one-byte 30 marker on each call, bounded by
  the queue budget. A command stop followed by acquisition shutdown is valid.

Century uses the native common-PID intersection and functional, physical or
mixed scheduling. Its registrations contain each system's default source,
separately from the mapped response ID. `CenturyNativeFrameOperations` emits
the native C0 functional ISO header, validates B5 and either registered source,
and implements the corresponding Century fast-initialization response check.
Physical system changes reuse a channel; switching between functional and
physical operation retains native connection boundaries.
Century retains active/system registrations across system changes; its native
acquisition loop consumes only Century data events. Registration alone does
not imply that an active/system request is sent by that loop.
An active-only registered Century entry retains `event=None`. This permits the
native all-mode80 configured/polling-no-op path without creating phantom data.
Starting acquisition with any absent registered DM event reaches a native NULL
dereference; the host exposes `NativeMonitorSourceFault` before I/O, without
inventing a DLL error code. Fully populated Century scheduling is unchanged.

`CenturyJ2534Worker.run_systems(cycles)` returns two separate native captures.
An optional `system_packet_sink(index, packet)` preserves the selected system
when writing shared monitor buffers. Each capture is consumed with that
system's selected frame table and signal metadata through the shared DRS/DM
playback path.

Original 12/18 DLL identities and static export comparisons are retained in
private evidence. The added version-18 receive-time field shifts derived object
layouts by four bytes and event virtual slots by eight bytes. Object layout
offsets and logging constants are not used as substitute wire semantics.
Broad export-to-export disassembly can include private helpers or jump-table
data; the evidence records this limitation explicitly.

Physical adapter and vehicle behavior remains `PHYSICAL_UNCONFIRMED`.
Independent source and integration review gates remain open until reviewed.
The shared base/Packet oscillator flag composes with the separate instrument
runtime. `selected_worker_oscilloscope` binds actual category999 descriptors,
selected signal metadata and source context before acquisition. The caller
must follow its native constructor route; P3 selection alone does not enable
the shared flag. Base drains samples after an accepted normal reply. Packet
performs one `DstiOscReadBuffer` with the native zero sentinel after successful
timestamped receive, checks its separate status, then publishes samples after
normal reply validation. Stop replaces the forward instrument capture with
the native reverse capture, separately from normal monitor packets. Combined
source-caller integration remains under review.

```sh
python -m unittest discover -s tests -p test_monitor_j2534.py -v
```
