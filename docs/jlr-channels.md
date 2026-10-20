# Offline JLR raw CAN channels

Status: **PHYSICAL_UNCONFIRMED**. This is an authored implementation tested with
synthetic USB exchanges. No adapter or vehicle was connected during validation.
A printed “Mongoose JLR Pro / SDD V168” label does not establish USB identity,
firmware, supported channels, or Toyota compatibility.

`scripts/jlr_channels.py` builds on the identity probe in `scripts/jlr.py`.
Importing or constructing a session performs no I/O. There is no default physical
transport, command-line send action, or GUI send action. An integrating caller
must inject a transport and explicitly call `open()`.

## Integration contract

1. Obtain a successful device1 Board109 payload using
   `client.transact(1, 0x109)`. `can_routes(payload)` requires exactly 180 bytes,
   source 1 / destination 0 / opcode 0x8109 and status 0. It returns immutable `CANRoute`
   values for the recovered default raw-CAN capability of board types 1..11.
   Other types produce no route. Multiple advertised slots require an explicit
   caller selection; the module never silently chooses the first one.
2. Construct `CANSession(client, payload, route, baud, receive_id,
   extended=False)`. The route must exactly match the supplied board response.
   Supported IDs are Classical CAN 11-bit or 29-bit, with zero to eight data
   bytes. This validates the reported board layout; it does not authenticate
   clone hardware, firmware state, vehicle wiring, or the allowed bus baud.
3. Call `open()` once, on a control thread. It opens device1, connects the
   capability-derived CAN channel, enables its pins, installs an exact pass
   filter for `receive_id`, and starts a receive thread. Each session exclusively
   owns its `JLRClient`. Do not perform other transactions or operate the
   transport directly while the session is active. Serialize control operations
   (`open`, `submit_frame`, `close`) in the integrating application.
4. `submit_frame(can_id, data, timeout_ms=1000)` returns `Submission`, containing
   target, sequence, remaining-count 1, adapter acknowledgement and a monotonic
   observation deadline. Acknowledgements 0 and 0x101 are accepted. Neither means
   ECU delivery or successful transmission. Unknown/error acknowledgement codes
   stop further submissions and raise an error.
5. Drain `events()` regularly. It returns a tuple of `CANFrame`, neutral
   `TxEvent`, local `TxTimeout`, and unclassified payload bytes. `CANFrame`
   preserves raw status and device timestamp; no timestamp unit is invented.
   `TxEvent` preserves unknown suffix bytes. `Submission.correlates(event)` checks
   source, sequence and remaining count, never status or delivery. A matching
   status 0x106 releases the pending observation slot as a loopback notification;
   status 0x10a and all other statuses remain raw and do not complete it. The
   timeout is local host policy, not a recovered firmware timer.
6. Always call `close()` in `finally`, then close the owned USB transport in an
   outer `finally`. `close()` stops and joins the receive thread, removes the
   owned filter, disables pins, disconnects and closes the protocol device.
   USB vendor 0xdb / value 0 and interface release remain `USBTransport.close()`'s
   responsibility. Closing discards pending observations; it does not promise
   cancellation of a frame already accepted by hardware.

Conceptual call order, using an **already injected** client:

```python
board_reply = client.transact(1, 0x109)
routes = can_routes(board_reply)
# Application/user explicitly selects an advertised route and vehicle parameters.
session = CANSession(client, board_reply, selected_route, baud, receive_id)
try:
    session.open()
    # Explicit application action may call submit_frame; drain events while idle.
finally:
    session.close()
# The outer transport owner still closes its USB transport, even on cleanup error.
```

## Host ISO-TP exchange adapter

`ISOTPExchange({ecu_name: (raw_session, Peer(...))}).exchange` connects the
existing host `Sender` and `Receiver` to the raw channel and can be injected into
`diagnostics.Session`. Its constructor does not open a channel. The caller must
explicitly open the configured `CANSession` first and retain ownership of its
cleanup. There is no automatic USB discovery or physical GUI action.

```python
peer = Peer(tx_id=0x7E0, rx_id=0x7E8)  # Illustrative, not discovered ECU IDs.
pump = ISOTPExchange({"engine": (raw_session, peer)}, cancelled=cancel.is_set)
diagnostic_session = Session(pump.exchange)
# Explicitly requested application reads now traverse the host CAN/ISO pump.
```

The ECU map is explicit, bounded to 64 entries and copied on construction. Each
peer's receive ID and 11-/29-bit format must match the raw channel's exact filter.
Normal and extended addressing are supported through `Peer`, with both address
bytes required together. Firmware ISO targets are rejected: host-generated flow
control goes only through the raw CAN target. Firmware ISO channels already
perform their own segmentation and flow control.

Every emitted SF, FF, CF and FC must receive a matching source/sequence/count
raw `0x106` loopback notification before another frame can be submitted. A
complete ECU response received before that notification remains buffered and
cannot produce a successful return. Matching unknown TX statuses, including
`0x10a`, abort instead of being interpreted as completion. This is a deliberately
conservative **host observation policy**; the loopback is not a proven firmware
TxDone or ECU-delivery guarantee. Real notification ordering remains unverified.

The pump routes peer PCI3 frames into `Sender.flow`, peer PCI0/1/2 into
`Receiver.feed`, submits generated FC frames, and ticks both machines while idle.
It supports bounded 1..4095-byte PDUs, subject to the raw session's cumulative
write-sequence ceiling. It enforces STmin conservatively from the time the matching raw `0x106`
loopback is consumed, accounting for both blocking USB submission and a delayed
device send after USB acknowledgement. Python scheduling
and the USB receive thread cannot promise submillisecond physical timing.

Defaults are a five-second overall exchange deadline, a one-second frame/progress
bound, a 4096-event budget, receiver BS0/STmin0, no padding and the Sender's finite
WAIT limit. These are native host policy, not reconstructed legacy firmware
configuration. Caller-supplied monotonic clock/sleep functions make synthetic
tests deterministic. Cancellation, queue-budget exhaustion, malformed input,
unsupported raw RX status, submit failure and timeout close the selected channel
and reset both ISO machines. The outer owner still closes USB even if protocol
cleanup fails. One exchange runs at a time; successful channels remain open for
subsequent explicitly requested reads.

Application service/reply validation remains in `diagnostics.Session`. The generic
ISO adapter itself transports PDUs and does not turn arbitrary requests into
read-only requests. Pre-submission peer data is rejected as stale; ISO-TP has no
application transaction ID, so application correlation is still required.

## Bounded operation and failure behavior

The receive thread shares the client's transport lock with transactions, so only
one reader can consume the stream. It reads while no command is pending as well
as between submissions. Reads are at most 25 ms; transaction read slices are at
most 50 ms. Commands have a 0.5 second response deadline, cleanup attempts every
applicable step, and cancellation stops ordinary operations without suppressing
cleanup. The injected transport must honor read timeouts and reject short writes.
The libusb backend has its own bounded one-second write timeout; these bounds
are not hard realtime scheduling guarantees.

Channel events default to 256 entries (configurable 1..1024), pending observations
to 32 (1..255), client unsolicited payloads to 1024, and each stream chunk to 64 KiB.
Queue overflow, malformed channel events and read errors fail the receive worker,
stop submissions and surface through `events()` after retained notifications have
been drained. The caller must then close the session and transport. No event loss
is silently reported as a successful session.

Write sequence values are not reused within a session. The session rejects a
write if its next sequence was previously used for a write (at most 255 writes).
This conservative host policy prevents late notifications from being mistaken
for a new submission. Closing/reopening is not proof that hardware flushed old
notifications: physical reconnect/queue-drain semantics still require validation.

Each lifecycle attempt is recorded before sending. If a reply is lost, cleanup
still attempts the corresponding undo. A lost filter ID invokes ClearFilters
mode 0 on this newly owned channel. Zero is a valid hardware filter ID. Cleanup
failures are aggregated in `ExceptionGroup`; a failed cleanup keeps the client
reserved even if `close()` is called again. Dispose of that client and close its
transport instead of reusing uncertain device state. Worker shutdown beyond the
one-second join bound raises; the transport owner still must close its backend.

## Static evidence

The wire facts below were recovered from `monpj432.dll` v1.1.16.0, SHA-256
`2710726fdd174f32b5e703e310cfce047a663451edbb3e35ca0c8eeff6929413`.
Addresses are VA in that artifact, not runtime observations. This document and
source contain authored descriptions/constants, not vendor code or decompiler
output.

| Behavior | Evidence location |
| --- | --- |
| Board109: eight 20-byte records at reply+20 | `0x1003f160` |
| Capability table and its consumers | table `0x100807d8`, consumers `0x1003f9c0`, `0x1003d5d0` |
| Default raw CAN requirements: family 0, variant 0, kind 1, pins 6/14 | requirement row `0x10080760` |
| Selected target is slot mask OR address-byte shifted 8 | `0x1003e710` |
| Raw CAN constructor / Connect 6 / PinControl 0x12 | `0x10018190`, `0x1000b320` |
| Device Open 3 / Close 5 | `0x1003ea00`, `0x1003fb90` |
| Write 8 acknowledgement 0x101, count field and event dispatch | `0x10043610` |
| Raw RX 9 and TX 0x0a handling / sequence-and-count loopback lookup | `0x1000bcb0` |
| Status0x10a uses a distinct lookup, not generic completion | `0x10018100`, `0x1000ba90` |

The default raw-CAN rows for board types 1..11 all report address-byte 5 and
resource 1 with pins 6/14. Therefore slot mask 1 yields target 0x0501, mask 2 yields
0x0502, and mask 128 yields 0x0580. Literal target 5 is rejected. This intentionally
omits pin-override protocols and other resource families instead of shipping the
entire extracted vendor capability table.

SLP request header is six little-endian u16 values: destination, source 0,
opcode, sequence 1..255, remaining count, zero alignment. Raw CAN Write 8 body is
`<IIHH>(flags, timeout_ms, DataSize, ExtraDataIndex=0)` followed by a four-byte
**big-endian** CAN ID and data. Raw RX 9 carries `<IIHH>` at+12 for status,
timestamp, unknown and DataSize, then CAN bytes at+24. PassFilter 0x0d carries
`<IHBB>(mode 0, flags, 1, 4)` then four mask bytes and four pattern bytes; filter ID
is u32 at reply+20. StopFilter 0x0e carries `<II>(mode 0, hardwareID)`.

## Runnable regression checks

```sh
python -m unittest discover -s tests -p 'test_jlr*.py' -v
ruff check scripts/jlr.py scripts/jlr_channels.py tests/test_jlr_channels.py
pyright scripts/jlr.py scripts/jlr_channels.py tests/test_jlr_channels.py
```

Synthetic tests cover board-slot selection/rejection, exact open/filter/write/
close packets, ambiguous partial-open cleanup, filter ID 0, cancellation, cleanup
aggregation, exclusive ownership, continuous idle RX, interleaved acknowledgement
and TX event, full source/sequence/count correlation, pending 0x101, local timeout,
sequence-reuse rejection, queue bounds, malformed RX and stopped senders. Existing
USB identity tests cover fragmentation, stream resynchronization, descriptors,
short writes and USB backend cleanup. Additional deterministic tests connect the
actual ISO Sender/Receiver in both directions with 11-/29-bit IDs, normal/extended
addressing, multiframe requests/replies, block boundaries and STmin, including a
blocking raw submission and a deferred device send after USB acknowledgement.
A synthetic USB integration check also carries a VIN
read through the actual `CANSession`, `JLRClient`, SLP codec and receive thread.
They exercise `diagnostics.Session` through the pump,
missing loopback despite an ECU response, unknown TX status, cancellation, stale
input, event limits and cleanup. These prove offline behavior only.
