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
   values for the recovered raw-CAN capabilities of board types 1..11, including
   advertised alternate pins.
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
to 32 (1..255), client unsolicited payloads to 1024, and each decoder input chunk
to 65539 bytes (the uint16 payload-format bound plus its four-byte header).
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
0x0502, and mask 128 yields 0x0580. Literal target 5 is rejected. The route list also includes the recovered pin-select pairs on applicable boards;
other resource families use their own explicit protocol route selectors.

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

## Firmware ISO and K-line channels

The same explicit injected-client lifecycle now supports `FirmwareISOSession`
and `KLineSession`. No additional USB device is opened. Each session retains
exclusive ownership of its client; the existing bounded receive worker, partial
open cleanup, event budget, error propagation and transport-owner cleanup rules
apply to these protocols too.

`protocol_routes(board_reply, protocol)` accepts 3 (ISO9141), 4 (ISO14230) or 6
(ISO15765). It returns all advertised pin/resource/address alternatives, with
standard pins first, rather than choosing a route. The 81 relevant routes across
board types 1..11 were reconciled against the original capability records.
K-line-only routes use Connect flag `0x1000`; pin 15 can select a distinct channel
address, and ISO pins 3/11 or 12/13 select address byte 22 on supported boards.
Slots remain bit masks. This is capability routing, not board authentication or
proof of electrically safe vehicle wiring. The session's exclusive ownership
prevents concurrent resource allocation within one client; separate clients or
independently opened handles are not a supported concurrency model.

Construct `FirmwareISOSession(client, board_reply, selected_route, baud, peer)`
with the existing `isotp.Peer`. `open()` installs a firmware FLOW_CONTROL_FILTER;
`submit_pdu(bytes)` sends a complete PDU, including the peer's CAN ID/address
metadata, in one Write8. It never generates host TX CF or FC frames.
`FirmwareISOExchange({"engine": channel}).exchange` is an application exchange
callback for an explicitly opened session. It receives RX9 segments and uses the
host receiver to reassemble them, **discarding generated FC** because firmware
owns FC. Firmware TX segment reports `0x10e/0x10f` and `0x10a` remain neutral;
no report is advertised as whole-PDU completion. A complete ECU response is the
exchange success condition after an accepted submission. Application service
correlation remains the caller's responsibility.

The firmware filter follows the observed 19-byte body literally:
`<II>(2, flags) + mask.Data[0] + pattern.Data padded to5 + flow.Data padded to5`.
EA uses TxFlag `0x80`; 29-bit CAN uses `0x100`. Received-peer and outgoing-flow
identities keep their original direction. Cleanup uses filter mode 2, including
the ambiguous lost-filter-ID case. The native mixed serializer selects the
protocol-specific target while preserving the generic Write8 body; it does not
prefix PCI bytes to the submitted whole PDU.

Construct `KLineSession(client, board_reply, selected_route, baud=10400)` for
ISO9141/ISO14230. `open()` sends the recovered literal initial SetValue
`(firmware_parameter=0x47,value=1)` after Connect/pin enable. It does not run an
initialization handshake or start periodics. `submit_data(bytes, flags=0)` accepts
complete K-line message bytes (maximum 4128), with optional native TX
`CHECKSUM_DISABLED=0x200`. Flags remain firmware flags. Firmware checksum handling
and byte timing are not reproduced by Python sleeps.

K-line RX distinguishes the body u16 at +8 (wire byte count) and +10 (returned
message length / checksum offset). `DataFrame.data` excludes the checksum;
`DataFrame.extra_data` preserves it. Explicit ConnectFlags can disable firmware checksums (`0x200`) or retain
sniff-mode checksum errors as status `0x40000000` (`0x10000000`). The default
checksum policy checks an 8-bit additive checksum; the recovered checksum-mode parameter 0x20 value 1
checks the low seven bits. Malformed sizes and checksum failures stop the worker
and remain observable. This conservative error policy differs from the DLL's
optional sniff/discard behavior; the native API does not silently drop corruption.
The generic data decoder preserves bounded trailing metadata, but the supported
K-line session requires exactly one checksum byte. KW82 is a separate protocol.

`KLineExchange({ecu: (channel, encode, decode)}).exchange` accepts explicit
application framing callbacks. `encode(request)` returns transmitted message
bytes; `decode(message)` returns the correlated PDU, or `None` for an unrelated
message. It requires an opened channel and has cancellation, a finite response
deadline and a finite event budget. It rejects stale queued input and receive
errors, and closes the selected channel on failure. A decoded response retires
that submission's local observation entry; this is not a separate TxDone claim.
For addressed ISO14230, `kwp_message(target,source,pdu,functional=False)` builds
short or long headers, while `kwp_payload(message,target=...,source=...)` checks
length/address correlation and extracts the PDU. These functions handle 1..255
PDU bytes; complete raw K-line messages remain available for other formats.
ISO9141 applications can inject their explicit three-byte header mapping.

### Explicit control operations

- `five_baud_init(address=0x33)` sends mode0/address through opcode `0x11`.
  It returns both keyword bytes only after a complete successful response.
  Missing address/sync/keyword bytes, invalid sync and statuses `0x208/0x209`
  fail explicitly. The host uses a ten-second deadline; it does not synthesize
  the 5-baud waveform. Extra returned bytes remain in the transport reply.
- `fast_init(message,expect_reply=True)` follows the original cISOSerial gate for
  ISO9141/ISO14230. Its body is
  `<IIIIHH>(1,expect_reply,0,8000,DataSize,0)+message`; the original's unspecified
  padding is zeroed. A requested response uses the native reply's embedded
  RX body at +20 and the same count/checksum validation. Initialization is never
  triggered automatically by an ordinary application request.
- `get_value` / `set_value` use **firmware** IDs. `get_config` / `set_config`
  map the recovered K-line J2534 IDs to firmware IDs, including different
  ISO9141/ISO14230 parameter overrides. Unknown J2534 IDs fail locally.
  Host loopback configuration is not exposed as a misleading firmware parameter:
  neutral TX events remain available for the integrating caller to interpret.
- `start_message_filter(mask,pattern,block=False)` installs an additional owned
  pass/block filter; stop accepts only owned IDs/modes. Filter bounds are finite.
  Cleanup clears every attempted additional filter mode, even after a lost ID.
  The firmware ISO session accepts its explicitly configured peer flow filter.
- `start_periodic(data,interval_ms)`, `stop_periodic(id)` and
  `clear_periodics()` expose K-line firmware mode4 records. They never run on
  open. The host bounds the interval to 5..65535 ms, data to the native 1..12 bytes and
  owned records to ten. These are explicit bounds, not a timing guarantee.
- `start_repeat(data,mask,pattern,interval_ms,matches=1,flags=0)`, query, stop
  and clear expose K-line mode5 records. TX/mask/pattern are 1..12 bytes; mask
  and pattern sizes agree. Query emits zero in the original's uninitialized
  middle DWORD. The original repeat serializer copies mask at `len(mask)` and
  pattern at `len(mask)+len(pattern)`, rather than using TX length. The pure
  `repeat_body` helper preserves these unusual offsets, truncates to the declared
  payload length and zeroes otherwise unspecified gaps. Unequal TX/filter lengths
  therefore remain a **literal codec**, not a proven useful physical repeat.
- `clear_tx` / `clear_rx` send opcode `0x11`, modes2/3. An acknowledgement does
  not prove that already transmitted bytes were cancelled. Cleanup clears all
  attempted periodic/repeat groups before disconnect, including ambiguous starts.

Native firmware TX, initialization waveform timing, actual voltage, hardware
filter behavior, hot unplug delivery and ECU responses remain
**PHYSICAL_UNCONFIRMED**. No firmware update/reset/detach/programming voltage
operation is added to this channel API.

### Additional static anchors and offline checks

| Contract | Original DLL VA |
| --- | --- |
| K-line constructor, flags and initial parameter | `0x100289b0` |
| K-line J2534 configuration mapping | `0x10029930`, `0x10029d30`, `0x1002b030`, `0x1002b890` |
| K-line 5-baud / fast init | `0x1002a700`, `0x1002a450` |
| ISO9141 / ISO14230 checksum consumers | `0x1002b4c0`, `0x1002c6d0` |
| ISO14230 header-length computation | `0x1002ba50` |
| Firmware ISO mixed Write8 serializer | `0x10025b40`, `0x1006e3b0`, `0x1006b120` |
| Periodic start/stop/clear | `0x1000d220`, `0x1000d3c0`, `0x1000d4d0` |
| Repeat start/stop/query/clear | `0x1000d5d0`, `0x1000d7d0`, `0x1000d8e0`, `0x1000d9f0` |
| Clear TX / RX | `0x1000daf0`, `0x1000dbf0` |
| J2534 export IOCTL dispatcher | `0x10059d90` |

Public tests exercise real SLP framing, `JLRClient`, session lifecycle and RX
thread through synthetic USB. They cover 4095-byte firmware ISO reception,
whole-PDU writes with no duplicate FC, K-line keyword/fast init/config/checksum,
periodic/repeat/filter control, alternative pins, malformed replies, partial
bulk reads, cancellation, timeout and simulated hot unplug. Private evidence and
original-table corpus reconciliation are retained outside the public source tree.

## Complete admitted family inventory for this JLR artifact

The original `PassThruConnect` at `0x100525d0` calls requirement lookup
`0x1003cda0` **before** its generic constructor factory. Lookup failure raises
“Unknown or unsupported protocol”. The exact eleven admitted IDs are:
`2,3,4,5,6,0x8001,0x8002,0x8003,0x8004,0x8005,0x800a`.
Thus generic J1850VPW/SCI/SW-CAN/Honda/J1939/J1708 factory code and unrelated
capability records in this shared DLL do not establish support by this artifact.
They are rejected by its original software gate, rather than deferred to a car.

`protocol_routes` also accepts PWM2, raw CAN5, UART-echo `0x800a` and aliases
`0x8001..0x8005`; aliases return the corresponding canonical family route.
Raw CAN's `can_routes` now includes its alternate pin pairs too. All 108 relevant
capability rows, across six families and eleven board types, match the private
original-table reconciliation. Route enumeration includes the pin-select
alternatives and still requires explicit selection by the caller.

`ByteSession(client,board_reply,route,baud)` implements the remaining admitted
PWM and UART-echo families through the same injected lifecycle and receive
worker. PWM is advertised on board types 3/5/9, pins2/10, target address byte2;
TX requires 3..10 bytes and Data[2] must equal the node address (default `0xf0`).
`set_node_address(value)` sends firmware parameter5 and updates that validation.
UART echo is advertised on seven board types, pin7/0, target address byte13;
TX requires 4..256 bytes. Byte-channel RX preserves status, timestamp and any
bounded trailing native metadata instead of coercing these messages into CAN.
Firmware owns PWM CRC and UART echo timing; injected application decoders own
message interpretation/correlation. `KLineExchange` accepts `ByteSession` as
well. The byte-session baud policy admits the original extended-mode range
5..500000; the original strict-mode preferred PWM values are 41600/83300 and
UART values 9600/10400. No claim of physically working arbitrary baud is made.

Native periodics are available on raw CAN and PWM too. Raw CAN periodic input
includes its four-byte ID. Firmware ISO periodic input is restricted to a
single-frame PDU and is sent with ID/address metadata to its native ISO target,
without host PCI bytes. The original validator `0x10020660` limits total data to
11 bytes (ID4 plus PDU7, or ID4/EA1/PDU6); selector `0x10023540` uses the ISO
address for an ISO message. The owned timer group is stopped or cleared on that
same address. Multiframe ISO periodics are rejected by the recovered limit.
UART-echo periodics fail locally because its original handler `0x1001c290`
explicitly rejects them. No fake periodic success is returned for that family.

Additional anchors: PWM constructors `0x1002f330/0x1002f650`, validation
`0x10030180` and RX `0x10030360`; UART constructor `0x1001acb0`, TX bounds
`0x1001c240` and RX validator `0x1001c510`. The UART ID is `0x800a`
(`UART_ECHO_BYTE_PS`), not J2610 (`0x8006`, rejected by the requirement gate).

Programming-output recovery is available as **I/O-free plans only**:
`voltage_routes(board_reply,ground=False)` enumerates reported output pins;
`voltage_commands(board_reply,selected_route,millivolts)` returns immutable
`WireCommand` records and never sends them. A programmable level is 5000..20000
mV; `None` disables an already-owned output. Enable orders device1 SetValue
`(1,millivolts)` before capability-target PinControl; disable reverses those
steps and sets level0. Ground routes have their own address byte `0x81` and
accept0/None. A consuming simulator/controller must supply device/pin ownership;
the plan cannot establish free physical pins. No programming-voltage output is
executed or added to the UI. Original anchors: `PassThruSetProgrammingVoltage`
`0x10057fe0`, PinControl `0x1003fc80`, SetVPP `0x10040080`.

PWM functional lookup operations are also implemented:
`ByteSession.update_functional_lookup(addresses,remove=False)` sends one native
mode3 add/delete per address byte, and `clear_functional_lookup()` clears mode3.
A started update records the group before I/O so cleanup also clears it after an
ambiguous failure. These operations reject UART echo. Exact instruction anchors
are `0x100303d0`, `0x10030510`, `0x10030630`; add/delete bodies are
`<II>(3,address)` with opcodes `0x0d/0x0e`, and clear is opcode `0x10` / mode3.
The original ISO TX status `0x10c` is explicitly ignored by `0x1001f6c0`; the
firmware exchange preserves that behavior instead of aborting a valid response.
