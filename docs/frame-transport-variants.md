# ChangeCommIF lower protocol variants

`create_lower_transport` is the selected runtime factory. It composes injected
primitive operations without loading a driver, opening a device, or creating a
network connection. `get_comm_frame` remains the separate pure native export.
The actual observed `interface_word` is required to distinguish low8 classes.
An empty constructor seed is valid metadata for a real NULL mode0 probe: the
descriptor contains only the native header and retains the actual startup
function. It does not create or send a substitute diagnostic request.
`send(None, initialization_mode=1)` remains invalid; pure `get_comm_frame`
continues to reject empty requests.
The lower constructors and `rebind` accept the management-only `ProtocolProfile`
base. Their protocol/frame/configuration joins do not read an ECU database.
`VehicleProfile` remains a compatible subclass; protocol acquisition with an
empty ECU filename never fabricates an ECU resource.

- Low3 (original12/18) selects raw protocol5. Native virtual34 uses its actual
  category/bus argument bytes, fixed baud500000 and five configuration inputs;
  the source configuration translator retains the baud parameter. SET_CONFIG
  status is ignored. One pass filter uses mask `((~bus)&255)<<3` and pattern
  `(category&255)<<3`. This class does not join the ordinary CAN configuration or
  startup functions. Its receive override discards every nonzero RxStatus and
  returns the first zero-status frame without NRC/session validation.
- Low8 (original12/18) selects protocol5 for device2/8 with interface WORD zero,
  otherwise protocol6. Both connect with flag100. Header bytes are
  `18,TAT,target,source`; TAT is DA/CE/DB/CD for buses18/28/38/48. Raw messages
  insert a length byte. Raw bus28 reports one additional storage byte after the
  request; the port initializes it to zero and excludes it during decoding.
  Protocol6 retains bus28's extended-address byte. The two classes retain their
  separate configuration/setup behavior. RxStatus100 is accepted; other status
  bits are discarded. Raw NRC validation starts at payload offset5.
- LowC (original12/18) connects native protocol1000d but sends protocol3. It
  retains the one-byte length, `(header&63)-1` validator, ISO configuration joins,
  four-attempt IOCTL10004/10005 initialization and virtual wakeup expecting67.
  Fast-init failures wait300ms, including after the final failure. Timeout7
  becomes9. Build12's original dde0/de50/df00/df80/e000/e0b0/e1a0 bodies were
  compared directly with the original18 counterparts.
- Low6 protocol2 and low9 ISO use the source-bound shared implementation.
- Low4 exists only in original18. Original12's selector has no case4 and returns
  its native90020201; it is not assigned the newer Ethernet implementation.

All numeric native codes above and below are hexadecimal, except explicitly
named baud rates, byte counts, time units and decimal retry counts.

## Original18 low4 v0500 API

Low4 requires an actual `EthernetBackend.invoke_ethernet` implementation, in
addition to the ordinary backend interface. A missing v0500 backend is rejected
before I/O. This is the separate native v0500 export family (2170/2174/2178/217c/
2184/2188/21a4), not an ordinary J2534 connect/read emulation. The backend is
already bound to the actual opened device; no observed device-kind number is
substituted for the device handle.

Every primitive receives immutable `fields`, an absolute host `deadline`, and a
cancellation callback, and returns `J2534Result`:

| Operation | Fields and actual result |
| --- | --- |
| `physical_connect` | `protocol_id=800f`, `flags=0`, `baud_rate=100000000`, `resources=EthernetResources(1,(3,11,12,13))`; actual `handle` |
| `physical_disconnect` | `channel_id`; actual native status |
| `logical_connect` | Parent `channel_id`, `protocol_id`, `flags=0`, packed `input` bytes; actual `handle` |
| `logical_disconnect` | `channel_id`; actual native status |
| `channel_ioctl` | `channel_id`, `ioctl_id`, typed `input`, `output_capacity` |
| `device_ioctl` | `ioctl_id`, `input` bytes or `EthernetResources`, `output_capacity`; actual bounded output `data` |
| `queue_messages` | `channel_id`, tuple containing one actual `NativeMessage`, `count=1`; confirmed message `count=1` |
| `read_messages` | `channel_id`, `count=1`, native `timeout`; one actual message and message `count=1` |
| `read_bytes` | `channel_id`, `protocol_id=8208`, requested byte `count`, native `timeout`; actual `data` and actual **byte** `count` |

`EthernetResources` represents the native connector/resource array semantically;
its Python object is not a serialized C pointer. TCP byte counts must never be
reported as one fabricated message. Native messages/results stay bounded to
4128 bytes, while the assembled diagnostic result can reach65535 bytes.

The protocol record joins management table85 (12 bytes, key WORD0), then table86
(12 bytes, key WORD0). Native virtual150 loads source address and four v0500 read
timeouts. Function106 supplies the startup request. The voltage gate performs
pin8/pin16 READ_VBATT observations, native pull-up controls and the literal
`0.53 < pulled/reference <= 0.83` check. `EthernetSettings` contains the original
INI defaults or explicit observed overrides, including the Mongoose prefix
exception. No INI success or voltage value is invented.

The session sequence is physical800f, link-ready status10000, IP8203, UDP8205,
UDP discovery, TCP8206 and routing8208. IP input is exactly21 packed bytes:
version byte, little-endian DWORD timeout, sixteen zero address bytes. Native
setup status failures collapse to91020306. Successfully acquired handles remain
owned and reviewable after a native failure until cleanup confirms release.

Diagnostic sends retain source/target addresses and native request capacity.
Service1..15 chooses the functional target and response address and suppresses
C650 initialization, including forced initialization. Other services retain the
physical addresses; explicit diagnostic-info response overrides are preserved.
Receive reads the13-byte8002 acknowledgement,8-byte8001 header, then actual byte
chunks. It validates the first chunk before continuing a larger response. NRC78
skips the next acknowledgement, selects the pending timeout and retains native
180-second DWORD tick arithmetic. NRC21 requeues the original frame; the256th
busy reply returns90020323. Native timeouts16 become9. Logging contains actual
application payloads, not link/discovery traffic.

`send_function` retains virtual50's ignored native send/receive statuses and
clears the D1-suppression flag after its exchange. `pre_initialize`/clean close
perform the selected D1 exchange only when that flag is zero. Cleanup releases
TCP, UDP, IP, then physical Ethernet. Host cancellation/deadline outcomes remain
exceptions, separate from native statuses. Handles returned before an after-I/O
host boundary are recorded before cancellation is raised. Before-I/O cleanup
boundaries never release unperformed operations. Unlike native's unconditional
handle clearing, failed host cleanup retains a child and its parents for retry;
clock failure uses a separate bounded cleanup clock.

`session_state` implements virtual14c/8970 as the actual TCP IOCTL8023 with a
four-byte output. It returns `(native_status, actual_state)`, retaining the
native zero-initialized state when an error writes no output. An absent TCP
handle returns `(0,0)` without I/O. `release_channels` implements virtual158/8800
without D1. ChangeCommIF's state-not2 branch stops its tester, releases channels,
rebinds the selected protocol/table85/table86 metadata, then calls `open` again.
The ordinary clean `close` continues to perform its selected D1 exchange.

## Verification and acceptance

Original12 constructor routing and the low3/low8/lowC override bodies were read
from that build's own cached C/ASM and independently extracted static bytes.
Inherited low6/low9/CAN behavior remains bound to the shared43 implementation and
review. Source-method mappings and hashes are recorded in
`analysis/evidence/no-car-107/implementation-review.json`. Consumer77/79 review
must bind the final source hashes before G3 closes. Physical adapter and vehicle
behavior remains `PHYSICAL_UNCONFIRMED`.

```sh
python -m unittest discover -s tests -p test_frame_transport_variants.py -v
```
