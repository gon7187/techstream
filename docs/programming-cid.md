# Modern calibration ID discovery

`scripts.programming_cid` implements the modern Unified CAN and Ethernet
`StartGetCID` control flow as Python over explicit injected providers. It never
loads a vendor DLL, opens an adapter, creates a socket or selects a vehicle.
Physical behavior is **PHYSICAL_UNCONFIRMED**.

`get_cids(action, exchange, nodes, *, family, mode, receive_timeout_ms, ...)`
requires resolved `CIDNode` records. `version=18` preserves current callers;
pass `version=12` when the selected source library is CUW12. Source catalog
integration must select the verified version explicitly. Each record contains immutable request and
response diagnostic IDs, an extended-addressing flag and a reset wake time. `family` is `unified` or `ethernet`; native mode 1 checks
reprogramming compatibility and mode 2 reads additional identity data in CUW18.
CUW12's Unified getter only reads software IDs in either host mode: it has no
compatibility, additional identity, charge-bus or FCM helper phases. Its result
sets `compatibility_evaluated=False` and `compatible=None`. CUW12 contains no
Ethernet getter; selecting that nonexistent family/version pair, or passing
CUW12 charge-bus configuration, fails before I/O.
`receive_timeout_ms` comes from the host's resolved parameter configuration.
`ChargeBus` describes the optional Unified local-bus controller and its power-on
wait. The host resolves calibration CPU-image/node associations before calling;
`wake_ms` must include the applicable CPU-image wake requirement.

| Operation | Implemented behavior |
| --- | --- |
| Entry/exit | Connect protocol 6 / 0x800F; save timeout; set configured timeout; wait maximum node wake; restore timeout and disconnect on exit |
| Unified addressing | Acquire/release flow filter per node; extended-addressing BS policy enabled for the node and restored afterward |
| Ethernet communication | Actual link check, link-up, UDP discovery, routing activation and logical-channel cleanup; addressed responses and DoIP framing through `NativeEthernetChannel` |
| Software IDs | `22 F1 81`, `62 F1 81`, count plus sixteen-byte records; strict complete count/length; skip empty records |
| Compatibility | Any software ID containing `!` enables the native fast path; otherwise `31 01 10 00` support bitmap selects RoB 01/11/21/31 (minimum seven bytes for Unified bitmap reads, native thirty-six bytes for Ethernet); `AB`/`EB` results are scanned in DID pairs for F021/F022 |
| Mode 2 | Slave CID `22 01 28`, assembly `22 01 05`, serial `22 F1 8C`, CBest `22 02 10`; common native decoders retain ASCII/NUL, assembly leading-NUL and hex truncation behavior |
| Local bus | Controller extended session; sync periodic `3E 80` (2000/100/1/1000); power-on `31 01 11 7E`; configured wait; power-off `31 02 11 7E`, stop periodic and default session during cleanup |
| FCM / ADS SWIN | Only FCM 0792/079A or ADS 0100; additional wait to the recovered 5000 ms wake threshold; `22 1F FF`; thirty-byte ASCII/NUL result; FCM owns its own filter |
| Native allowed timeout | Only explicit native transport code 9 or 16 and exact configured request ID; never swallow a host deadline or cancellation |
| Pending response | Matched `7F <SID> 78` continues receive-only through the shared channel; no request retransmission |

The `action(event, remaining_seconds)` provider must perform the requested host operation
or raise. `get_timeout` returns the previous unsigned integer timeout.
`start_filter` and `start_periodic` return an owned non-`None` token; corresponding
stop operations receive that token. Other operations are `connect`, `disconnect`,
`set_timeout`, `wait`, and `set_bs_to_ecu`.
Ethernet also uses `control_io`, `logical_connect`, `logical_disconnect`,
`logical_connect_udp_discovery`, `logical_disconnect_udp_discovery`,
`queue_messages`, `read_messages`, and `read_tcp_message`. Link status must be an
unsigned integer; reads return bounded native J2534 payload bytes. Discovery
provides the peer IPv4 bytes used by logical channel 8206. Routing activation
requires the native nine-byte result with byte 4 equal to 10 hex.
`wait` actually waits or advances the replay clock. Acknowledging an event
without performing it does not implement a transport. Setup exceptions
must leave their own incomplete resource acquisition rolled back. Cleanup tries
all acquired resources even when another cleanup fails. Cleanup exchanges get a
fresh bounded timeout and deliberately ignore cancellation so bus power and
session restoration can be attempted.

`exchange(ecu, request)` and optional `receive(ecu)` follow the shared native
channel contract. Unified requests are UDS payloads, with `ecu` the resolved
request ID in hex. The provider binds that ID and extended addressing to its
transport. Ethernet writes are full diagnostic TCP frames; reads contain source
address, tester address and UDS, as returned by native J2534 reads. The shared
Ethernet channel rejects malformed framing and filters unrelated addresses with
bounded receive-only operations.

Returned records expose identity data, compatibility and explicitly allowed
native timeouts. Slave/assembly/serial/CBest/SWIN native transport or negative-response
failures produce an empty field (list for slave CID) plus structured `optional_errors`; malformed
responses, host errors, cancellation and deadline failures propagate. No result
implies authorization to program or that an adapter/car was present. Providers
must enforce the supplied remaining time while blocked in I/O; Python cannot interrupt
an arbitrary blocking callback.

Run `python -m unittest discover -s tests -p test_programming_cid.py -v` for the
synthetic full-flow and fault-injection checks. They cover both families/modes,
resource restoration, each successful lifecycle and wire operation failing,
strict lengths, receive-only pending, FCM/ADS and native timeout discrimination.

Unified CAN calls use the concrete `VendorP5Channel` timeout policy. Each call
preserves the transport timeout, waits after NRC78 without resending, and retries
only native driver errors9/16 within max(saved timeout,5530ms). Pending reads use
1000ms and the native final fractional adjustment; every exit restores the saved
timeout. The native elapsed pending limit is180seconds. Its expiry alone emits
`write_diagnostic` with request ID and payload `3e`; that callback must return the
accepted count1. Host cancellation and host deadlines never emit that write.
The optional `channel_factory` accepts the shared six channel arguments and
pending-policy keywords and must return a concrete `VendorP5Channel`, preserving
its timeout-control providers. Ethernet does not accept this CAN factory.
Optional native helper failures include bounded positive-prefix mismatches and
native pending expiry. Empty, oversized or otherwise malformed payloads remain
host validation failures and cannot be swallowed as an empty optional field.

`native_result` preserves the native seventh output on successful completion of
the node loop. It is independent of compatibility, and does not advance the
caller phase. Host cancellation or deadline expiry in the final cleanup callback
propagates before this output can be returned.
