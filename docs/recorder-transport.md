# Native recorder stream transport

`RecorderTransport` connects `NativeVimClient` logical packets to the recovered
ComTol32 transfer frames and ACK state machine. The caller supplies an already
established stream and an explicit `denso-vim-control` capability declaration.
Construction performs no I/O, adapter discovery, driver changes or firmware work.

```python
from scripts.drive_recorder import NativeVimClient
from scripts.recorder_transport import RecorderTransport

capabilities = frozenset({"denso-vim-control"})
with RecorderTransport(stream, capabilities=capabilities) as transport:
    client = NativeVimClient(transport, capabilities=capabilities)
    mode = client.get_mode(timeout=10)
```

The supplied stream implements:

```python
def read(size: int, *, timeout: float) -> bytes: ...
def write(data: bytes, *, timeout: float) -> int: ...
def close() -> None: ...
```

Reads return at most `size` bytes. Empty bytes and `TimeoutError` mean temporary
idle. Disconnect/EOF must raise `ConnectionError` or another `OSError`. Writes
return the exact accepted prefix count. A partial successful write resumes at
that prefix; zero/invalid progress or an uncertain write exception fails the
exchange. The stream must honour its timeout and must not silently reconnect.
This contract supports USB/serial wrappers and authored peers; it does not name
or open a particular operating-system endpoint.

The callable interface is
`transport(request, *, deadline, cancelled) -> bytes`, matching
`NativeVimExchange`. Deadlines use the injected monotonic clock, shared with the
client. There is one active exchange per transport; nested/concurrent calls
fail immediately. `cancel()` interrupts at the next I/O boundary. `close()`
closes the supplied stream once, including from another thread. The context
manager closes it on normal return and exceptions.

The recovered state sequence is idle1 → transmit/ACK2 → await-response5 →
receive3 → take4 → idle1. Segments contain at most 511 bytes; continuation
controls wrap their seven-bit counter. Transfer control3 contains either
`06 state8` or `15 error32le`. State5 sends the original empty control`0x7f`
status query on one-second scheduler ticks; its replies contain `06 state8`.
This state observation is not a capability negotiation. No unproven startup
feature probe or capability response is manufactured.

Native ACK inactivity expires after two seconds; receive/response inactivity
after ten seconds. A shorter caller deadline also applies. Corrupt checksum,
boundary or continuation frames receive their recovered native NAK and leave
the partial response intact, permitting the peer's valid frame retry. The
transport never appends a rejected frame. Outgoing NAKs, unexpected states and
timeouts fail explicitly.

An ACK carries peer state, not a transaction ID or acknowledged segment number.
Lost ACKs do not prove that the application command was unexecuted. Accordingly
the adapter never automatically resends a command or a previously accepted
segment. A native NAK can request a peer retry; a transient empty read can be
polled again without resending data. After interruption, uncertain write,
timeout or protocol failure, this transport remains faulted. Dispose it and
supply a newly synchronized stream before another command. Creating that new
stream is an explicit caller operation, never an automatic device action.

Host bounds are 64 MiB per logical direction (configurable lower), a maximum
517-byte incremental frame buffer, one exchange, no background receiver or
unbounded queue, and 100000 I/O events per exchange by default. The event budget
includes short reads, short writes, idle polls and peer retries; callers can
raise it explicitly up to 1000000. It may stop extremely fragmented transfers
before the byte limit. Per-call I/O slices default to 50 ms and may be set up to
one second. These are host policy, not OEM hardware guarantees.

The implementation reuses `NativeTransferFrame`,
`NativeTransferAcknowledgement` and `NativeTransferSession` from
`scripts.drive_recorder`. Static anchors are ComTol32 `0x1000a450` dispatch,
`0x1000a790` segmentation, `0x1000a980` ACK/NAK, `0x1000aa80` sequence,
`0x1000aaa0` reassembly, `0x1000abd0` validation and `0x1000ad50` checksum;
`0x1000a190` timers/status query and worker `0x10009cc0` scheduler. The logical
command retry loop at `0x10001800` is not evidence that every command is
idempotent. Public regression vectors are authored; no OEM recording is shipped.

Run `python -m unittest discover -s tests -p test_recorder_transport.py -v`.
The tests exchange actual bytes through the logical client, including loss,
corruption/retry, sequence wrap, fragmented I/O, cancellation, hotplug and bounded
failure paths. Physical USB timing, device identity and vehicle behavior remain
`PHYSICAL_UNCONFIRMED`.
