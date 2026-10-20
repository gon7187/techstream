# Selected native communication

`scripts/native_communication.py` implements selected CommandCommon communication
without loading vendor binaries or discovering adapters. Construction takes an
explicit `VehicleProfile`, observed bus identity, native source build (12 or 18),
and a retained typed lower frame-operations object. The same `MonitorSupportCache`
is exposed as `.cache` for support and DDR consumers.

`execute(selected, request, extended=False)` reads send/receive DWORD timeouts and
BYTE retry count from the selected DB11D record. Ordinary requests and responses
use the native BYTE ceiling; extended requests retain WORD lengths and default to
the native frame's 4096-byte receive capacity. Positive SID checking is separate
from connection mask checking. Send faults do not read; receive `90020323` exits
immediately; `90020321` retains partial bytes after retries; other failed replies
are not copied into the result. Source 18's advisory `6bbe0` timeout conversion is
applied only for SIDs 1 through 10 and selected ProtInfo+26 equal to one. Source 12
uses the literal settings timeout.

`connection_no_buffer(frame_id=0, settings_id=1)` uses the canonical direct DB111 /
DB11D selection, never an EcuFunction substitution. Empty requests perform null
initialization. Nonempty requests use the shared Ever cache, or explicit TEMP
cache. Force invalidates the exact Ever ECU/request entry. Mask mismatch remains
`status=0, connected=False`. On a new eligible connection the runtime drains
ReceiveExt with capacity 4095, timeout zero, argument five zero and wait 100 until
`91010009`, which is normalized to success. Other drain errors clear connected.
In build 18, category 20/52 and the native category-four SID allowlist skip this
drain; build 12 drains unconditionally on a cache miss.

Empty requests always use the native fresh local CCommCachePlus flags. Nonempty
default/Ever calls also use fresh `NoInit=False, NoSession=False`; only a supplied
TEMP cache preserves the caller's flags. Scoped flags are restored after success
or failure. Actual12/18 tests distinguish these branches using forced native
initialization, rather than inferring the choice from method names.

`begin_operation` renews explicit host budgets and clears TEMP through the shared
cache while retaining Ever entries. Cancellation, source identity changes,
primitive budget and monotonic deadline checks apply between primitive calls.
`close` marks application I/O closed, including lower cleanup failures, and returns
the actual cleanup status. Failed native driver release preserves the owned channel
for a subsequent cleanup retry; repeated cleanup never repeats a business write.
This retry policy deliberately retains resources that the original outer destructor
could discard. `disconnect(flag, deadline=...)` also exposes the native outer flag:
flag one preserves the PSA pre-init D1 setting; other flags suppress that D1.

`communication_flags(no_init=..., no_session=...)` scopes fresh native CPlus flags
without resetting cache storage or budgets. Explicit `SupportQuery.capacity` is
forwarded to the selected transaction; omitted extended capacity remains 4096.
Already typed parent TimeoutError survives a matching post-I/O deadline failure;
cancellation still takes precedence over native faults.

Source anchors:

- `analysis/evidence/no-car-49/common-focused.c`: `10071790` selected connection.
- `analysis/evidence/no-car-2/common-0-v12.asm`: `1003c9a0` ordinary version 12.
- `analysis/evidence/no-car-2/common-0-v18.asm`: `1005d190` ordinary version 18.
- `analysis/evidence/fullport-scaling/CommandCommon.dll.asm`: `1005d4c0`
  extended transaction, `1006a8e0` frame defaults, `1006bbe0` timeout conversion.
- `analysis/evidence/no-car-43/kgp18-fixed/10013900.c`, `100139b0.c`,
  `10013a10.c`, `10013940.c`, `100139e0.c`: wrapper mode/clear-buffer ABI.

Verification: `python -m unittest discover -s tests -p test_native_communication.py -v`.
The authored serialized DDB checks exercise actual direct metadata selection,
version 12/18 selection, mask/status distinction, cache hit and receive drain.

The normal CAN integration is checked through `from_backend`: authored serialized
DDB -> actual direct selection -> Common -> NativeFrameController -> actual
NativeFrameOperations -> typed J2534 connect/config/filter/write/read/drain and
cleanup. Additional checks cover null initialization without application writes,
packet-log hooks and a reported write failure followed by the explicit Common
retry on the retained channel. Protocol constants, payload headers and timeouts
are asserted literally.

`is_behavior_code` implements Common14050 / version12 fc10 over the canonical
`behavior_frame` producer. It reads the first ComSet row, then the communication
frame, collects big-endian WORD identifiers from segmented replies, applies the
advertised BYTE total, and tests the first receive-check WORD. A timeout after
accepted packets terminates collection successfully. Native transaction failures
retain the distinct `ignored_failure` flag consumed by support dispatch.

Version differences verified separately: version12 extended transactions ignore
the NoSession cache flag; version18 extended transactions prioritize it. Version12
connection draining has no category/SID skip list; version18 adds that list. Empty
connection requests set initialization control one, which selects lower mode zero
and permits a null initialization request.

`NativeFrameController` ports PSA service-family setup and the selected D1/D2
session sequence, preserving the NoSession bypass and retaining the actual lower
channel. The native18 WWH classifier EE50 drives the lower request-state selector;
native12 uses its original single PSA class. Category 0x1B5 receive data beginning
61 80 has bit 3 cleared in its third byte, as in both original builds.

TesterPresent uses the selected function DD and the original 2000 ms idle worker,
not a J2534 periodic-message approximation. It calls the concrete lower send/read
with the native low-BYTE request length, 1000 ms timers and 120-byte receive cap.
Reply bytes update session state and subsequent initialization mode. PSA sending
and closing stop and join the worker before sharing the channel. Worker provider
exceptions are retained in `tester_error`; uncertain lower I/O follows the lower
poison/cleanup policy. Each worker exchange has a five-second host deadline and
stop waits at most five seconds. This is an explicit host cleanup bound; native
15890 waits 185000 ms for acknowledgement. A failed stop returns 90020402 without racing
another owner onto the channel. Receive deliberately ignores native start errors.
Build12 worker requires the ordinary four-byte echoed reply, including for SID10;
build18 handles SID10/50 specially as session state three. Build12 starts from
the current diagnostic SID predicate; build18 uses the PSA
initialization flag or WWH diagnostic request state.

Authored serialized DDB checks also cover PSA D1/D2 and family changes, WWH
12/18 selection, actual DD worker lifecycle, and DDR RAM recording/replay with
concrete packet-log bytes. Source anchors for the outer lifecycle are the cached
KGP `10013e70`, `10015310`, `100155f0`, `10015890`, `10015d30` bodies in
`analysis/evidence/no-car-43/kgp18-fixed/functions.c`, and focused native12/18
extracts under `analysis/evidence/no-car-77`.

`change_context(profile, bus_id=..., first_request=..., request=..., deadline=...)`
implements retained lower selection independently of the bound Common cache.
Native12/18 forced bus transitions reconstruct the concrete selected lower;
ordinary compatible transitions rebind the retained channel. PSA metadata matching,
flags, WWH mode and observed interface-word changes participate in selection.
StopCommunicationCheck completes the old session and clears only native runtime
category, preserving canonical profile metadata. Bus 0x1C preserves its initialized
flag and SID sentinel 10000: NULL performs selected wakeup and returns before a
base NULL send; SID changes first finish the old native81 session.

The native lowA WatchIdle worker starts after eligible outer sends. At 3000 ms
inactivity it executes the selected pre-initialization helper and clears native
runtime category. It uses the retained lower channel; it neither disconnects nor
invents a periodic packet. Host stop joins before context changes and cleanup.
Diagnostic event traces retain at most 256 entries.

After retargeting a controller, construct the Common runtime for the new selected
profile/ECU/bus. The former bound runtime rejects use before I/O. Bind packet logs
to the retained controller when contexts may change; its concrete lower packet
hooks migrate and stopping the outer logger disables the current lower.

For native workflows which retain one controller across multiple ECUs, construct
the first runtime with `from_backend`, then create each pinned ECU/cache with
`owner.share_context(profile, ecu, bus_id=..., first_request=...)`. These explicit
siblings retain one controller. An actual send selects its own profile and bus
through `change_context` using the actual request; an Ever cache hit performs no
retargeting or I/O. Inactive contexts may renew budgets, but cannot directly
receive from another ECU's channel. Disconnecting the outer owner cleans the
currently selected lower, including when the last exchange belonged to a sibling.

Authored 12/18 integration checks cover forced 12→22 reconstruction, retained
12→32 transport identity, selected inverse headers, exact log bytes, stale runtime
rejection, and actual 1C NULL wakeup 03e0→0367 plus native81 metadata failure.
Native18 low nibble four now constructs the actual Ethernet lower. Its selected
SID reaches `set_service_context` before setup/send, selecting protocol WORD6 for
services1..15 and WORD8 otherwise, including native initialization suppression.
Session function dispatch invokes the lower's `send_function`, whose completed
exchange clears D1 suppression. Serialized DDB tests exercise the actual typed
`invoke_ethernet` primitive with distinct functional and physical addresses.

`bind_comm_log(DdrPacketLog(..., communication.operations))` binds the concrete
native12/18 file owner. `start_comm_log(kind)` preserves native filename modes
and same-kind handle rules; `stop_comm_log()` closes the file and reports deferred
write failures even after disconnect or cancellation. Tests cover actual lower
packet bytes saved in modes0/3 for12/18 and mode0x14 for18, followed by disconnect
and log stop. Native12 Each workflows do not invent a logging call.

`execute_raw(selected, request=None, capacity=255)` implements Common18:5c450
separately from ordinary positive-SID validation. It retries every failed status,
rejects a successful empty response, and uses BYTE receive capacity with literal
selected timeouts. SendInt argument5 remains the retained selected bus. Independent
stack tracking confirms separate bus and receive-pointer locals in both builds;
the temporary cdecl allocator argument changes the apparent stack offset.
Concrete12/18 lower tests accept a non-positive-SID reply through this path.

The low4 cross-context branch queries actual ioctl8023 state. State2 retains the
query status and channel; other states stop the tester, release the selected
TCP/UDP/IP/physical resources, rebind metadata and reopen. Failed host cleanup
retains resource ownership and rejects subsequent application I/O.

Final source-hash-bound review remains OPEN. Physical adapter/vehicle behavior
has not been exercised.

`connection_check()` is the standard native12/18 ConnectCheck route, separate
from NoBuffer. It checks the retained CShareData-slot8 observation list, then
executes the selected ordinary frame on a miss without NoBuffer's drain. Standard
AddBuffer appends actual selected first-row request bytes (BYTE length), actual
reply bytes, category, bus, supported result and protocol BYTE. Duplicate entries
are retained. `connection_entries` exposes an immutable snapshot shared by all
contexts of the one controller. `connect_set` inserts only an absent category/bus
pair; its overwrite mode updates the first matching category while retaining its
request/reply lists. `clear_connection_buffer` clears this list, independently of
the Ever/TEMP response caches. NoBuffer never populates connection observations.

The original standard CommConnection overwrites transport status with AddBuffer's
status. On empty requests and failed exchanges, however, its receive-count local
is genuinely uninitialized in both builds. The port raises `SessionError` before
inventing that count, cached bytes or a successful AddBuffer result. Replies over
the original 128-byte stack buffer also fail explicitly. These are source-undefined
host boundaries, not negative connection observations.

`protocol_context(profile, bus_id=...)` derives the constructor metadata seed from
the candidate's canonical DB111 default frame, including an empty frame. Runtime
lower constructors accept that empty metadata seed without sending invented bytes;
the public GetCommFrame contract still rejects empty requests. `check_protocol`
binds the literal CheckCommProtocolCache algorithm to these actual shared contexts: misses run
the native NULL SendInt initialization probe; native failures call ConnectSet with
supported zero. Host cancellation, deadlines and source-undefined errors escape.
Cache hits preserve the native protocol-local value zero. Tests exercise both
builds over actual typed J2534 initialization and standard connection/cache paths.

Protocol candidates may use a management-only `ProtocolProfile`, whose ECU database
identity is `None`. Their real management metadata and NULL initialization remain
available without constructing an empty ECU database. ECU-record consumers still
require a `VehicleProfile`.

Shared contexts retain the same native DataCtrl Ever buffer. Its key uses the
selected category and literal request, so changing a display name or bus variant
does not create a second wire transaction. A different management source cannot
join that buffer.
The same owner join shares support-kind slots10/11/19/1a and Mode35 slot21;
their results remain indexed by the selected category rather than display names.

When native open returns a failure, the outer controller performs Disconnect(0).
Only completed cleanup permits a later candidate to construct a fresh lower;
the failed open status remains the result of the original attempt. Host failures,
invalid metadata and incomplete cleanup retain the failed-context guard.
