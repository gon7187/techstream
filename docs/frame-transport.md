# Selected communication frame transport

`scripts.frame_transport.get_comm_frame(profile, request, *, bus_id, driver,
diagnostic_mode=bytes(16))` translates selected version 12/18 management records
into a `FramePlan`. It performs no file, device, browser or network I/O.
`DriverProperties(status, api_version_bytes, source)` supplies an explicitly
observed `PassThruReadVersion` result; it never queries a driver. Missing selected
records and unsupported native protocol branches fail explicitly.

The result contains:

- `connect`: exactly two DWORDs, protocol and flags. Baud is a configuration pair.
- `configs`: ordered `NativeConfig(parameter, value)` pairs, preserving native
  remapping, omissions and API-version-dependent timing conversion.
- `filters`: filter type plus three explicit native mask/pattern/flow messages.
- `send`: six DWORD header words and the complete addressed request bytes.
- `initialization_message` and `init_bytes`: native initialization outputs,
  distinct from a response expectation.
- Selected startup/tester requests, resolved address and database/driver provenance.

`NativeMessage.encode/decode` use little-endian header words in order
ProtocolID, RxStatus, TxFlags, Timestamp, DataSize, ExtraDataIndex, followed by
exactly DataSize bytes. Address bytes inside message data retain native big-endian
order. Native generated messages set ExtraDataIndex equal to DataSize.

## Native mapping

The native GetCommFrame dispatch uses the low bus nibble: 1/9/12 selects protocol
4 (legacy ISO), 2 selects protocol 6 (ISO15765; ECU flags select the PSA variant),
and 7 selects protocol 1 (J1850). Only full bus 0x22 sets connect flags 0x80.
No protocol or address is inferred from an ECU name.

Selected protocol records supply physical/functional/slow/extension addresses.
Management slots 14/15/51 supply CAN/ISO/J1850 configuration records, respectively.
Their native simple-table lookup keeps the first matching record. Selected
function slot 18 joins communication slot 17 and variable slot 0 for startup
and tester requests. Lower GetCommFrame does not require a ComSet record.
The existing `CommandFrame` three database references remain request/mask/check;
the native fourth byte list is a mutable received-data buffer.

CAN messages have a four-byte identifier, plus the extension byte for high bus
nibble 0x20. High nibble 0x30 selects the functional identifier. CAN filters for
high nibble 0x10/0x20 include a pass filter and flow-control filter; the PSA flow
mask is 0xffffffff. Diagnostic mode WORD0 == 1 changes the resolved address;
any nonzero WORD0 supplies the pass-filter address. The request header still
uses the selected protocol address, matching the separate native paths.
Legacy and J1850 headers are three bytes with the recovered source/control/target
rules. This helper does not append a checksum.

The observed API boundary is 03.05: IDs 6 through 13 have doubled uint32 timing
values for API >= 03.05, before native config ID omission/remapping. A failed
ReadVersion observation follows the native old-API branch.
`translate_configs(values, driver)` publicly exposes this same native mapper
for distinct caller constructors; it is an alias of the existing implementation,
with identical bounds, omissions, ordering and uint32 conversion. A successful malformed
or incomplete version observation is rejected instead of reading unwritten bytes.

## Execution and bounds

The plan is data, suitable for the existing `NativeDrsExecutor` primitive backend.
`drive_recorder.selected_check_mode_plan` consumes this producer for selected
CheckMode groups. Callers retain their native initialization/session ordering;
the producer performs no hidden connect or initialization. The regression suite
also executes produced connect/config/filter/write/read/disconnect commands
through that executor with injected primitive I/O, including cancellation,
deadline and fault at every boundary. Resource ownership and cleanup belong to
the executor; no callback can replace frame generation with an invented success.

Each native message is bounded by 4128-byte storage. `NativeFrameReceive`
represents the assembled application result, whose native WORD capacity permits
65535 bytes; Ethernet lower operations assemble bounded message chunks. Ordinary
message decoding retains its per-message limit. Legacy fast-init is bounded
by its actual 64-byte native scratch buffer, even though the original passes a
larger capacity argument. Unsafe overflow cases are rejected. Native outputs
left untouched by a branch are represented with deterministic empty/zero values:
legacy/J1850 filters, CAN/J1850 initialization outputs, and unwritten
initialization header fields. These are explicit host policies, not claims that
uninitialized native memory contained zeros. No vendor binary is executed and no
physical transport result is claimed.

## Source and verification

Recovered entry anchors in `KGP_CommFrameCtrl.dll`: version 18 export 0x16980 to
0x169c0, shared generator 0x3780, CAN header 0x9500, ISO header 0xf820, J1850 header
0x12bd0, config builders 0x18270/0x18380 and setters 0x182c0/0x183d0. Version 12
export 0x12030 to 0x12070 uses matching protocol behavior with different object
layouts and CAN-record offsets. Original binaries, full static C/assembly,
virtual-target audit and source hashes are private evidence under no-car-43;
public tests contain independently authored synthetic records and literal bytes.

Run `python -m unittest discover -s tests -p test_frame_transport.py -v`.

## Lower native runtime

`runtime_frame_plan` selects metadata for the actual source-built lower class.
Unlike the pure export, PSA/WWH/Dual setup does not require an unused selected
0x7f tester frame. It preserves the pure export's behavior through a separate
entry point and takes explicit native build and class variant. Actual runtime
low6 selects J1850 protocol2 and its 0x61 header; the pure export still rejects it.
Additional native ChangeCommIF subclasses for bus low3/4/8/C are recorded as open
software reconstruction work and rejected by this runtime factory. In particular,
the pure export's lowC/protocol4 result is not substituted for the actual runtime
lowC/Open0x1000d subclass. Distinct lowA/Century/packet factories supply their own
concrete plans and subclass algorithms.

`NativeFrameOperations(profile, plan, backend, native_build=12|18, bus_id=...,
 driver=..., device_kind=...)` executes the recovered lower transport over
`J2534Backend.invoke`. The backend supplies concrete connect, IOCTL,
filter, message write/read and disconnect primitives returning `J2534Result`.
It receives an absolute seconds deadline and cancellation predicate for each
call. It must bound its own blocking calls and poll cancellation. Primitive field
mappings are read-only. A wrapper can report a host boundary through
`J2534Result.host_boundary`: `cancelled_before`/`deadline_before` require an empty
outcome because no primitive ran; `cancelled_after`/`deadline_after` retain the
actual outcome, which is validated before the host error is raised. Constructors
perform no I/O. Native source build is independent of the selected DDB format.

The native third Open argument represented by `open_baud`/`baud_rate` selects
standard PassThruConnect when zero; nonzero selects PassThruOemConnect with that
value. Zero does not claim a physical line baud rate of zero.

`open(setup=True)` connects and configures; `open(setup=False)` permits the native
outer caller to establish service context before `setup`. `adopt_channel` binds
an explicitly owned or borrowed existing channel, including its actual configured
state. Dynamic `send` rebuilds the retained native header for each supplied PDU.
Its initialization modes are literal native values: 0 forces initialization and
permits NULL, 1 checks health, 2 bypasses initialization, and 17 continues after
an initialization status error. `None` and `b""` remain distinct. `clear_rx=1`
issues IOCTL8. `no_session` records caller state; outer session orchestration is
implemented by `native_communication`, rather than hidden in the primitive driver.

`receive` handles native status mapping, nonzero RxStatus drops, source/length
validation, response-pending limits or the 180-second pending window, busy
resends, partial negative responses, active-test expiry and optional timestamp
unwrapping. Decoding uses the retained protocol, including when the driver reports
a different ProtocolID. CAN removes four or five bytes; ISO/J1850 removes exactly
three bytes. This layer retains trailing checksum bytes. NULL output buffers
return the native error without reading. `drain` performs the separate raw native
read/log/discard loop.

Runtime configuration differs from the pure GetCommFrame output: device8 CAN
adds config0x2a and retries without it on failure; selected ISO timing10 uses
WORD50 for devices other than4. J1850 protocol2 issues IOCTL12 and config4/5.
PSA service-family changes and WWH request-state changes rebuild the concrete
filter/address context. WWH is available for its recovered build18; build12 has
no matching exported WWH selector. `set_request_state` consumes the actual outer
classifier result. Century workers subclass the concrete `_frame_message` and
`_validate_message` byte algorithms in `monitor_j2534`; `_decode_message` and
`_drop_message` also represent the actual native inverse/RxStatus virtuals; driver I/O and bounded
lifecycle remain in this class.

`apply_temporary_config`/`restore_temporary_config` implement the separate native
CAN config0x23 save/override/restore methods. They are explicit operations, since
the native send helper does not call them unconditionally. `NativeSharedState`
retains observed shared CanMaskJudge result and connection blocking state; `None`
means the native shared item is unavailable. `set_runtime_flags` exposes the
observed zero-write-timeout, timestamp-unwrapping and pending-window flags.

Pre-initialization uses the selected native 0x58 or 0xd1 helper. A healthy owned
close performs the corresponding native exchange and, for bus0x1c, selected0x81
before disconnecting. `set_preinit_d1_suppressed` preserves the native DWORD setter;
its constructor value1 suppresses that extra D1 exchange. Upper PSA service D1/D2
orchestration is a separate native caller path. `clear_runtime_context` mirrors
the native category-zero setter without discarding the selected profile; later
pre-init/close helpers then suppress category-dependent business writes.

The count-based pending limit invokes its actual tester-frame exchange before
returning the original pending status. ISO temporarily configures interrupt mode,
uses a zero write timeout, waits 1000ms before each raw read, and restores the
mode after confirmed status outcomes. A validation failure clears RX and attempts
native reinitialization. Uncertain I/O adds no configuration or recovery writes;
recursive native recovery is bounded to one level as an explicit host policy.
`set_burst_mode_state` and `set_interrupt_mode_state` retain the actual native
flags after separately performed driver configuration. Active SID30 tracking
requires nonzero burst mode; timestamp unwrapping requires burst mode1 and does
not advance on a partial negative response.

All owned resources are recorded before post-call cancellation checks. Cleanup
has a separate finite, cancellation-immune five-second budget, checks before and
after every primitive, and retains unreleased ownership for a retry. Typed
before-I/O cleanup boundaries retain ownership; after-I/O boundaries first apply
the confirmed filter/disconnect outcome, then propagate the host error. Borrowed
channels are never disconnected. Explicit driver write errors preserve the
channel for native caller retries. Exceptions, unconfirmed write/read counts,
cancellation after I/O and uncertain completion poison the object and clean up;
a poisoned cleanup adds no further business writes. Repeated cleanup never repeats
an uncertain close-session write. An owning acquisition worker may temporarily set
`defer_cancel_cleanup=True`: host-observed cancellation or deadline expiry at a
confirmed primitive boundary then propagates while retaining the channel for the
worker's separate bounded native stop exchange. Backend-thrown interruption or
timeout and unconfirmed message counts still poison and clean up. The worker
restores the flag and callbacks after its owned lease. Identified host-clock
failure is also deferrable after a confirmed boundary; the acquisition still fails.
`last_confirmed_clock` permits a separate cleanup clock based on that observation
and real monotonic elapsed time. A clock exception escaping an unconfirmed backend
primitive remains a transport fault. Native undefined/unwritten
outputs and short successful counts are rejected instead of inventing an output
or success. `rebind` retains a selected same-class channel, refreshing actual
metadata while preserving an unchanged configuration. `finish_bus_session` exposes
the native selected81 exchange separately when an outer context switch retains
the channel; `prepare_bus_session` represents the base native constant-zero slot
and is concretely overridden by subclasses that perform that operation.

Packet logging accepts an explicitly owned writer via `set_packet_log`. Native
records contain decoded application bytes as uppercase ASCII hex followed by the
two literal bytes `\n`, not a linefeed. The file owner handles native final-suffix
truncation. Empty payloads emit nothing. Writer failure disables logging and
sets the supplied error hook while transport continues. Short writes are treated
as failures as an explicit host policy. No file is opened by this module.

Runtime anchors include build18 send/read 0x1990/0x1d50, setup
0x8bc0/0xf030/0x12920/0xbd80/0xe440, initializers
0x96c0/0xfb30/0xfc80/0xffc0/0xc690, pending tester0x25b0,
inverse validators
0x95f0/0xae60/0xf900/0xf980/0x12ef0/0x12f60, and native close 0x1900.
Build12 send/read are 0x1740/0x1ae0, with source-specific configuration offsets.
Static evidence and candidate runtime audit remain private; physical results
remain unconfirmed.

## Shared MultiMon lower

`NativeMultiMonOperations` exposes `connect_multi_mon`, the three-argument
`entry_comm_system_info(category, bus, entry)`, `send_multi_mon`, `receive` and
`close(disconnect_flag=1)`. Its one or two selected `DualTarget` entries and
profiles describe non-voltage ECU contexts; an outer voltage slot does not count
as another lower entry. Imports and construction perform no I/O.

MultiMon has its own concrete lower variant: ConnectMultiMon constructs native
18:d670/12:9e70, separately from the Dual constructor. It inherits normal CAN's
count-based pending state and requires selected tester7F metadata even for phase5.
Its unused startup67 metadata is resolved only if initialization actually runs.
The SendIntExtMultiMon/DualMon exports share entry18:13e10/12:f920 and procedure
18:14400/12:fe90, which activate the registered context and refresh configuration
before sending. The source
ignores the sixth argument and fixes lower initialization mode to2. One protocol6
channel serves both registered contexts. Selected target plans and the native
registration/filter algorithms are shared with `NativeDualControl` and
`NativeDualTransport`; its source-built CAN class also handles selected low8
contexts without substituting pure GetCommFrame dispatch.

Typed before/after host observations preserve actual channel ownership. An
explicit `defer_cancel_cleanup` lease retains confirmed host cancellation for an
outer bounded native stop; unknown backend failures or unconfirmed counts poison
the lower and invoke resource-only cleanup. A failed cleanup preserves pending
ownership in `control.channel`. The caller may retry bounded cleanup with a valid
clock. `Disconnect(1)` performs its recovered category14/15 service/state/configuration
transition before lower close. The Multi variant uses normal CAN's selected58
pre-initialization on lowA buses; it does not substitute Dual's D1 policy.
If the shared host clock fails, default cleanup uses a fresh five-second
monotonic budget for resource release only. No physical result is asserted.

`reset_released_runtime()` restores the exact base native constructor state for a
confirmed new class/channel generation. It rejects still-bound resources and
subclasses that need their own constructors. The controlling shared lower calls
it only after release and a new channel generation, before adopting the borrowed
channel. Host cancellation/cleanup leases, packet-log ownership/error state and
last confirmed host-clock observation survive that native reset.

`runtime_frame_plan(profile, b"", ...)` also constructs a header-only metadata
seed, matching native lower construction before a request exists. This runtime
entry permits a selected empty default frame or an active-only caller without an
invented application byte. `get_comm_frame(profile, b"", ...)` keeps its original
nonempty export contract. Actual `send(None, initialization_mode=0)` performs only
selected initialization; NULL with mode1 remains rejected.

Management-only construction accepts `ProtocolProfile`, including a selected
category with no ECU filename. These frame/config/protocol operations use only
management records; they do not require an ECU database or invent an empty one.
`VehicleProfile` remains a subclass for callers that also have ECU records.
