# Onboard Drive Recorder

`scripts.drive_recorder` implements the recovered native DRS binary envelope,
low-level DRS command records, recorder INI configuration and injected execution.
It never opens an adapter, loads a vendor DLL or assumes that J2534/JLR support
implies an onboard recorder. This is separate from desktop sample logging.

```python
from scripts.drive_recorder import DrsFile, RecorderController

settings = DrsFile.parse(settings_bytes)
controller = RecorderController(
    backend, capabilities=frozenset({'native-drs-execution'})
)
results = controller.execute(settings, timeout=10, cancelled=lambda: False)
```

The injected backend implements
`invoke(operation, fields, *, deadline, cancelled)`. It must enforce the deadline
and cancellation during blocking I/O. The controller checks both before and after
calls; Python cannot interrupt an arbitrary blocking backend. Operations come from
native DRS records, rather than a synthetic JSON recording schema. The native
file is parsed and every command, including nested children, is decoded before
the first backend call. Child trees are bounded to depth 64 and 100,000 records.
High-level container context is passed intact to the backend; the controller
does not invent a flat execution order for conditional native groups.

A backend exception latches `fault`; cancellation latches `cancelled`. Further
execution requires `recover()`, which acknowledges a host error and makes no
claim about ECU/adapter recovery. These lifecycle states are authored host policy.

## Native packet and service APIs

`NativeVimClient(exchange, capabilities=frozenset({"denso-vim-control"}))`
uses an injected `exchange(request_bytes, *, deadline, cancelled)` callable.
Requests contain the native compact opcode and payload. Replies contain the
compact request opcode OR `0x80`, control `0x06` and payload, or a native NAK
with u32 error. Mismatched reply IDs fail. This is the logical ComTol packet,
not a claim that physical I/O is implemented.

The selected logical DMCI wrappers, packet reader/writer, exchange and session
FSM have a passive 12/18 comparison in
`analysis/evidence/no-car-6/comtol12-18-logical-parity.json`: 40 helpers and 30
DMCI wrappers agree, retaining literal internal addresses and constants while
resolving named imports. This proof covers application `VS_x86` and its
byte-identical `VS_x64` copy only: build12 SHA256
`c6ba92c4a9119afff7d8615bfc4e025f670ca04486470b7f6390f09316f16903`,
build18 `ec1954a645005f539ca76ffb4de8e4ba6087ef5b4bcdead510b0daa2ab687615`.
Direct calls are closed at explicit CRT heap and concrete backend-constructor
boundaries. Native backend virtual I/O and other module variants require
separate evidence.
Pure DRS serialization and device8 recording export do not invoke ComTol32.

`NativeTransferFrame`, `NativeTransferAcknowledgement`, `encode_vim_transfer`,
and `decode_vim_transfer` implement the original outer binary framing: STX,
control, u16 byte length, at most 511 payload bytes, additive u8 checksum, ETX.
Segmentation preserves original single/start/continuation/final controls and
7-bit continuation sequence wrap. Transfer ACKs carry the native u8 state;
transfer NAKs carry a u32 error. They are distinct from logical command replies.
`NativeTransferSession` models the original states 1..5, outgoing segment ACK advancement, keepalive 0x7F, receive reassembly, 2-second ACK and 10-second response deadlines, completion and cancellation. Receive states preserve partial buffers and emit original NAK codes for bad length (3), checksum (4), boundary (6), and sequence (5), allowing a valid frame retry. Invalid state and authored size-limit failures raise explicitly. The complete transport retry/exchange wrapper is integrated separately; this module does not open USB.

`NativeVimFiles(client)` additionally requires explicit `denso-vim-files`.
It exposes `open`, `read`, `write`, `seek`, `close`, `list_files`, `download`,
and `upload_settings`; synthetic tests exchange real native binary layouts.

`OnboardRecorderService(entrypoints, root_path)` exposes `update` with USB and
switch events, `report`, and `shutdown`. Entry methods `check(root_path)`,
`execute(notification_handle, root_path)`, and `cancel()` receive keyword
`deadline` and `cancelled`; these are injectable equivalents of the original
onboard DLL exports, not a remote control opcode. Backends must bound their own
blocking calls. Successful native execution is tracked even if a post-call
host deadline expires, so shutdown can still cancel it. A failed Check result
means settings are unavailable and does not start recording.

## Binary format

The little-endian header is `magic:u32 = 0x80000001, word1:u16, word2:u16`.
The two header words are preserved without invented version meanings. Each table
is `size:u32, id:u16, payload[size-2]`; size includes its ID and excludes the
four-byte size. Duplicate IDs, table order and opaque payloads survive round trips.
A wrong magic, incomplete header/record, impossible length or configured size
limit fails explicitly. Native DM recordings use `0x80000002` and are handled
by `scripts.snapshot`, rather than accepted as DRS settings.

Recovered public typed support:

| ID | Native class / operation | Payload support |
|---|---|---|
| `0x8100` | `CDmSystemInfo` | Shared snapshot system-information codec used by native DRS generator |
| `0x0001` | `CCmdSelectCarTypeVin` | Core words, VIN core string, full SelectName / CarInfo / OptionInfo lists and trailing words |
| `0x0005` | `CCmdTriggerInfo` | Native core words + u16 type / duration / point |
| `0x0006` | `CCmdTriggerParam` | Native core words, quantity / condition, full condition and stealth-ID lists |
| `0x0028`, `0x0029` | Session change records | u32 + native buffer core words / length / bytes |
| `0x0002` | `CDrsMonBuffInfo` | Direct buffer fields, nested frame 3 / signal 4 tables, core string, full selected-ID list |
| `0x0004` | `CDrsMonSignalInfo` | Full signal records, core strings, version-dependent display lists, ordered raw fields |
| `0x0003` | `CDrsRcvFrameInfo` | u32 count, repeated u16 frame index / u16 length |
| `0x0011` | `CDrsMonSettingInfo` | Empty own payload + native child-table envelope |
| `0x0012` | `CDrsMonStopInfo` | Empty own payload; child envelopes preserved |
| `0x0021` | `CDrsDiagCommSetting` | Empty own payload + native child-table envelope |
| `0x0022` | `CDrsDiagCommEnd` | Empty own payload + native child-table envelope |
| `0x0023` | `CDrsChangCheckMode` | Empty own payload + native child-table envelope |
| `0x0024` | `CDrsConfCheckMode` | Empty own payload + native child-table envelope |
| `0x0027` | `CDrsCheckCarInfo` | Empty own payload + native child-table envelope |
| `0x0200` | `CDrsPtConnect` | u32 protocol ID / flags |
| `0x0201` | `CDrsPtDisconnect` | Empty own payload |
| `0x0202` | `CDrsPtReadMsgs` | Timeout + initial message header 6I, mask blob32, pattern blob32 |
| `0x0203` | `CDrsPtWriteMsgs` | u32 timeout + message |
| `0x0206` | `CDrsPtStartMsgFilter` | u32 filter type + three messages |
| `0x0211` | `CDrsPtIoctlSetConfig` | u32 count + u32 parameter / value pairs |
| `0x0213` | `CDrsPtIoctlFiveBaudInit` | u32 length / bytes + trailing u32 |
| `0x0214` | `CDrsPtIoctlFastInit` | Message |

Messages serialize six u32 values in order: protocol ID, RxStatus, TxFlags,
Timestamp, DataSize, ExtraDataIndex, followed by DataSize bytes. They use packed
field serialization, not the in-memory padding/capacity of `PASSTHRU_MSG`.
ReadMsgs aliases native Read/Write and serializes timeout plus only the initial
message header, then the second message mask bytes and third message pattern
bytes. `NativeReadExpectation` preserves this layout and matches normal received
messages using `(received & mask) == (pattern & mask)`; RxStatus low five bits
are skipped, matching the native read loop. Payload keys are `mask_data` and
`pattern_data`.
Unrecovered condition/mode/status integers do not get guessed meanings.

`selected_check_mode_plan(profile, bus_id=..., driver=..., diagnostic_mode=...)` now compiles the actual selected frame wrappers through `frame_transport.get_comm_frame`: group21 connect/config/filter/initialization, group22 optional function58 plus disconnect, group23 change and group24 confirmation. It requires explicit observed driver properties and native diagnostic-mode context. `selected_session_tables` supplies phase5 category20 records28/29 from first selectedD1/D2 request bytes and the native diagnostic-mode/ProtInfo leading DWORD rule.

`selected_check_mode_frames(profile, level=1)` executes the native selected frame producers: function3 for level1, function4 for level0, exactly one change frame; function5 supplies confirmation frames. Change mask is `ff`, change pattern uses selected receive-check bytes; confirmation mask and pattern both use selected receive-mask bytes, as the original does. It retains selected settings DWORD0/4 and source provenance. `native_mode_exchange_tables(frame, send)` composes the native203/202 pair after the protocol producer supplies its actual message: header length is wire size minus request size, receive arrays receive zero header prefixes, initial read state copies only protocol/RxStatus/TxFlags, and the selected two DWORDs supply write/read timeouts. Protocol-specific `GetCommFrame` headers/connect/config/filter production is a separate dependency before composing complete conditional DRS groups.

`NativeDrsExecutor` executes J2534 primitive groups with an injected provider: connect returns a u32 channel ID; reads return one `NativeMessage`; other operations use the table names above and receive `channel_id`. It preflights complete groups, skips empty writes and status notifications, applies the native mask matcher and disconnects on faults, cancellation or post-connect deadline expiry. Check Mode follows the recovered `confirm24 → [change23 → wait1000ms → confirm24]` branch, at most seven changes, then `end22`; return0 means initially confirmed and return1 means a change was needed. An absent setup21 returns0. An absent initial confirm24 reads the persisted `temp.dat` Check Mode DWORD. Subsequent attempts require group24 and return native `0x901f0105` when absent. `CCmdWordId` list items serialize only their u16 ID. Public selected/stealth memory tuples retain constructor core `(1,0,id)` for compatibility; those core words are not present per item on the wire. Other classes explicitly serialize their core where their original reader does so.

`NativeRecorderState` encodes the exact eight bytes: persisted raw trigger reference (default `0xffffffff`), then Check Mode DWORD (default0). Sliding triggers1/7 convert the persisted raw reference using each signal; a fresh reference initializes from the first sample. The last condition raw value is persisted only after a complete capture and successful stop.

`RecorderPaths.parse()` reads UTF-16 BOM or UTF-8 INI, the native `[DriveRecord]`
keys `SettingFolder`, `OutputFolder`, `MaxFile`; it does not create directories or
resolve Windows CE paths against the host filesystem.

## Native DMCI acquisition and record output

`NativeDmciCommand` implements the native field serializers for all 30 inventoried command classes (`0x100`–`0x11c` and `0x11e`), including core lists/buffers. `NativeVimClient.dmci` requires explicit `denso-vim-dmci` capability in addition to `denso-vim-control` and emits the original logical command bytes:

| DRS IDs | Native wire commands | Operations |
|---|---|---|
|100/101/102/103/104|107f/117f/227f/237f/127f|Create ISO/CAN/VPW/PWM, delete diagnostic interface|
|105/106|207f/217f|Create/delete DLC12|
|107/108|137f/147f|Create/delete monitor|
|109/10a/10b|157f/167f/177f|Setup packet/pair/DTC monitor|
|10c/10d/10e|187f/197f/1a7f|Start, get monitor data, stop|
|10f/110|1b7f/1c7f|Active start/stop|
|111/112/113/114/115/116|1d7f/1e7f/1f7f/247f/257f/267f|ID map, pickup, system send, negative count, PSA interface, interrupt timing|

`get_monitor_data` decodes status, interface-ID/buffer list, five further native buffers and trailing u32; unproven buffer meanings remain neutral. `NativeMonitorRecorder(settings, client, interface_id=..., phase=...).capture(...)` executes group11, polls actual `0x197f`, runs packet/condition/window logic and always attempts every command in group12 with one fresh bounded cleanup deadline. A failed stop does not suppress later delete-monitor/delete-interface commands; the primary acquisition error and additional cleanup failures are retained. Group27 and trigger7 protocol groups require a matching `NativeDrsExecutor`; they cannot be silently omitted. Phase0 consumes all ordered frames; phase1 consumes the first frame. Interface is an explicit resolved provider input. The supplied phase must match the DRS field used by native `SetPhase`. `NativeMonitorBuffer.phase`, `.block_packets` and `.serial_mode` expose the proven setter inputs; historic constructor fields `buffer_size`, `frame_count` and `value_after_count` remain compatible aliases. `allocation_size` is the native ring `CreateBuffer` input. Unsupported phase, conflicting frame IDs and packets larger than the ring fail before start. The native packet generator supports block counts1/2; phase0/block2 uses the original lookup stride quirks. Phase1/block2 supports at least two equal-width initial frames, with every signal confined to the first ordered frame and a strict in-payload bit extent. DriveRecord binds each read packet to converter slot0; physical generator slots are not inferred. Other frame fields remain unsupported. Proven P4 Run/CreateDrs paths select phase0/block1.

`NativeRecorderCapture.packet_bytes()` emits native u32 timestamp plus frame payloads. `capture.monitor_buffer(settings, metadata, phase=..., block_packets=...)` builds native frame/signal/ring buffers for `snapshot.encode_monitor_buffer`, retaining caller-provided DM metadata. Techstream18 native constructors establish frame version3, signal table1, signal item4 and ring1, revision0. This bridge emits that explicit18 grammar even when selected metadata originates in12; it does not establish12 writer-version parity. Actual captures retain immutable native ring images. Serial0 preserves the configured allocation, original oldest/write/written fields and native equality-collision behavior; unused authored allocation bytes start at zero. Serial1 normalizes the selected native region to offset zero while retaining configured capacity. A manually constructed capture without ring state is encoded as a normalized authored region. No timestamp resampling occurs. Trigger window bounds use floor at the left boundary and ceil at the right boundary, with millisecond arithmetic. Native capture now composes the original unsigned time lookup, clamp-left-zero and floor/ceil byte selection through `recorder_buffer.NativeRecorderRing`. The standalone `NativeTriggerWindow` helper retains its bounded host wrap policy; capture no longer uses its retained history. Native out-of-allocation timestamp dereferences fail closed. DriveRecord capture explicitly selects the SH3 seek policy: interior sentinel/exhaustion exits with an uninitialized native return register fail closed rather than borrowing the different x86 `0/1` fallback. Aggregate packet input, retained window and exported capture bytes are capped at32MiB before joining/decoding. The configured allocation now uses recovered native overwrite, unread/free accounting and selected-region serialization. Its inclusive collision can advance oldest before bytes are overwritten. Native ring complement primitives are executable separately; static call/reference analysis finds no demonstrated active DriveRecord complement producer, and the constructor-zero capture path remains zero. Serial modes other than0/1 are rejected.

`capture.dm_bytes(...)` writes the full native DM envelope (version1/revision0), system table8100 then monitor table8101. `NativeRecorderSeries` adds native first-free `name-01.dm` through `MaxFile`, the minimum2MiB free-space check and repeated recording. Its injected filesystem supplies only `exists`, `free_bytes` and `write` primitives with deadline/cancellation keywords; the module itself does not open paths. Trigger type4 stops at record quantity; other modes accept an explicit finite `max_records` prefix. Host limits cap records/slots at100000. Successful DM writes remain reported if cancellation arrives immediately afterward; failed exports/saves restore the prior raw reference. Sliding references are then written as native eight-byte `SettingFolder\temp.dat` state using bounded finalization. A shared-client lease spans capture/series cleanup, and an executor lease prevents reentrant channel ownership changes.

The injected byte tests use authored native request/reply bytes, not vendor execution or physical transport. They cover acquisition, conversion, trigger/window output, native DM playback, cancellation, fault cleanup, J2534 masking and both Check Mode branches. Host DMCI117–11c and11e serializers and logical wire commands are also implemented: additional frame277f, Phase5 interface287f, data-ID setup297f, clear dynamic data-ID2a7f, Phase5 active start2b7f, RID monitor2c7f and routine info2d7f. These host exports do not establish support in every supplied WinCE firmware; peer NAK/error replies remain authoritative. Their selected-metadata producer generation is a separate shared dependency. Selected database records are not yet automatically compiled into all protocol-specific monitor setup commands. The shared `data_monitor.selected_p4_monitor` now resolves actual selected Freeze/PhyData/Unit/PatDisp metadata and P4 setup commands. `native_p4_monitor_buffer(plan, phase=..., allocation_size=..., name=..., text_encoding=...)` binds those named fields into native DRS: scaling order is divisor/multiplier/offset, extended DWORDs retain native order, block1 and recorder serial1 follow original producers. Phase, allocation, encoded name and language encoding are explicit inputs. The integration test creates an authored database, selects a profile, builds DRS, captures native DMCI replies and plays the resulting DM buffer. Vehicle selection/context and other protocol/special producer branches remain separate required inputs; this path does not establish entire generator parity.

## Native contract reconciliation and remaining gaps

| Native contract | Evidence / disposition |
|---|---|
| Adapter family | Original onboard code is Windows CE Hitachi SH3 `DriveRecord.dll` plus `ComPc32VIM.dll`, internal CF storage and a physical trigger switch. A generic J2534 adapter, Mongoose or JLR cannot be declared recorder-capable from diagnostics support. |
| Setting generation | `CommandAPI!CreateDriveRecordSettingFileAPI` builds `CCreateDrsFileSnd`, then calls `CCommCtrlMain::CommandExecute`; `CreateDrsFile_DT!Execute` provides a separate DB/protocol-dependent generator. The new codec can author native low-level records but does not reproduce this entire generator. |
| Start / status / stop / cancel | `OnboardRecorderService` implements recovered DiagTool USB/switch transitions through injected `Check`, `Execute`, `Cancel` exports. Enabled switch permits startup before USB state is known; known USB connection blocks startup and cancels active recording. Shutdown cancels active work. The real mode commands 1/2 are implemented, but their diagnostic/programming states are not recorder start/stop opcodes. Shipped ComPc32VIM explicitly rejects command `0x70`; the host export does not establish device support. |
| Read / list / download | `NativeVimFiles` implements actual native open `0x21`, close `0x22`, read `0x23`, seek `0x2e`, find-first `0x26`, find-next `0x27`, find-close `0x28` request/reply bytes. `list_files` and `download` bound entries/bytes/deadlines and close handles on success, errors and cancellation. Returned DM bytes can be parsed by `snapshot`. Transfer framing and native ACK session are implemented; bounded stream scheduling is in `recorder_transport`. Live USB behavior remains physically unconfirmed. |
| Configure / upload | DRS/INI bytes can be parsed/authored. `upload_settings` uses native create/open and write `0x24` packets, retries partial writes, rejects zero progress and closes the handle. `CREATE_ALWAYS` explicitly replaces its named remote settings file. `get_time` / `set_time` implement system-time 4/5 and local-time 6/7 packets with native SYSTEMTIME 8H, status u32 and BOOL u32 results. |
| Trigger parameters | Native settings have trigger type/duration/point, record quantity/parameter condition, PID/condition/value/unit-multiplier/unit-divisor, stealth IDs. NativeTriggerInfo, NativeTriggerCondition and NativeTriggerParameters implement the original core/header/list bytes and are exercised through native DRS files into an injected backend. `NativeTriggerComparison` recovers signed32 comparisons 3 = equality, 5 = less-than, 6 = greater-than, initial/sliding reference updates and native phase values. `evaluate_native_comparisons` implements AND1 / OR2 and evaluates every condition; one condition forces OR as the original does. Inputs must already be converted. `native_trigger_sign_value` recovers unsigned, two's complement and sign-magnitude conversion from the original SH3 instructions. `convert_native_trigger_value` applies signal affine conversion and trigger-unit mul/div, reusing independently recovered `signal_conversion.affine`. Inputs are already extracted raw signal values, not complete diagnostic frames. `NativeMonitorRecorder` now acquires native DMCI monitor replies, extracts recorded frame bits, converts values, evaluates conditions and retains the native pre/post trigger window. Full producer and special trigger-mode parity remain open. |
| Monitor buffer and signals | Tables `0x0002` and `0x0004` have full typed byte round trips, including nested table boundaries. Integer fields whose meanings are unproven retain neutral names. Vehicle table `0x0001` is decoded as native `CCmdSelectCarTypeVin`, with all three typed lists; model/selection integer meanings stay raw. |
| Records | Native files are `.drs` settings, `name-%02d.dm` recordings, temporary `temp.dat` and `VIM.vlg` log. No authored fixture is represented as an original vehicle recording. |

Consequently the final all-offline-software gate remains **OPEN**. The unresolved
items above are software reverse-engineering gaps, not all hardware-dependent.
Physical behavior is separately **PHYSICAL_UNCONFIRMED**.

Private evidence is retained under `analysis/evidence/no-car-6/`: source hashes,
exports/imports, x86 serializer assembly and REA function evidence. REA's `target_unavailable` rejects unsupported SH3. Static inspection was recovered with a private little-endian SH2 SLEIGH subset compiled from installed primary-source definitions; complete mapped DriveRecord, DiagTool, ComPc32VIM and DataListCtrl images were analyzed without execution. The original source gates SHAD/SHLD definitions behind SH2A; enabling those two definitions privately recovered the trigger sign-conversion path. Unresolved COREDLL ordinals remain explicit. Host x86 serializers and reciprocal VIM dispatch independently establish the supported packet layouts.
Neither provider error nor positive synthetic tests proves native parity.

Verification: `python -m unittest discover -s tests -p test_drive_recorder.py -v`.
Fixtures are authored literal binary layouts and injected adapters, with negative
truncation/length/type/capability, preflight, cancellation, deadline and fault cases.

Manual trigger inputs are observed button WinCE ticks. Native05914 consumes one available packet-count snapshot. A packet strictly beyond that tick marks the immediately preceding consumed packet when nonzero, otherwise the crossing packet. If no packet in that snapshot crosses the tick, the last packet becomes the marker. Post-trigger acquisition requires a following packet even when post duration is zero. The producer writes the entire available batch before consumption. Native05c74 drains its snapshot and compares only its final timestamp against the right boundary; mode0 retains later producer packets even when the selected window ends earlier. A batch larger than unread capacity fails with cleanup. These branches have authored native-byte regressions.

`native_monitor_buffer(ecu_id, signals, frame_sizes, selected_ids, ...)` accepts the shared typed monitor metadata for other proven producer families without importing their modules. The P4 wrapper remains compatible. Full setup from a fresh adapter still requires the shared producer's CreateDiag/CreateDM/IDMap/initialization/delete lifecycle; a plan containing only monitor setup/start/stop requires its explicitly preconfigured interface.

Core buffers, strings and lists preserve serialized core words as wire metadata; they do not emulate C++ object lifetime or `CCmdCore::Read` version normalization. Display items have a version-dependent body: only proven versions0/1/2 are accepted, and future versions fail before execution. Opaque DRS table preservation remains available for inspection.

`selected_car_info_frames(profile, cache, bus_id=..., category_flags=0)` implements the18 `GetFrmCarInfoVin_DT` producer over a shared `MonitorSupportCache`: selected function85 support, optional86 native multi-receive, exact category-specific function order, first successful frame, repeated-request mask OR and maximum timeouts. The native initial helper's status is retained as `ignored_initial_status`; cancellation and host budgets propagate. Negative cached observations retain their native behavior. Requests/replies are limited to the original255-byte work area and ten-message arrays; a short nonempty mask repeats its first byte through the observed reply length, matching native `CCmdList::GetAt` out-of-range behavior. An empty mask with a nonempty reply fails closed instead of dereferencing an absent native list node. Absent selected functions retain nativeC0040101, while malformed host metadata remains a host validation error.

Passive original12 witnesses also establish the outer generator order: writer2/0,
`DataMonitorRun`, first original buffer with serial1, Check Mode only for trigger7,
then unconditional selected VIN production after trigger records. Its selected
Check Mode/VIN generator helpers match18 instructions and switch tables after
named-import and documented address relocation normalization. The runnable
witnesses are `runtime/no-car-6/verify_create12_outer.py` and
`runtime/no-car-6/verify_create12_helpers.py`. Serializer implementations and
primitive packet layouts require their separate evidence; this comparison does
not establish the complete12 recorder grammar.

`selected_car_info_plan(..., driver=..., diagnostic_mode=...)` adds actual43 protocol headers and emits complete group27 connect/config/filter/init, request/read checks, optional function58 and disconnect. Pass these records as `build_native_drs(check_car=...)`. Generation requires real injected diagnostic payload observations through the typed cache/stream primitives; VIN strings or authored expected replies are not substituted. Tests serialize an authored DDB, resolve the selected profile, collect ordered primitive observations, round-trip native DRS and execute the resulting group27 through `NativeDrsExecutor`. The cache's source-build selector is explicit; this producer's recovered branch is18. Whole selected vehicle-context/table1 construction and remaining protocol-specific monitor lifecycles stay separate dependencies.

Clock callbacks must return finite values. Deadlines reject nonfinite or nonadvancing sums before any primitive, and callbacks are checked again after I/O. If a resource was acquired before the clock became invalid, bounded cleanup uses a context-local real-time fallback to close it; ordinary operations still reject that invalid clock afterward. Cancellation/deadline failures retain the original callback error as their cause.

Capture preflight reserves the native ring header and the structural minimum complete DM envelope. `NativeRecorderSeries` additionally checks the worst-case complete DM size against the actual supplied metadata and system record before acquisition. Standalone capture cannot reserve arbitrary metadata supplied only at later export; its export boundary remains bounded and rejects oversized output. The native ring primitive retains its separate allocation limit.

`native_monitor_buffer(..., default_signal_slots=...)` preserves native constructor-default slots left by source-proven metadata overwrite branches. Explicit slots must be unique in-range indexes with exact constructor-default fields; their three strings have stored length zero. Assigned empty labels continue to include their native terminator. The adapter accepts shared `MonitorSignalMetadata` directly for P4/P5/PSA/DLC12/packet producers; the P4 wrapper does not reinterpret other plan types.

`unassigned_short_name_slots` separately preserves constructor-zero short names for source paths that assign other fields but never assign this string (native P5 c8d0/cf40). These explicit unique in-range slots must contain empty short-name bytes; normal name/unit serialization is unchanged. Neither slot set is inferred from protocol or phase.

`selected_vehicle_vin(profile, cache, bus_id=...)` obtains the normal native
SelectCar VIN through actual selected85/86 transactions. Bus12 reads bytes3..19
from a bounded reply; other buses assemble the native four-byte segments with
service checks, drain/retry behavior and the original length accumulator.
A clear support bit returns `None`; transport errors preserve their native
status. The returned17 bytes may still carry the native unavailable first byte
(0/ff/?), which the selection state machine must check. Existing cache budgets
and cancellation remain in force. This primitive does not yet implement the
complete interactive regional7d state machine or variant14 fallback to category1c8.
Original18 category18d instead uses selected function103 with native no-init,
no-session extended communication; original12 retains85/86 for that category.

The terminal CategoryMaster adapter retains the native last matched level
across requested IDs. An unknown ID first fails C0040001; an unknown ID after
a valid category uses that preceding category's value and label. This ordered
behavior is verified across all six original regional source bodies.

Nonzero DMCI reply status raises `NativeDmciError`, a `RecorderError` subclass
whose `.status` retains the original DWORD. Consumers can map that native
result without parsing text; host timeout/cancellation/context exceptions stay
unchanged. VIM transport-control failures remain `NativeVimError`.

`selected_vehicle_context(..., communication=...)` can resolve diagnostic
CarInfo1/2/3/16/17 through its actual `NativeCommunication` channel. It executes
the native empty probe and protocol3/4 query tables, preserving request order,
Ever-cache reuse, raw identifier bytes, native year/numeric formatting and
regional phase21 behavior. Without that channel these fields remain explicit
unsupported requests. Native12 stack-copy overflow and unrepresented failure/partial receive state
fail closed;18 retains its proven copy clamp. Known Ever-negative empty replies
retain native constructor/prior header bytes and formatter defaults.
`NativeVehicleSelector(communication, info_ids=..., text_encoding=..., division=...)`
now binds automatic7d to actual `NativeCommunication.protocol_context` and
`check_protocol`. `select()` runs ordered protocol probes, native85/86 or103 VIN
acquisition, raw13B decisions before registration pruning, division priorities,
and the protocol3/4 identification/129 fallback. `answer(group, choice)` follows
staged native option queries, registration checks and protocol resume. Both return
the recorder-facing `NativeVehicleSelection`; the pending option key and hidden
VIN registration name remain on the owner. A later terminal answer reconstructs
the provider with real shared Ever observations, without another empty probe.
Empty priority results retain the constructor output rather than entering129.
Protocol candidates use `build_protocol_profile`, which reads management
metadata without binding an ECU database. This preserves candidates such as
EU491 whose native category has an empty ECU filename. Binding a final ECU
resource remains a separate catalog operation.

`NativeVehicleSession(communication)` owns the embedded ShareData2A VIN list
recovered from the original DiagCommCtrlMain constructor and destructor. Pass
that owner to `NativeVehicleSelector` to retain first-match category observations
across selections, including seventeen zero bytes after native acquisition
failure. `vin_entries` exposes immutable observations; `dispose()` clears the
vehicle owner independently of the adapter. Cancellation and invalid host state
do not create negative observations. Passing the communication directly retains
the separately proven absent-slot path.

`NativeVehicleSession` also retains the ordinary18 manual category state used by
the selected `SelectCarTypVn10_DT.dll` NA translation. Its
`NativeVehicleSelector.select_categories(selected_ids, bus_judge=...)` returns an
immutable `NativeCategoryMenu`; the menu is not a DRS table. A fresh selector
using that same session can consume mode1/mode2 through `select()`. The adapter
admits only source build18, native controller build18 and the first actual DB113
selection naming `SelectCarTypVn10_DT.dll`; EU Brd and JP Std sources reject the
manual entry before communication. Retained state is bound to the catalog,
management hash, selected DB113 row and exception IDs, and is invalidated by
session disposal.

`select_multigroup_categories(selected_ids, bus_judge=...)` admits the selected
NA18 category-command row `SelectCarCtgrMltOpt.dll` and builds the embedded1D
option-group list from the surviving DB129 and DB12A records. The list retains
source order and duplicate labels; `multi_option_groups` exposes immutable
snapshots of its ABI fields. The actual 5190/58D0 selector path uses those
retained entries, including hidden duplicate IDs, sibling next-group updates,
and terminal formatting through the shared communication/provider state.
Ordinary category production leaves an existing1D list untouched, and a later
7d answer follows that list when present. The adapter requires source build18,
native controller build18, the first selected DB113 7d row naming
`SelectCarTypVn10_DT.dll`, and the first selected DB113 48 row naming
`SelectCarCtgrMltOpt.dll`; this is source admission, not runtime OEM DLL hash
attestation. Host-side safety ceilings cap retained 1D data at100000 entries
and the serialized response at32 MiB; more than65535 unique synthetic select
IDs is rejected before append instead of emulating the native WORD wraparound.

The authored Multi controls use serialized synthetic DDB data and the real
`NativeCommunication` adapter. They cover duplicate-text IDs, sibling mutation,
terminal answers, stale1D crossover, cache-negative behavior, fallback ordering,
and mode2 clearing. They do not prove every regional GUI lifecycle, the full
family of provider consumers, or physical communication. Existing automatic
12/18 tests remain independent and unchanged.

The selected vehicle context models the recorder-facing GUI export: ordered
names/options and terminal words survive, while display-only CarInfo IDs
16,17,18 are removed after their native diagnostic processing. Original18
constructor and merge instructions establish the exported object at parent+e84.
