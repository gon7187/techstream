# Utility XML execution

`scripts.utility.UtilityRuntime` executes decrypted `UtilityResource` trees in Python. It never loads a vendor DLL or opens a transport. Obtain resources through the strictly bounded SRP decoder in `scripts.script_vm`, then explicitly inject the exchange, library and dialog services needed by the selected utility.

```python
runtime = UtilityRuntime(
    resource,
    ecu="selected-ecu",
    exchange=fake_exchange,        # (ecu, request: bytes) -> response: bytes
    receive=fake_receive,          # (ecu) -> next response, without retransmission
    library=host_library,          # (name, argument_tokens, storage) -> integer status
    dialog=choose_event,           # screen -> key or event dictionary
    cancelled=is_cancelled,
)
report = runtime.run(function_id)
```

Interactive hosts can call `start(function_id)`, inspect `screen()`, submit `display(values)` for display/selection events, `key(id, values)` for radio choices, and submit `progress(elapsed_ms)` for progress events. `report()` returns JSON-compatible storage, ordered execution events, status and provenance. Dialog callbacks may return a key string, `{"key": "2", "values": {"INT02": 1}}`, or `{"elapsed_ms": 1000}`. Missing callbacks fail at the operation requiring them; no implicit successful ECU operation is supplied.

The executable grammar covers every tag and attribute in the 18 privately inspected Techstream 18 SRPs: block and popup navigation; communication actions; `IF`, direct bodies and `THEN`/`ELSE`; `CALC` assignment, `_PLUS`, `AND`, `OR` and comparison expressions; `CALLFUNC`; `RECEIVE`; initialization, fast, display, key and progress actions. `INITACTION`, also present in the native parser table, runs when entering a block. `FASTACTION` runs on entry; `DISPACTION` updates key availability. Radio defaults initialize their output. `PROGRESS` exposes timing in the screen descriptor and accepts monotonic host events at `UPDATETIME` intervals. Hosts own delivery of timer events and presentation/localization; presentation text is preserved without embedding vendor resources.

`BLOCK` switches screens, `POPUP` saves the underlying screen, `POPUP_OFF` restores it, `RETURN` restores the prior normal block and `END` terminates. Transitions execute iteratively, including communication-to-communication chains. An action stops the current command list; commands after it are not executed. `AFTER` commands run after matching a response and can replace the event's default transition. Unknown executable tags, attributes, children, expressions, block IDs and navigation underflows fail explicitly.

Communication `SEND` frames contain `$`-prefixed hex bytes or declared byte values. Response frames use the same form with `*` as a wildcard byte; matching compares the specified prefix, allowing longer responses. The first matching non-SEND event wins. `NORESP` matches an empty response or a transport `TimeoutError`. `RETRY` limits retransmissions; `NEGRETRY` covers retryable negative replies. `NEGREPEAT` continues reception through `receive`, bounded by `REPEAT`, `TIMEOUT`, the global deadline and instruction budget. Pending replies never cause an implicit retransmission. `OTHER` is normally a wildcard fallback. `WAITTIME` uses the injected clock/wait service. `SEND TIMEOUT` also checks elapsed callback time; actual blocking I/O must enforce its own timeout.

`RECEIVE POS` is **one-based**, established by the decrement at native executor RVA `0xf5b5`; `SIZE` is checked against the received buffer. Default endian is `BIG`; explicit `LITTLE` is supported. Integer destinations receive the converted integer; byte destinations retain their declared width. The shipped corpus uses one-byte destinations. Unlike unsafe native out-of-bounds behavior, malformed positions and widths are rejected.

Host safety limits are explicit: XML and aggregate retained storage/response/trace are at most 16 MiB, XML nesting is at most 128 with 100,000 nodes, navigation stacks have 4096 combined entries, the default instruction budget is 10,000 and deadline is 300 seconds. Cancellation is checked around callbacks and waits. Callback storage changes are validated before committing them. Callbacks are trusted injected code and must bound their own allocations and blocking time; Python cannot interrupt arbitrary synchronous host code. These limits and rejection policies are host choices, not native capacity claims.

## Library binding ABI

`library(name, arguments, storage)` receives the function name, a tuple of original string argument tokens with CSV quoting removed, and a copy of declared storage. For example, an authored text `"7","INT02"` becomes `("7", "INT02")`. Numeric tokens are values held in mutable native temporaries; storage tokens refer to mutable declared values. A provider resolves input tokens and updates the corresponding storage entry for output references. Writes to numeric temporaries do not survive the call. The callback's returned integer is assigned to the XML `OUT` **after** argument writes. The returned wrapper status is distinct from an operation result written through a reference.

The native descriptor is 12 bytes: a type word, index word, pointer at offset 4 and length at offset 8. Type 1 identifies integers; type 4 identifies byte storage. No native pointer, function or DLL is exposed to a script. The interpreter requires providers to preserve declared storage keys and supported value types. The parent integration module `scripts.utility_bindings` supplies the Toyota host implementation; the runtime itself does not manufacture support tables, ECU IDs or session success.

The following is the complete function-name set observed in the decrypted corpus. RVAs refer to `UtilityExNeoNK.dll` unless stated otherwise. Integer arguments retain their order. "Return" denotes the integer assigned to XML `OUT`.

| Function | RVA | Arguments and observable contract |
| --- | --- | --- |
| `InitialCom` | `0xfde0` | One in/out integer: input converted to boolean; writes initialization result to it; returns wrapper status 0. |
| `FinalCom` | `0xfe30` | One output integer receives finalize result; returns wrapper status 0. |
| `ChangeSessionMode` | `0xe3d0` | One integer, accepted values 1 or 3; returns communication result; successful reply shorter than six bytes becomes result 3. |
| `SetNrLimitTime` | `0xe590` | One integer configures the negative-response time limit; wrapper returns 0. |
| `SetResponseNoCheck` | `0xe860` | One integer toggles response validation; wrapper returns 0. |
| `SetUseReqMode30_3BFuncFlag` | `0xff80` | One integer converted to boolean, stored as request-routing flag; returns 0. |
| `ChkA8SptInfoForBitWrap` | `0xf720` | Five through eight integers: input support selectors, final output reference receives lookup result; returns 0. The corpus uses five arguments. |
| `GetSptTableDataPosRecvData` | `0xfb90` | Five through eight integers: input support selectors, final two output references receive lookup result and selected data byte; returns 0. The corpus uses five arguments. |
| `SleepThread` | `0x100b0` | One integer duration in milliseconds; returns 0 after the wait. |
| `StartExtendedSessionP5` | `0x101a0` | One integer converted to boolean; returns underlying session result. |
| `EndExtendedSessionP5` | `0x102a0` | One integer converted to boolean; returns underlying session result. |
| `StartComThread` | `0x103a0` | One integer selects worker 0 through 3; returns busy status 15 if already running; selection 3 waits for completion. |
| `StopComThread` | `0x10430` | One integer controls abort/await behavior; returns worker status. |
| `GetThreadStatus` | `0x10510` | No arguments; returns worker status, including 15 while busy. |
| `GetThreadRecvData` | `0x10520` | Two integers: receive-data offset and output reference; writes selected data value and returns 0. |
| `GetEcuId` | `IT3UtilityNeoNK:0x14a0` | One output integer receives selected ECU ID; returns 0. |
| `GetComProtocol` | `IT3UtilityNeoNK:0x14e0` | One output integer receives selected protocol masked to a byte; returns 0. |
| `GetProgButton` | `IT3UtilityNeoNK:0x1560` | No arguments; returns 0/1 and acknowledges the progress-button state. |

Type/count validation failures in the extension wrappers return 99; the two utility-host output getters return -1 on invalid arguments. These statuses belong in providers, rather than being silently changed into successful operations by the interpreter.

Static evidence: `IT3UtilityNeoCtrlNK.dll` SHA-256 `478df6d2bf27b0ca8df31fd7d02d43231f6e25a103de6fa61b421c93432bf0e7`, XML parser command table at `0x1bde4` onward, CALLFUNC parser `0x6d90`, CALLFUNC execution `0xdd30`, command dispatch `0xb720`, RECEIVE execution `0xf580`, comparison `0xebd0`. Extension SHA-256 is `5b36acc8aa9c58dcac9dc433e3c9fa26ee7e53e85acc70996a47e0d63c27d1cc`; function pairs are at `UtilityExNeoNK:0x141e8` through `0x14318`. Utility host SHA-256 is `1953edf8821af8c7df612c383c756b87febb3ce7ba055744305ca5db4c2f37a6`.

Regression command: `python -m unittest discover -s tests -p test_utility.py -v`. Authored synthetic fixtures test real execution, by-reference callbacks, branches, frame assembly, response extraction, retries, pending receive, popup/back restoration, radio/key/progress events, missing dependencies, callback failure, cancellation, loops, memory and deadlines. Private corpus checks verify all 18 original XML trees against the supported schema and execute a terminating dialog path for each using explicit fake services. All 45 communication definitions are exercised: 231 event cases execute the asserted event type, and one additional `OTHER` event is statically shadowed by an earlier `SUCCESS` wildcard with the identical terminal action. This is software execution evidence; it does not establish successful operation on a vehicle. Vehicle effects remain `PHYSICAL_UNCONFIRMED`.

## Native TY2 procedure controller

`NativeUtilityRuntime(NativeProcedureLibraries(caller_bytes, engine))` now executes
source-owned native controllers. `start(0x1381d)` selects the TY18 Door connection
history clear workflow. This is native procedure control flow authored in Python,
not an XML translation, user-supplied operation plan, or business-success callback.
The exact TY2 and UtilityEx source pair must pass the library source binding.
Other procedure identifiers and source versions fail closed.

The source constructor registers initial screen `0x1381d` and success screen
`0x1381e`. Start invokes IAT `0xc1898`; only native status 15 opens progress with
resource IDs `0x94b6`/`0x94ba`, duration 10000 ms and update 1000 ms. `progress(ms)`
consumes monotonic host events and polls IAT `0xc1958` at the update interval.
Busy 15 preserves the dialog. Result 0 closes progress and selects success screen;
result 1000 closes progress and selects resource IDs `0x94b7`/`0x94bc`; other results
select the generic native error IDs `0x104a`/`0x104b`. The injected engine executes
the actual recovered TY business provider, including its normal/extended session,
clear request, normal-session restoration and lower-controller finalization.

`screen()` and `report()` expose these events to the normal host presentation
adapter; native resource text is neither bundled nor manufactured. The host event
`key("acknowledge")` dismisses a result. That event name and result acknowledgment
API are host presentation policy. Native progress cleanup stops/hides the progress
dialog and removes timer `0xfa00`; it does **not** stop the business worker.
`cancel()` is a separately identified host safety policy: cooperative cancellation
and join of the existing owned `UtilityWorker`, without forced thread termination.
A failed join retains worker ownership and reports `cleanup-failed`. Known
cooperative `Cancelled` exceptions become a cancelled result; other provider faults
propagate. Host limits are 300 seconds, 300000 event milliseconds and 10000 trace
entries. Injected callbacks still must bound their own blocking operations.

Source: `IT3UtilityTY2.dll` SHA256
`ecba533aeaa2ec2a014fa59a113d025a8efe90338767c2786b8a5a891ca0f599`;
constructor `0x37ef0`, entry `0x38030`, start `0x38150`, poll `0x381a0`,
status chain `0x51d90`→`0x4e040`, progress cleanup
`0x51910`→`0x4a520`→`0x6aaa0`. The independent native library bridge owns exact
receiver marshalling for other methods; that is not evidence that their outer
procedure controllers execute. Those controllers, other native source versions,
MFC presentation parity remains explicitly open. The normal Door desktop route
has separate source-pinned GTK evidence owned by leaf11.
The SpNK CCU state-machine audit is private evidence; its unavailable CAN/SIL/repro
lower dependencies are not bypassed. No source-bound full-native-utility coverage
claim follows from this controller.

The normal application can construct this same controller with
`runtime, recording = open_native_utility(caller_path, engine_path, recording_path,
cancelled=...)`. This reads bounded regular files and constructs the real
`UtilityExContext`, `NativeProcedureLibraries` and `UtilityExEngine`; it never
substitutes the communication facade. `recording.report()` exposes input
provenance and consumed/total primitive counts. After a completed replay, require
`recording.assert_complete()` before presenting the chronology as consumed.

The recording JSON has exactly `schema`, `source`, `caller_sha256`,
`engine_sha256`, `broker` and `events`. Schema is
`techstream-native-utility-v1`; source is `authored_synthetic` or
`recorded_unverified`. Both source hashes must match the selected files. Broker
keys are canonical decimal strings with explicit DWORD values; absent values fail.
The events use the existing `ProgrammingTrace` typed chronology. Only `action`
records for literal native DRIVER SDK names or OS `wait` are admitted. A DRIVER
request contains `operation` and positional `arguments`; the typed mapping result
contains `status` and an `outputs` mapping keyed by zero-based argument indexes.
Byte buffers use the existing typed bytes format; received messages use the typed
`PASSTHRU_MSG_2026` data record format, which represents an SDK message rather than
a 2026 communication algorithm. Positional output writes preserve the caller's
mutable backing. Each OS wait must contain its actual elapsed duration. Duplicate
JSON keys, business-operation callbacks, wrong chronology, oversized inputs,
invalid outputs and unconsumed events fail visibly.

The source-bound TY18 Door fixed manager `native:1011d4f0` is now joined to the
real native communication lifecycle. Exact-source private checks cover normal
completion, a native NRC result, a raw SDK host fault and cancellation inside a
blocked raw read, including both filter releases and disconnect. These are offline
raw-primitive recordings, not physical effects.

`replay_native_utility(caller_path, engine_path, recording_path, language_path,
symbols_path, dialog=..., cancelled=...)` is the normal desktop composition. It
selects group `0x1346` from the actual native factory (TY2 RVA `0x6b705`, jump
table `0x6beb8`, case `0x6bcaa`, constructor `0x37ef0`), reads the actual U-language
and `UtilityResID_NK.rsd` through `UtilityTextResources`, and passes source-resolved
screens to the existing host dialog contract. There is no management-language
fallback. Reports retain each entry's language pool, symbol offset, native key,
row and source hashes. The close/acknowledge event is a host presentation policy
using an actual common source caption. Other source-owned controllers remain
open unless explicitly admitted below; arbitrary operation plans are unavailable.

Optional `broker_data` contains explicit canonical decimal keys with hexadecimal
byte snapshots, such as the native communication configuration producer. An
absent byte producer fails rather than supplying zero/default data.

The same runtime also admits TY18 DCM45 initial screen `0x13723`, with success
screen `0x13724`, through its selected execution event `start(0x13723)` and RSD
group `0x1352`. Normal replay selects `NativeDCM45Runtime`, whose `open(0x13723)`
first presents conditions `0x948d`. Source Next invokes the actual CGW security
worker through IAT `0xc1964`; its machine return preserves native scheduler EAX.
The ordinary broker112=18 path is joined through the real selected communication
manager and raw SDK. Broker112=20 additionally invokes actual Initialize and
InitializeDoIP. Its actual standard/SIS primitive tables are kept separate;
the tested conditional branch executes all source calls and returns native
business result99, which presents the source generic error. Factory table index23 selects
case `0x6baed`, which constructs controller `0x33040`; receiver method `0x33180`
passes its stable four-byte `this+0xe8` storage to the actual DCM45 export.

The progress timer calls screen virtual slot `+0xfc`, resolved to `0x32de0`.
State1000 polls the native worker, stores a terminal result in screen field
`+0x38`, and dispatches state2. Completion `0x3b040` polls once more before
`0x33310` branches on the stored result. The host drains this queued completion
inside the progress event while preserving both native calls and their distinct
results. Result0 selects the success screen and formats the output byte as
unsigned decimal; result2005 selects source warning `0x948c`/`0x9492`; other
results select the common source error. Host acknowledgment and cooperative
cancellation retain the same explicit presentation/ownership policies as Door.

Private exact-source DCM45 checks compose the real factory, libraries, native
wrapper, business body, fixed communication manager and raw SDK facade. Success,
native warning, raw write fault and cancellation inside a blocked raw read all
replay their complete primitive chronology, including filter/disconnect cleanup.
The text adapter resolves the selected/common U/RSD resources with per-entry
provenance. This establishes the selected execution event only; the other
44 receiver methods and their surrounding workflows remain open.

For Door, `open(0x1381d)` presents the actual initial conditions resource `0x94b8`
without starting native work. Its source navigation key uses caption `0x102f`
(TY2 `0x2b600`) and invokes the screen's actual Next callback `0x38150`.
`replay_native_utility` uses this entry, then accepts `next` before the existing
progress and result phases. Its eleven-resource preflight includes the initial
conditions and Next caption. Cancellation on the initial screen opens no SDK
channel. Direct `start(0x1381d)` remains the selected Next execution event for
callers explicitly invoking that stage.

Door generic errors preserve the source return to the initial conditions screen
(TY2 `0x38160`/`0x381bf`). After dismissing that error, `next` can retry the same
controller and context; elapsed progress restarts at zero. The native1000 warning
closes the procedure after dismissal. Exact raw recording checks cover an SDK
Connect error followed by a successful same-controller retry, in addition to
initial-screen cancellation and the existing worker fault/cancel paths.

## Native EFI61 controller

`open_native_utility(..., function_id=0x13308)` selects
`NativeEFI61Runtime`, bound to the actual TY18 factory group `0x1334`.
Opening invokes source receiver method `0x1ffe0` against the same 24-byte backing
throughout the workflow. A successful support query presents native conditions
`0x13309`; Next selects `0x1330d`, containing only the supported source choices.
Choice IDs remain native indices 0 and 1, including ID 1 when only the second
choice is available. Next accepts `{"selected": [0, 1]}` (or either supported
subset), writes the native selection DWORDs, and invokes `0x1fff0`. Empty,
duplicate, boolean and unsupported IDs fail before starting work.

The production text adapter resolves the native choice texts `0x9ae9`/`0x9aea`
and source Next caption `0x102f`; `requires_selection` tells the host to disable
Next until a supported checkbox is selected. Completion selects `0x1330c`;
a write error returns to the conditions after acknowledgment. A support error
closes after acknowledgment. Worker ownership and cooperative cleanup use the
same engine state as the Door controller.

Private original-source checks run all four support vectors through actual
receiver methods, TY business providers, native communication and raw SDK
recordings: both choices consume 32 primitives, either single choice consumes
30, and no choices consume 15 before host cancellation. The normal production
replay additionally resolves all 14 possible text resources and checks the
five-screen path. Fault and blocked-read cancellation exercise lower cleanup.
These checks do not establish vehicle effects or other controller coverage.


The full DCM45 CGW phase uses progress IDs `0x10b7`/`0x10ba`. Successful
security access starts the source DCM45 receiver method; native results
10002–10004 present `0x10b6`/`0x10b9` with source caption `0x10b5` and close.
Results 10005–10007 present `0x10b6`/`0x10b8` with source captions
`0x1044`/`0x1046`. The retry choice returns to the existing conditions without
automatically starting another worker. Other errors use the generic native
modal and close. The normal adapter preflights 19 possible source resources.
Private original-source checks cover success and native2005 (32 raw primitives),
CGW session failure10002 (12), authentication failure10005 (24), an SDK fault
(8), blocked-read cancellation (9), and authentication retry followed by success
(56), preserving actual filter/disconnect cleanup. The conditional broker112=20
path consumes 18 primitives, including standard controller initialization and
both source SIS controller initialization calls, then reports native99. Credential material is not included in the result receipt. Desktop
admission of this controller remains independent from backend execution proof.

## Native BSM27 and BSM28 controllers

`NativeBSMRuntime`, selected by `function_id=0x137b8` or `0x137ea`, executes the
actual TY18 groups `0x134a`/`0x134b`. These wrappers require native broker111=4;
other modes retain the source99 rejection. Opening runs action0 through receiver
method `0x37390`/`0x37a00` with stable eight-byte backing. The provider retains
the original target in its native state and writes its probe status at offset4.
Only a zero probe status enters the shared native CGW controller on Next.
Nonzero probe status uses the direct action1 path. The real raw SDK timeout9
maps to native probe status2; it is not replaced with a successful probe.

The source timer distinguishes direct action completion from the stored-result
common dispatcher. Success selects `0x137bc`/`0x137ee`; native2000 and direct-path
errors use the source warning with captions `0x103f`/`0x1040`. The first choice
returns to conditions; native modal result200 closes. Generic write errors also
return to conditions. Probe errors close after the source generic modal. The
shared CGW code preserves the same native virtual flow as DCM45; each procedure
supplies its own source virtual174 handler, rather than an external operation
callback.

Original-source normal replay checks cover both variants and both probe branches:
33 primitives through CGW, 22 through the native status2 bypass. They verify the
saved target and final restored target, consume the full chronological raw trace,
and resolve all 22 possible source text resources. Desktop admission is separate.

BSM negative checks additionally exercise both source warnings and same-context
retry through the normal adapter: CGW paths consume 34 primitives for a warning
and 58 after retry; bypass paths consume 23 and 32. Both variants independently
exercise raw SDK fault and blocked-read cancellation, including both filter
releases and disconnect. The source modal caption join is separately audited:
caption argument5 maps through control `0xbca` to native result100, argument6
through control `0xbcb` to result200. Public code contains no native dialog bytes.

The five admitted native resource groups were checked against all 13 original
Techstream18 U-language files: 65 combinations resolve all 1144 preflight entries
without missing keys. This does not add native controller or physical coverage.
The current receiver inventory distinguishes 42 available business bodies from
five of 45 receiver methods with admitted outer controllers. Door uses a separate
direct thunk. Other controllers remain open.
