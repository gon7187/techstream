# Actual CUW2026 Phase6 and CAN DCMPRL

The implementation uses authenticated actual2026 sources. It neither loads vendor
DLLs nor opens a communication device. All I/O is injected through
`NativeRuntime2026`; physical behavior is **PHYSICAL_UNCONFIRMED**.

`scripts.programming_2026_p6` currently provides:

- `bind_native_context(...)/execute_context(context, runtime)`: canonical actual31
  selected parameter row, exact supplied DLL bytes, actual47 CUW metadata and
  actual48 address producer. Frozen contexts carry a factory identity proof;
  manual geometry and undeclared overrides fail before execution. The supplied
  runtime survives between exports, preserving P6 periodic ownership. Native
  controller timing, retry, tester and UTC-date observations remain explicit.
  Prepare/flash report their source-proven BOOL as `native_return`. Getters
  return vectors and expose their output-argument BOOL as `native_success`, with
  `native_return=None`; both retry resets are void with `native_return=None`.
  Typed native failures preserve that ABI distinction and recovered enum/status
  fields. Host cancellation and provider faults remain exceptions.
  Canonical P6 preparation binds the shared actual AES composer from exact
  SecretInfo/CUW bytes. Its decrypt/encrypt operations run locally within the
  existing runtime's cancellation, deadline and call budget; transport receives
  only its primitive operations and the derived-key CAN frame.
  Nonvoid exports require the engine-issued `dh_state` matching the selected
  metadata. Writers require its configured persistence notification before I/O;
  DCM getters additionally require the active `dcm_getter_state` record view.
  Native errors, retry, byte counts and percentages mutate this actual state.
  A captured retry Boolean can only confirm the current engine flag.

- `DCMPRL2026(context, action, ...)`: native CAN DCMPRL version getter, prepare
  and flash chronology. The provider supplies primitive host operations, including
  complete address-prefixed CAN reads/writes through shared `CanDiag2026`.
- `native_dcmprl_plan(container, cpu_index, module, ...)`: immutable CUW image,
  ECU/CPU classification and exact2026 module binding. It consumes the actual
  archive's `GetData` and `GetFlashSize` values; raw S-record text is never a
  binary flash buffer. Noncontiguous Intel HEX inputs fail before communication.
  Three-byte communication
  IDs must come from the native host selection table. Parameter names are
  `ReceiveTimeoutBeforeGetCID` and `WaitTimeAfterEndOfFlashing`. Standard CPU
  archives additionally require the selected Boolean `FlagToHoldSFormatRecords`;
  a preserved record map has no contiguous DCM flash buffer and is rejected.
- `get_phase6_cids(runtime, nodes, ...)`: native F188 count/17-byte records,
  unresolved `?` polling, placeholder filtering and programming-DTC fallback.
  Start timestamp and the two elapsed-time thresholds are explicit native host
  state, rather than invented CUW metadata.
- `process_before_ig_off_on_at_retry(runtime, target)`: both Phase6 prepare and
  flash retry exports reset the selected CPU's node through `Unified2026`.
- `prepare_phase6(runtime, context, secret_client, retry=..., gateway_kind=...)`:
  native functional/legacy broadcasts, OTA/IG-off handling, gateway discovery,
  gateway key collation/routine modes, periodic messages, programming session
  and service authentication. Successful preparation retains the periodic
  resource in the same runtime for the flash stage; failure releases resources.
  Authorized cryptographic primitives come from the shared source-backed contract.
  `native_phase6_prepare_context` imports the node timings, protocol, gateway
  mode, service key and first logical block's hexadecimal `P4ServerMaxTime`
  multiplied by60; these values are never operator-supplied geometry.
- `native_phase6_nodes(container, module)`: imported node diagnostic targets and
  actual2026 hexadecimal wake-time scaling, without manually supplied geometry.
- `Phase6FlashChannel`: native DD00/FF00/DD01/DD02 routine framing and
  download/transfer/exit helpers, including send-timeout restoration, negotiated
  bounded block lengths, strict sequence acknowledgements and counter wrap.
  It also writes native F120..F13F/F050 programming information, retaining
  tester padding and the native decimal-text-to-hex date representation.
- `native_phase6_flash_plan(container, module, node=...)` imports actual2026
  logical areas, CPU associations and archive aliases into a frozen plan.
  `Length`, `TransferLength` and `CheckData` remain distinct native fields.
  `flash_phase6(runtime, plan, tester_id=..., system_date=..., state=...)` runs
  the information/download/authentication/erase/content/verify/end/reset/default-
  broadcast path over ordinary buffers or authenticated large-file backing.
  Method classification controls erase and content selection; only native method
  strings02/03 select wire formats11/21, while other known codes retain raw01. It preserves acknowledged-byte evidence and clears
  per-CPU visible progress on failure. The same prepared runtime owns periodic
  cleanup. Tester bytes and the observed UTC date are explicit host inputs.

DCM getter starts its native7000-ms countdown in500-ms steps, querying the
separate native cancellation callback after each step. Cancellation there reports
native success with an empty identifier vector; cancellation inside reception
throws the native exception. Host cancellation/deadlines remain separate policies.
DCM exports sharing a runtime release only their own filter/timeout/connection
resources, retaining a caller-owned programming connection.
Explicit native StopFilter exceptions in the export cleanup tails preserve the
already-computed business BOOL and remain reported as suppressed cleanup errors.
An untyped provider fault propagates with its original Python type. Native
programming failure resets progress after StopFilter and before timeout restore;
host faults retain assignments already executed.

P6 getter also observes the explicit native cancellation callback after filter
acquisition and before sending F188. A true result skips that request and still
runs the native no-identifier/DTC policy. Reception checks the callback separately;
the getter converts its generic native exception to CPass9999. Only driver
statuses9/16 permit DTC fallback. Filters retained by a native skipped-read path
are explicitly released by conservative host compensation before disconnect.

DCMPRL's native first prepare attempt resets directly; retry obtains a two-byte
seed, applies the recovered arithmetic and sends its key before reset. No embedded
secret is needed. Flash starts RID0200 or0201, splits the imported image into1024
byte regions, downloads each with24-bit offset/length, transfers60-byte chunks
with per-region sequence restart, sends the16-bit byte-sum at transfer exit,
stops its routine and resets. Denso DCM suppresses the per-transfer100ms sleep.
`DCMPRLContext.flash_size` must be source-bound for flashing. Native progress
uses this value separately from the materialized image length; an S-record span
with gaps can therefore produce a percentage above100, exactly as the source.
Native500ms countdowns reject nonmultiples before I/O to avoid the source's
nonterminating decrement case. Flash publishes `wait_remaining_ms` before its
filter is acquired and after every500ms decrement, matching callback13. Failure
cleanup restores the timeout and releases
filters; native progress reset uses the actual2026 common helper.

Authenticated large sources use the actual descriptor's inclusive source spans
and four address groups. Reads stay within5-MiB windows; binary zero padding,
S-record lookahead/record boundaries and zero-tail counter restart are preserved.
Descriptors are validated against the issued source producer before communication
and again when consumed. A changed or closed backing fails explicitly. Native
GetLength remains the original payload length, independently of descriptor144.

**Coverage remains open.** The host callback that advances a CPU boundary still
needs integration with the actual controller; plans crossing CPUs fail before
communication. The logical-block callback is a source-verified assignment to the
caller's selected-logical-block state. Independent scoped native/wire reviews
cover the single-CPU main and large source-to-provider path. Full exported CFG,
DCMPRL/P6 preparation/getter integration and actual CUW controller transitions
still require review before complete family claims. DCM getter host contact-type
record integration and full error/cleanup scope still need independent review.
`dcmprl_getter_host_records` applies through the active engine record view before
cleanup; it retains the identifier string and contact-buffer tail while resetting
the discriminator and conditionally writing CAN. The gateway-kind1 branch still
needs its distinct256-byte worker producer; AES recovery does not supply it.
Canonical large writers also require a source-issued streamed persistence input;
a small substitute source cannot stand in for an actual large calibration.
Existing12/18 modules are
never selected as a2026 fallback.

All fixtures are authored. Private binary/decompilation evidence is held outside
public source under `analysis/evidence/no-car-21/source/`; owned source hashes and
reconciliation status are under `analysis/evidence/no-car-32/`.

Check: `python -m unittest discover -s tests -p test_programming_2026_p6.py -v`.

DCM native filter-cleanup faults are suppressed while retaining the saved business
result. Timeout restoration and getter disconnect execute outside the recovered
MSVC try ranges: their original exceptions escape without a terminal native BOOL
or success-outparam inference. Host Python exceptions likewise propagate without
being converted to native catch-all outcomes.

The Phase6 writer follows the native272a CPU boundary inside the same export:
when adjacent logical blocks belong to different CPUs, the engine-issued worker
updates the current source-selected CPU synchronously. It does not queue another
prepare/write phase. An actual active engine, its shared runtime and the original
logical-block CPU sequence are required before any multi-CPU I/O.

Current integration checks use all six selected modules and both retry exports
through the public replay factory, actual engine state, native bridge and recovery
persistence. They include a two-CPU node and a host fault immediately after its
CPU transition. Both authenticated300-MiB S-record and binary sources execute
through that same factory using one pinned container shared by engine, replay and
recovery cache. Full saved-source hashes match; traced Python allocation peaks
remain below24MiB. These checks use injected communication and do not establish
physical vehicle or adapter behavior.

Gateway key callback26 now requires the concrete source-issued online controller
and primitive replay chronology. The256-byte gateway key is produced separately
from the16-byte Phase6 AES key. Opaque action-provider key-success values are
rejected by the shared runtime.

DCM failure-tail progress callbacks execute outside the native catches at18c6.
If resetting count or percentage throws, that exact exception escapes; the next
callback, timeout restore18d4 and BOOL return18f0 are not executed. The runtime
retains the timeout resource so a separate caller-requested close can compensate.
This applies equally to host faults, cancellation and typed native exceptions.

The mixed-CPU check currently proves source-selected CPU changes, +360 logical
ordinal, counters and persistence only. Full3f620 callback equivalence remains
OPEN until its elapsed/gating and outer-controller effects are reconciled; the
state-selection helper alone does not certify the whole native callback.

Native progress arrays use the ordered engine+358 index. DCM reads and mutates
`DHControllerState2026.native_cpu_index`; P6 maps each source logical-block CPU
through the actual worker before accessing those arrays. The authored reversed
array-layout regression checks this distinction without claiming complete3ddf0
CPU-structure reordering. A canonical prepare control with Node01.Protocol01 and
Vehicle.Protocol02 selects the exactPhase601 catalog row through the shared native
selector; it does not fall back to02.

Cached P6 gateway state is a raw byte, including3/255. Every nonzero value skips
classification; only1 selects the Phase5 gateway key/routine branch. Canonical
getters return native CID byte strings to the controller; display decoding stays
at the report boundary. Prepare/write adapters consume the factory's issued
runtime metadata projection, so filtered blocks and already-reindexed CPU values
are retained. In-export CPU transitions use the actual engine handoff, including
the outer thread when present.

The retained IG-cycle helper has current prepare/write controls: exact selected
DLL and operation/phase are preserved, the literal void reset export emits one
reset write, and no invented sleep changes the shared clock. The selected P6
getter now writes source-derived 12-byte companion records for every CID
appended by each node, using that node's `GetDiagID()` value. The existing
outer getter callback imports the exact counted ID/record pair before the
Phase6 G selection completes. The source mapping, callback edge and host
contract are documented in
[`programming-2026-p6-cid-transfer.md`](programming-2026-p6-cid-transfer.md).
The mixed-CPU getter→matching→prepare/write composition remains OPEN; the
callback positive uses authored host traffic and does not run the vendor
binary or a physical ECU.
