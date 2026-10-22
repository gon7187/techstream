# CUW2026 DH implementation boundary

Status: **OPEN pending independent closure review**. All21 DH modules have concrete getter, prepare, writer or retry handlers; operation-address coverage alone does not establish full source parity.

The private source inventory binds 21 modules and 90 unique native export addresses to
outer, companion, and reconstructed inspection SHA-256 identities. The SIL getter is
owned separately. No vendor PE, vehicle, or external authentication service was run.

Implemented assembly-reviewed `TCUWDHUtils.dll` helpers:

| Native RVA | Host function | Observable detail |
| --- | --- | --- |
| 17b0 | `checksum` | Both byte ranges, modulo256 |
| 3110 | `convert_su_characters` | Bounded slice; preserves NUL; replaces quotes, backslash, nonprintable bytes with underscore |
| 3150 | `su_tester_present` | `000007863e01` |
| 3db0 | `extract_software_id` | Configured six-byte complement plus five response bytes, with native NUL termination |
| 5300 | `read_software_id` | `1a81`, positive prefix `5a` |
| 5610 | `request_download` | `340144` plus four-byte address and length; native subtraction metadata, zero means1 |
| 7bc0 | `transfer_data` | `36` plus data; no synthetic block counter; offset advances after `76` |
| 5fb0/60d0 | `request_transfer_exit` | `37`/`77` |
| 3510/3630 | `ecu_reset` | `1101`; classic `51`, Phase5 `5101` |
| 74e0 | `verify_checksum` | Checksum compared in reply `7101f010XX`; request is `3101f010` |
| 75c0 | `verify_su_checksum` | `3101f01300`/`7101f01300` |
| 76a0 | `verify_result` | `3101f01101`/`7101f01100` |

These are low-level algorithms, not a substitute for the native family caller's session,
addressing, timeout, filters, retry, periodic-message and metadata orchestration. The
Phase5 methods have distinct host timing/cleanup contracts; only their PDU helpers are
shared here. The family implementations below consume actual CUW metadata and engine
state. The private source inventory retains their identities; passing helper tests alone
does not close family coverage.

The focused unittest suite uses literal wire replies, malformed controls, cancellation,
receive-only pending, negative responses, transfer range checks and no-I/O invalid input
controls. It does not establish physical acceptance. **PHYSICAL_UNCONFIRMED**.

## Native getters

The canonical `bind_native_context` accepts actual `NativeParameterBinding2026`, imported
CUW bytes, exact selected DLL bytes and the source-bound engine state. It reproduces the
31 parameter-file/row selection and48 address resolver, retaining the selected CPU's
address group. It never indexes that group again by a global CPU index. `execute_context`
executes this frozen binding. Earlier getter/phase bind helpers remain wire-fixture
compatibility interfaces; older catalog dispatch does not establish2026 selection.
`get_dh_cids` uses `CanDiag2026` primitives and owns connect/filter teardown, including
partial initialization, callback cancellation, pending responses and cleanup failures.

| Exact2026 module | Native operation | Result detail |
| --- | --- | --- |
| TCUWCanDHUDSSoftwareIDGetter.dll | StartGetCID | `22f181`; count plus16-byte records, native destination truncates each to15 characters and skips empty values |
| TCUWCanDHSoftMaskIDGetter.dll | StartGetCID | `1a8801`, then `1a8802`; each returns ComplementCID plus4 characters |
| TCUWCanDHSoftwareIDAndSoftMaskIDGetter.dll | StartGetCID | `1a81` and configured `21/PIDForReadSoftMaskID`; ComplementCID plus5 software characters and8 mask characters |
| TCUWP5CanDHVehicleInfoCIDGetter.dll | StartGetCID | Source-defined functional07df request,07e0 flow-control request,07e8 response; `0904`;16 characters, rejects empty records |

Additional reviewed helpers now include gateway CAN-ID selection, classic/Phase5 session
and diagnostic broadcasts, software-information selector enumeration, supplied-table
four-byte seed/key rounds, specified-byte seed reads, source AES16-byte and external64-byte online gateway key
computation contracts, communication stop/resume and owned synchronous periodic frames.
No actual authentication service was contacted, no source secret record is embedded, and
no provider can assert programming success: external online computation returns raw bytes only. Native callback21 AES is computed by the source port.

The native `GetSoftwareInfo` procedure continues through tail target RVA4eb5 back to
RVA4d56. The port reads every nonzero selector in order; the first pseudocode fragment
alone omits that loop. Source queue2 retains the continuation separately.

The classic getter also preserves the native standard/extended-address offset rule and
SU software-selector loop. `bind_stateful_dh_getter` binds engine-created
`DHControllerState2026` and the exact2026 location/new-calibration getters. Verification
and writable CID/mask stages advance only after their actual request succeeds; retries
retain the last successful stage. Native `typCUWData+74c` is CPU progress/status, not a
protocol selector. There is no production setter for completed status100. The focused
unit fixture supplies100 explicitly to exercise the post-write branch; native writer
completion is now produced by the classic writer's actual transfer replies; the other
writer families remain required.

`bind_dh_prepare`/`prepare_dh` now implement classic DH prepare from the actual parameter
dispatch and engine-owned context. The handler includes protocol5/6 diagnostic masks,
SU session/periodic setup, gateway CPU selection, supplied-table four-byte seed/key or
source AES authentication computation, the native30-retry ceiling and timeout/filter
cleanup. Connection and periodic ownership survive successful prepare for the writer;
the outer owner must close the runtime. Unit checks cover both mask protocols, SU
sync-lock/key flow,31 failed attempts, cancellation and timeout restoration. Native
engine error-state propagation and independent review remain required.

Classic `flash_dh` materializes the actual47 CPU-image/flash-code archives, sends the two
native transfer passes or checksum path, resets sessions and updates36 progress only
after each real `76` response. Native error disposal resets count and percentage in
callback order. `PrepareRetry` retains the selected write parameter row and CPU address
group while calling the exact2026 prepare implementation. Canonical checks use a two-CPU
S-record CUW with CPU1 selected, actual31/47/48 adapters and authenticated static module
bytes; CPU0 stays untouched and failure resets CPU1 progress. Next-CPU ignition lookup
uses global `Parameter.ini`, including its missing-row error. Global native CPU indexes
stay distinct from the selected node's local index.

Gateway dependencies use `SecretInfoClient.from_native_modules`: exact SecretInfo and
CUW bytes reproduce the native client authorization producer without embedding its
private input. Native callback21 uses the recovered generic AES client algorithm; online callback27 runs the concrete source-issued113 controller through `runtime.bind_p5_online`, using private authored/captured primitive chronology and the actual36 engine worker. Generic action callbacks cannot supply a successful key.

Native error catches retain their three controller fields. CJ2534 has primary enum1
and a distinct driver status; ordinary CPass errors update the primary enum while
preserving the prior secondary field. A primary enum9 cannot trigger a driver-timeout
fallback, and driver status48 cannot set the writable-CID primary-error48 flag.

`prepare_uds_dh` implements the Phase5 broadcast sequence, an unconditional locked
`1002` exchange at the actual `CanIDForGetCID` address and SCM_DH109 secret selection.
`flash_gateway_dh` implements the CPU0 single-pass checksum writer, with separate count
and percentage state changes before their notifications. CPU0 addresses are rebuilt
from actual31/47/48 inputs while preserving the selected write parameter row.
`prepare_19pf_gateway_dh` implements physical0044 and online0003 authentication paths,
including their distinct periodic addresses and security order. The engine's fresh
context+964 flag originates in the engine and actual worker retry transition.

`prepare_uds_dh` also implements the distinct P5 variant: fixed1000 wait, P5 pending/busy
semantics, short seed/key responses and EVP_DH168 secret53 versus secret59.
`prepare_multirom_dh` accepts only native driver timeouts9/16 for the initial0792/1083
restart probe, then masks, authenticates and enters1085. A positive restart reply is
the native primary1000 failure. CPU0 communication groups use actual source selection.

DHUDS/P5DHUDS `PrepareRetry` stops periodic before invoking the exact corresponding
prepare implementation with the retained write row and CPU0 communication group.
Modern prepare/retry retain the selected write row while rebuilding actual CPU0
communication groups.

`flash_gateway_dh` also implements the19PF writer: forced SU checksum, source-owned
notification, both progress fields changed before callbacks, periodic stop and two-CPU
session cleanup. Its error kind reads the actual notification after error disposal.
`flash_multirom_dh` consumes two actual S-record segments and parameters, includes the
transfer sequence byte and second block-size subtraction, and derives progress from
the two parameter lengths. Host bounds reject native uninitialized/overflowing buffers.

`flash_uds_dh` implements both modern writers with actual selected CPU addresses,
archive lengths, sequence counters, CRC and fixed20-byte CMAC requests. Classic
Format4 uses physical file slots for the four address/size rows, aggregate image
progress, actual persisted divided-image index and count-only prefix reconstruction
on retry. Phase5 uses its distinct pending/busy loop and has no divided-image branch.
Native errors before notification set kind1 and communication phase1; later faults
set kind2. Empty native StopFilter catches preserve the saved business Boolean.

`flash_usb_dh` implements the USB routine sequence and status check with the actual
notification handler suspended and restored. Recovery16e0 consumes the actual36/114
worker's selected target CID and imported software-vector count. A target match or a
changed nonempty software count runs the routines; equal count with no match skips
them and follows native successful finalization. The temporary CID filter has the
native empty typed catch; host faults retain their original identity.

All90 unique export addresses now have concrete implementation mappings. Complete
coverage still requires independent review of all source branches and error/cleanup
edges. G1/G2/G3 remain **OPEN pending that review**. Native StopFilter failure tests
preserve both successful and failed business Booleans in classic, Gateway,19PF,
MultiROM, DHUDS/P5 and USB writers. USB host-fault controls verify exact exception
identity, unchanged native error fields and restored notification/timeouts.

Canonical results carry `native_return`: the native Boolean output parameter for CID
getters and direct Boolean return for prepare/write/retry exports. Host cancellation in a business operation carries `None`. Host cleanup faults,
including interruption, propagate their original exception after remaining resources
are restored; typed native StopFilter faults preserve the saved Boolean. Gateway composition uses
`bind_gateway_client` with the same engine state and three exact dependency images;
its gateway-type mutation occurs before authentication, matching native6e00.

Initial central-gateway fallback consumes the controller's exact pool BASE
`NativeControlParameterBase2026`, issued under its owned engine phase. It reads slot0
as held, including a prior FILE's row, without selecting or rebinding a parameter row.
`bind_gateway_client` authenticates a pool-backed BASE against its exact engine DH
state, worker/runtime and current held context. The separate constructor-empty factory
remains valid only before any parameter slot loads and retains exact current metadata.
Each public gateway entry validates its capability again before I/O; copied,
cross-engine and stale capabilities fail. After parameter loading, selected native rows
use `NativeParameter2026.boolean`: the
parsed native LONG is true when nonzero (including2). Legacy `CalibrationSelection`
wire fixtures retain their separate0/1 contract.

Native prepare/write phases require the caller-supplied connected CJ channel. Their
source modules do not perform an initial `Connect`; classic prepare connects only
inside the explicit mask protocol transitions at1a15(protocol5) and1ac9(protocol6).
A concrete runtime channel observation suppresses the old wire-fixture convenience
connection without claiming a new disconnect owner. `ControlCommPhase2026.execute`
applies the engine→CONTROL pair import and the CONTROL→engine return only when an actual
`J2534InterfacePair2026` is bound, so the original acquisition-view cleanup survives;
unpaired callers retain the supplied connected control channel. Opaque provider fixtures
retain explicit setup.
