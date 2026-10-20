# CUW2026 SIL programming

`scripts/programming_2026_sil.py` translates the authenticated 2026 SIL native
algorithms into Python over injected J2534 primitives. It creates no transport,
discovers no device and never loads or executes an original or reconstructed PE.
Module authentication uses the native-module registry's exact digest and canonical
name, including the protected-source/reconstructed-engine relationship.

`SIL_OPERATIONS` maps the ten programming modules to generic CID/preparation/flash,
DCM/PRL version/preparation/flash, DH software-ID, and HINO AMT
CID/preparation/flash. `SILChannel` implements the shared SIL communication module:
physical addressing, FIVE_BAUD_INIT, FAST_INIT, receive-only pending response and
request/response with native busy retries. Generic preparation is the actual
three-byte native `b0 01 c3` implementation: true without I/O.

Use `bind_context(container, node, observed_cids, selection, identity,
attachments, observations)`, then `execute_context(context, runtime)`.
The immutable context records authenticated module/calibration digests and hides
operational arguments from its representation. The binder consumes actual 2026
CUW metadata and archive materialization from `calibration_2026`, and a frozen
`NativeParameterBinding2026` from the actual 2026 parameter file selector.
It reproduces that binding against the actual container, node, CPU and native
operation stage, and verifies the selected DLL field against the authenticated
module identity. An unrelated row, stage, container or module is rejected. It derives memory geometry from native parameters
and the actual ECU descriptor. It resolves old passwords from observed CID and
native target rows, or extracts the new password from actual image bytes using
native PasswordAddress/ByteOrder. The selected FlagToHoldSFormatRecords is
honored; a map-only archive cannot supply fabricated contiguous SIL image bytes.
No password, geometry or target-index override
is accepted. Runtime observations are restricted to the actual native
use-new-password/reset/status/received-CID-count flags and CPU selection. DH
conversion data is an explicit `id_conversion_records` byte attachment of bounded
14-byte records. Context reports expose identities and operation names only.
Execution accepts only the exact live context issued by the binder; replacing a
frozen context's arguments or digest does not authenticate a new operational plan.
Validated parameter metadata retains actual engine CPU-type overrides.

For the actual host stack, use
`SILChannel(sil_j2534_action(j2534_device), ...)`, where the device is an actual
`J2534Device2026` over an injected low-level provider. This explicit bridge maps
SIL IOCTL/configuration events to its typed primitives and returns its acquired
channel handle only after successful connection. Getter acquisition owns the whole
connection lifecycle and requires an unopened device; an existing caller-owned
device or channel is rejected without I/O and remains intact. Prepare/flash may
use their caller-established connection because they do not acquire one. Partial connection or
post-acquisition cancellation rolls back the actual native connection. Its
FIVE_BAUD_INIT, typed FAST_INIT, reads and protocol-3 writes are exercised
through the actual 2026 host implementation in authored integration tests.
Normal SIL reads perform the native indication read followed by a separate data
read. A native indication error is swallowed at that native catch boundary;
host exceptions and cancellation propagate. The FAST_INIT drain uses one raw read.
Plain native `CPassThruException` codes remain distinct from `CJ2534Exception`
business enums and driver statuses.

The SIL primitive provider receives `(event, remaining_seconds)`. Void IOCTL, wait,
timeout-setting and disconnect operations return `None`; connect returns a uint32
handle; write-message returns the actual complete-message count; read-message
returns immutable J2534 message data; get-timeout returns uint32 milliseconds.
FAST_INIT returns `{"data": bytes, "rx_status": int}`; the actual device bridge
also supplies its live Boolean `can_frame_padding` for RxStatus classification.
Both shared and raw serial initialization retain the required single drain when
the native indication requests one. FIVE_BAUD_INIT returns bytes. Native transport
errors retain their native code. The algorithm
interprets primitive results and determines business success itself.

NRC21 busy repeats the native request; NRC78 pending reads without retransmission.
Native retry counts, checksums, lengths, byte order, block commands and serial
status polling are retained. The generic bootstrap includes the native 100
handshake, descriptor and blank-check iterations. Host policy additionally bounds
input sizes, absolute time, cancellation, primitive calls and cleanup calls.
Executing a context through an existing runtime shares that runtime's exact
clock, deadline, ownership and budgets. Timeout restoration and acquired-handle
release run through the independent cleanup budget after cancellation or failure.

The source index at `analysis/evidence/no-car-35/implementation-source-index.json`
joins native entrypoints, exact engine identities and source-body hashes. Static
exports include C, literal ASM, per-function hashes and indirect-flow evidence.
A completed decompilation is not independent CFG or semantic verification. The
independent source/integration review gate G3 remains open until reviewed.
`business-edge-index.json` separately retains unfiltered direct CALL/JMP support
closure, including unwind thunks and vector/string destruction helpers. Compiler
or library names do not exempt those source bodies from semantic review.
Generic programming accepts typed `SILProgress2026` state with an optional
observer. Native count updates precede percent updates after every 256-byte write
and verification packet; percent uses twice the actual archive flash size.
Observers receive these derived values and cannot provide business success.
Cancellation after the count callback prevents the following percent callback.
`execute_context(..., progress=state)` preserves this controller-visible state.
DCM and HINO writers expose their native count/percent chronology through the
same typed progress carrier. `SILTransferState2026` retains distinct password760,
notification968, reset964, error/driver, status and countdown fields, including
failure state. Its optional `engine` must be an actual `CUWEngine2026` bound to
the same calibration. A detected alternate CPU calls its actual `apply_cpu_type`
at the native mutation point, before loading the alternate parameter row; a later
failure retains that change. Writer-local shrink detection is not promoted to an
unproven engine mutation.
Native failure cleanup is observable: generic startup sets status1; its block
scope clears progress count then percent before setting status2. Both select
retry-password760 from last-block96c and the error enum after first clearing760.
HINO clears progress count then percent before setting status to
`1 + writing968`; DCM sets status2 before those progress callbacks. These native
catch paths remain distinct from host abort and untyped host exceptions.

Native callback12 and host abort/deadline are separate inputs. Callback12 follows
each native call-site flag and branch: shared transport cancellation can retain
the previous response buffer, version acquisition can return early, and getter
outer callbacks can raise native enum3. Generic raw programming does not invent
callback12 polls. `SILCIDState2026` retains identifiers already appended before a
failure; the original exception exposes that carrier as `sil_cid_state`. Each
canonical exported getter clears the previous invocation's vector once, while
inner communication retries preserve partial results from the current call.
Shared receive/exchange native ALL handlers retain the previous buffer when a
callback fails before memset, and return empty logical data when a read fails
after memset. CPass/CJ errors retain their separate rethrow paths. Fixed-offset
native seed/CID consumers read the corresponding zeroed backing-array bytes;
host exceptions do not acquire this native return behavior.
Cleanup preserves a local host failure's identity and records a failed cleanup
as an exception note. A native cleanup error retains its native precedence over
a native process error. An unrelated enclosing exception handler does not change
successful-operation cleanup behavior.

These checks provide no evidence of physical programming.

The canonical controller adapter is `execute_context_report`, returning frozen
`SILExecutionResult2026`. Its `native_return` is the six prepare/write exports'
actual BOOL; for four pointer-returning getters it is `None`, with the actual
param7 BOOL in `native_success`. Private `result` retains internal byte counts,
identifiers or reset-state values. Those values do not substitute for an export
BOOL. `native_error` retains a caught native typed exception; host failures remain
exceptions. A failed getter's `result` retains its partial identifier tuple,
matching the contents behind the native vector pointer. The original
`execute_context` API remains available.
Optional `error_code`, `j2534_error`, `status` and `use_new_password` fields retain
source-assigned slots; unknown initial controller state remains `None`. Timeout
setup and cleanup outside the native DCM/HINO process catch propagate their
exceptions, rather than acquiring a fabricated false return. Host abort after a
timeout-setting callback still restores the previous timeout before propagating.
Getter disconnect is also outside the native process catch. Initial timeout setup
is outside CID/DH/HINO catches and inside the DCMPRL Version catch; Connect is
inside all four. The canonical report preserves these distinct native boundaries.

Run `python -m unittest discover -s tests -p test_programming_2026_sil.py -v`.
The authored-only suite covers complete wire flows, native fallback, image/password
bounds, malformed replies, pending/busy handling, runtime budget retention, and
primitive failure/cancellation boundaries including resource cleanup. No public
fixture contains private calibration data, OEM binaries or extracted secrets.

The private static-identity composition check is
`PYTHONPATH=. python runtime/no-car-35/verify_factory.py`. It runs all ten exports
through the actual imported calibration, parameter selector, engine-owned phase,
controller and typed J2534 adapter. Native state comes from the engine, with no
JSON reset/password overrides. Each of the nine I/O modules also receives a typed
driver fault, an exact host exception and a host abort after the first write.
It checks native status/error/retry slots, partial state and handle ownership.
Actual engine progress observers see DCM status/error/driver assignment before
zero count and percent; HINO errors precede those observers and its status follows.
The resulting reports are `factory-composition.json` and
`factory-fault-composition.json` in `analysis/evidence/no-car-35`.
Sixteen additional controls execute the four getters through actual
`ControlCommPhase2026.receive_cids`, including its four-entry version gate and
final byte-vector commit. DCMPRL Version also updates the actual SIL contact
buffer from native progress0, independently of the observed CID count.
Their report is `controller-getter-composition.json`. Complete programming
orchestration and the independent per-edge semantic review remain separate work.
