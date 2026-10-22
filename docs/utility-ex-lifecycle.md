# UtilityEx fixed manager and worker lifecycle

`scripts/utility_ex_lifecycle.py` implements an owned native communication
lifecycle over individual typed positional SDK exports. It never executes the
vendor PE, opens a device, or substitutes an initialize/session success callback.
The facade is owned by `scripts/utility_ex_comm.py`.

The eight fixed-manager identities retain their original module hash and object
address. Source-specific automatic selectors distinguish 12 (modes 14/15), 18
and DS4 (also 34), and Plus (also 74, but not with protocol 62). The selected
module globals take precedence over broker snapshots. The concrete lower's
reviewed source support remains mandatory: accepting a manager identity is not
proof that every lower branch has been completed.

The worker implements the recovered ThreadMain body that the original C cache
missed: a 120 ms wait, unsigned wraparound subtraction, strict `>` gates for
both the last worker attempt and last lower receive, serialized exchange,
optional exact response size, and conditional reconnect after native faults.
It supports an actual owned Python thread and a deterministic `worker_step()`
entry for injected-clock checks. The thread is joined before finalization; a
host timeout keeps lower ownership available for retry instead of disconnecting
under a live worker. Worker exceptions remain observable through `worker_error`.
`keepalive(False, True)` follows the native close flag and also closes the lower;
the second argument is not merely a request to wait for the thread.

Extended session entry sends and validates `10 01` then `10 03` before starting
the worker. Generic normal session `10 01` with keepalive selected stops the worker only
after a validated positive response. The distinct `stop_on_error=True` normal
helper also stops it on native error, malformed response and foreign exception. Reinitializing
an existing manager retains its worker and serializes against its exchange.
Initialization restores native defaults without resetting retry1064 or
pending1098; a successful initialization clears native_error10b0.

The selected NK18 classic CAN lower is separate from the fixed-manager CAN pool.
Native objects `1014ae60` and `1014ad90` use the direct protocol6 singleton,
source broker500 configuration (including retry without parameter2a), literal
profile presets, and the original two filters. Their send/receive timing and
interrupt behavior differ: the older lower sends tester-present and consumes
bounded pending replies; P5's interrupt is the native no-op. Acquired filter and
channel handles are retained before post-call host checks and cleaned after
foreign faults. Cleanup retains failed disconnect ownership for retry.

Validation uses authored packets and raw `PrimitiveResult` SDK functions with
positional output DWORDs/messages. The focused suite covers selectors across all
eight images, SDK chronology, session echoes, native pending and malformed
responses, worker scheduling and a real background run, cancellation, native
resource cleanup and foreign exceptions. Private original images are used only
for static source comparison and are not required by this authored unit suite.

The full leaf132 acceptance remains open until every selected legacy/P3/P5/SIL
variant, additional fixed-class layout, original-source independent review and
actual business consumer composition have been verified. No physical vehicle or
adapter validation is claimed.

The NK18 selected driver includes both ordinary and extension-byte CAN objects
(`1014ae60`, `1014ad90`, `1014c168`, `1014c288`) and three distinct SIL response
address variants (`1014aea0`, `1014af30`, `1014af80`). SIL requires the separate
constructorD DRIVER binding and SDK Connect protocol1000c while message protocol
remains6. Its startup and exit handshakes, address subtraction, filter chronology
and disconnect ownership are modeled explicitly. Native direct filter helpers
ignore raw SDK failure statuses; foreign exceptions still unwind owned handles.

`UtilityExLegacyP4Lower` implements the selected NK18 `1014c0b0` ISO9141 lower.
It retains source profile timing tables, the broker73 fast-init distinction,
FIVE_BAUD_INIT byte-array descriptors, literal checksummed wire frames, and the
distinct aggregate and single-frame receive methods. Aggregate receive continues
after a positive frame until native buffer-empty, preserving the latest parsed
status; it returns NRC78 immediately. This is separate from the P3 lower.

Explicit `cleanup_exchange` and `cleanup_session` borrow the existing concrete
SDK guard's thread-local cleanup allowance for at most five seconds. They let a
known release command finish after cancellation without clearing global cancel
state or granting subsequent ordinary commands the same privilege. The scope
is restored even if a primitive raises. SIL's native end handshake uses this
bounded release scope before filter/channel cleanup.

TY18 selected classic CAN, P5, extension CAN and all three SIL objects retain
independent object identities and the TY module's own target globals. Their
method bodies and direct DRIVER primitives were compared against the NK18
implementations with relocation references recorded separately. The TY18 legacy
P4 object also retains the distinct aggregate and single receive methods.
`select_diagnostic_mode()` preserves the native byte mask, same-mode early
return, and retained-child rejection. Gateway mode3 allocates a distinct retained broadcast child before I/O.
The NK18/TY18 child sends to the functional third target while filters and
response decoding retain the physical fifth target. Other image source guards
remain explicit.

The separate TY18 SIS components use the seventeen-export v0500 DRIVER table.
`UtilityExSISDriver` retains controller, physical and three logical handles;
`UtilityExSISMessage` retains the independent nine-DWORD message descriptor and
mutable backing. `UtilityExSISLower` implements the measured GPIO initialization,
the source-bound credential fallback through individual ANSI INI primitives,
physical configuration, discovery/routing activation and DoIP stream send/read.
Private profile constants are projected from caller-owned source bytes. Socket
state IOCTL8023 succeeds only when its output DWORD is2; a state failure99
performs the actual close/reinitialize path. The independent SIS fields, UDS scheduler, session lifecycle and no-recovery
worker retain their shifted offsets and the separate ACK retry state. Its
finalizer retains the lower pointer after releasing the native handles.
Facade and business-consumer integration remain separate acceptance gates.


`UtilityExSelectedCMNWorker` implements the scheduled CMN body for all four NK
images, independently of their timer-based keepalive exports. The source engine
owns the shared background thread and cancellation lifecycle. The plain branch
sends2100 and captures its interval/stop flag. The custom branch copies payload
once but rereads the live BYTE length, interval and flags from
`UtilityExSelectedCMNFields`; busy setup calls can overwrite these fields.
Recovery uses native initialize mode1. Exit resets only the busy/no-response
limits100/3; it does not send a wire interrupt. The trampoline stores the native
result separately and closes the lower only when both its cleanup flag and result
are nonzero. An increase into uninitialized copied stack bytes fails closed.

The authored SDK suite runs without executing the original images. Optional
facade-authentication checks read caller-owned originals and skip when those
images are unavailable. These checks cover the shared CMN route through the
concrete facade and the source-specific no-I/O cancellation paths.

`UtilityExSelectedTimerKeepalive` models all eight separate SetTimer families.
The host supplies individual positional SetTimer/KillTimer primitives; the
callback belongs to this module and performs the actual selected exchange,
response-size check and source recovery. Recovery uses an explicit target
without rewriting module target globals. A failing F0 recovery action kills
the timer, publishes its status and closes the real selected lower. Failed
KillTimer retains the callback owner. Stop preserves the native active flag.

The selected classic CAN/SIL object mapping now covers all eight exact images.
The 12 profile switches are smaller: standard DC/15D and extended D0/180 only;
later-only profiles fall back to the native 12 default. Selected Plus classic
response addresses still use +8, independently of pooled Plus mode74. Authored
raw SDK checks exercise all 56 object variants, constructorD SIL handshake
chronology, and each image's native fault, foreign exception and cancellation
cleanup. `selected-lower-source-matrix.json` records original vtables, method
source hashes and repaired collector gaps. Facade/business admission remains
the responsibility of the corresponding separate source audits.

`UtilityExSelectedP5Worker` covers the eight separate selected workers, including
TY18 worker1d5e0. It uses
the plain selected stack scheduler11740, the selected last-receive clock, its
own mutex, exact response size, and explicit-address recovery. Its pause mutex
is available for source P5 business exchange coordination. A self-stop signals
the worker without closing its lower. Restart preserves an unobserved host
exception; all fixed and SIS workers retain that protection too.
`stop_fixed_worker` closes an existing concrete owner, while an untouched BSS
manager only resets its own fields. Common finalization never binds a DRIVER
or allocates a pool merely to close an inactive manager.

Selected indices1/2/4 are separate concrete P3-derived classes. All use the
physical protocol4 DRIVER, regardless of their abstract getter15/6/3 metadata.
The F1 class has its own tester byte and sixteen timings. The strict F0 class
has exact negative-response lengths and a separate10400-baud timing table;
profile156 is available only after12. The slow class retains the base F0 codec
and its own nine timings. All24 derived-class source routes have authored raw
SDK checks; the108 facade separately authenticates all96 original-image routes.

The ordinary classic CAN lower consumes native timeout field10 after12.
The12 ordinary, all SIL/extension, P4 and P5 classes retain their own literal
timeouts. Tests distinguish these source consumers through positional SDK
write/read calls, rather than treating every retained field as a live setting.

Plus SIS source has explicit differences from TY18: three controller arguments,
individual JSON port and adapter-name reads, a lower target at offset3c, and its
own module globals. The separate source-bound binding and JSON primitives are
now joined. Authored raw SDK checks cover its controller ABI and exact JSON
port bytes/authentication reads;108 separately exercises the original-context
Plus facade through session, NRC, cancellation-safe cleanup and four closes.

Fixed worker vslot18 is a separate alternate UDS exchange, rather than the
ordinary business vslot20. Its no-response, busy and pending budgets occupy
10b4..10cc; P6 shifts them by+4 and SIS by-4. The worker uses this independent
scheduler and shares only the source-defined error, pending count and suppress
flags with ordinary exchanges. SIS alternate exchange performs one ACK attempt
and one bounded payload read, including the exact1020-byte case without the
primary receiver's extra zero-length read. All eight fixed worker source
identities have distinct timeout/NRC21/NRC78 fault checks. The original-source
entry/receiver/abort packet is `alternate-worker-source.json`.

`UtilityExP6Lifecycle` owns the two Plus P6 managers with separate fields,
pool/lower and primary scheduler. Mode16 with protocol18/78 selects native
kind17/18 (hexadecimal). Its native10d0/c4/c8/cc alternate defaults and byte105c
session state stay separate from ordinary and SIS managers; finalization retains
alternate busy_ms10c8. Four raw SDK checks cover both images and physical6/8012,
worker positive/NRC21, primary DID/NRC33, cancellation-safe normal session and
filter/disconnect cleanup. Actual P6 facade/engine/business consumer and full
independent review remain open; see `p6-outer-source.json`.

Worker recovery follows manager vslot0c(address,1): it rebuilds the selected
child, retains the receive clock and stages current child configuration without
resetting outer session or alternate budgets. Leaving diagnostic mode3 replaces
the pending broadcast child before publishing mode1/2, as23460/17ec0 require.
The separate108 original-context P6 facade checks now cover both Plus images
and physical6/8012 through the shared four-slot pool and cancellation cleanup.

The background fixed/SIS/selected-P5 loops now invoke the individual host
`native_sleep(120)` primitive. Deterministic step calls do not sleep. Background
loops use `_paced_native_sleep`: if host Sleep returns before 120 ms of monotonic
time, the worker waits on its stop event for the remainder. This preserves the
literal cadence and prevents a virtual-clock replay host from spinning the DCM,
selected-P5 or SIS worker. A host fixture that asserts deterministic step timing
should still provide blocking or synchronized Sleep; virtual clock-only Sleep is
suitable for direct `worker_step` checks. Foreign Sleep failures remain observable
and retain lower ownership for close.

At this review freeze, ordinary broadcast support is admitted only for the
two18 images. Other six ordinary broadcast source branches remain open. P6
uses its separate25e70 broadcast selector and CComCanP6_Broadcast lower; that
branch raises an explicit source error until implemented. The83 public P5
worker wrappers remain TY18-only despite the all8 component source port.
Public PlusSIS/P6 initialization exports and exhaustive actual business joins
remain separate gates. This freeze requests independent review, not completion.

## Lifecycle hardening after the handoff

The reviewed checkpoint left three owner/cancellation defects open. The public
implementation now keeps these invariants, with authored regression checks that
do not require an original image:

- A selected P5 worker whose `Thread.start()` fails clears `active`, drops the
  unstarted `Thread` and leaves `stop()` usable. A later retry does not inherit
  an owner that can never be joined.
- Every manager lifecycle, CAN/P6 pool, direct driver, selected lower, support
  cache, driver arbitration, manager mutex and shared field set is published
  once per context key. Concurrent aliases receive the same owner and the same
  lock instead of constructing a second owner. Publication is serialized
  separately from native I/O.
- A selected CMN worker does not read or write the shared timer status on
  cancellation or success. Its explicit `stop_on_error` branch publishes its
  own error before cleanup, even when that value equals the entry status and a
  timer published a different value during the exchange. The regression covers
  plain and custom requests across all four NK images; the separate status-15
  overwrite hypothesis remains refuted.

These checks are `tests.test_utility_ex_lifecycle.LifecycleHardeningTests` and
`tests.test_utility_ex_comm.PublicationOwnerTests`. They establish the Python
owner contract only. The original-image twelve-check oracle and independent
source review were not run for this change, so leaf153/108 acceptance remains
open.
