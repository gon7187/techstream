# FCHV01 action workers

`scripts.utility_ex_fchv_01` supplies only `Ex2FCHV_01_SendMessage` for the exact
Techstream18 TY (`79fc495c…`) and GTSPlus TY (`821bbfd9…`) images. The source
identity is verified against immutable supplied image bytes before dispatch.
The TY core imports this provider lazily, preserving its existing FCHV operations.
The common UtilityEx wrapper requires mode20/21 and one argument, starts a worker
with10000ms stop deadline, returns running15 and publishes the uint32 body result
unchanged. Busy workers return16. Scheduler cancellation and host failures remain
exceptions and cannot become a fabricated successful result.

The argument is an owned mutable bytearray of at least28 bytes. Native little
endian DWORDs are action0, UI stop4, retry/progress8, drive tick12, drain tick16,
fill tick20 and variant24. Variant397 (`0x18d`) selects the original special
branch. The worker rereads the live UI flag and source variant during loops and
reloads action before post-operation session cleanup. Direct source Sleep calls use one `native_sleep` host wait, with explicit host
cancellation checks before/after; they do not use the sliced NK helper. The shared
timer preserves
the original extra one-tick subtraction across DWORD wrap.

Actions0 and2 initialize the exact manager, set retry delay0/pending180000/retries0
and enter extended session through normal-first session negotiation. Action0
checks support and restores normal session, propagating restoration failure.
Action1 and unrecognized actions do nothing. Actions2–19 implement preparation,
pressure raising, actuator drive, settling, warming, fill/balance, hold/release,
drain, transition, retry and final cycling with their distinct DID offsets,
byte orders, thresholds, deadlines and source cleanup sequences. Actions20–25
perform the native abort sequences and return2100. UI stop remains a native
return2100; retry17 returns2101 while incrementing the retry DWORD up to5.
Successful intermediate operations and retry2101 retain the manager. Action18
restores and finalizes even on success. Other native errors restore/finalize;
Python faults/cancellation use scoped `cleanup_exchange` for tracked routine/control
stops, then `cleanup_session(1,1,stop_on_error=True)` and
finalization independently. Secondary cleanup faults are attached as notes to the
original exception, preserving its identity. Tracking in `TYContext.state` retains
possibly active outputs across messages and clears them only after confirmed stop.
This authored host safety path does not change native normal-return packet traces;
the concrete lower layer must separately admit scoped cancellation cleanup for
each exact manager/source.

The Plus image has independent nonspecial behavior: action7 allows9000ms for the
first decay check; action11 sets progress rather than starting routine1116;
action12 repeats its pressure/valve sequence up to seven times with interruptible
200/250ms waits; action13 maps its nonspecial read failure to2038; action14 returns
without the special drain tick; action18 follows its distinct current/temperature
finish sequence. The older image retains its own nonspecial flag DIDBF and
routine paths. These differences are selected by exact source identity, not by
filename or a guessed cross-version alias.

Communication is expressed as concrete `TYComm` initialization, configuration,
session, `exchange` and finalization primitives. Reads22 validate DID echoes and
bounds, controls2F validate DID/control echo, and routines31 validate their three
identifying bytes. Persistent native communication globals belong to the shared
manager held by `TYContext`; native business state is not duplicated. The separate output set in context state
is used only for authored host-fault cleanup.
No whole-business-operation callback is used.

`python -m unittest tests.test_utility_ex_fchv_01` checks positive paths, both
variants, every action, source and buffer boundaries, echo failures, timers,
status mapping, cleanup, cancellation, live UI mutation, retention and the TY
aggregator. Private `runtime/no-car-115/exact_body_replay.py` additionally checks
all26 action values in both exact source images through the actual TY dispatcher
and public wrapper, including mode rejection, busy status and scheduler cancel.
Private static verification matches retained C/ASM digests and67 function bodies
against22604 original PE bytes without executing them.

These checks use authored primitive replies and virtual time. Concrete lower
driver/keepalive integration and independent complete source review have separate
acceptance gates. No OEM code, network or device session was executed.
Physical behavior remains `PHYSICAL_UNCONFIRMED`.
