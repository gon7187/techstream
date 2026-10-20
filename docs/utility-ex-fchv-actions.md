# Source-bound FCHV multi-action workers

`scripts/utility_ex_fchv_actions.py` implements the native argument-buffer branches
of FCHV03, FCHV04, FCHV11, FCHV12 and FCHV17 `SendMessage` in the independently
reviewed 18 and Plus TY source identities. The existing FCHV04 `ChangeProtocol`
and `CheckCanSendTime` exports remain in the TY core.

The module accepts one bounded mutable native bytearray. Minimum capacities are
0x308 (03), 16 (04), 48 (11), 0x128 (12) and 16 (17). Source hashing precedes any
communication. FCHV04 reads its action at offset 8; other groups read offset 0.
The public wrapper preserves the actual bytearray through the TY dispatcher.

| Group | Native branches |
| --- | --- |
| 03 | Support selection, session/routine start, paired valve polling, phase 1/2/3/4/5 transitions, ordered 17-row data publication, timed snapshot, stop and cleanup |
| 04 | Classic mode 4 target 0x7c4/150ms active tests; CAN modes 20/21 selected 0x7d2 controls; Plus second manager 0x10135c58 target 0x7c4, dual keepalive, separate session and controls |
| 11 | Support bitmap and valve mask, six-byte table records, 0x7061 temperature threshold, opening/closing, periodic selected-row publication, retained lifecycle and stop |
| 12 | Five 0x38-byte descriptors, support flags, 0x7060 threshold, valve mask polling, NRC mapping, retained streaming, explicit stop |
| 17 | Three ordered active controls with partial rollback, routine readiness, 230s/5s duty cycle, 480s timeout, caller completion flag and explicit cleanup |

Timers use the shared uint32 wraparound elapsed calculation. Direct native Sleep
calls use `native_sleep`, preserving one host wait with explicit pre/post HOST
cancellation checks. Normal-session calls bind the native 20260/130f0 helper,
including unconditional keepalive shutdown on a failed normal reply. The caller controls
stream termination through the original native flags. Successful native start,
stream and poll paths keep the initialized controller where the source does;
stop/error paths restore the normal session and finalize as recovered. Host
exceptions and cancellation trigger bounded controller cleanup rather than
inventing an ECU status. No whole-operation provider is called.

The 18 decompiler loses stack arguments and sometimes marks real reply branches
unreachable. Literal assembly confirms the DID arguments, three-byte echoed
headers, support bitmap stores, grouped valve output bytes, and the initialized
routine start byte. The five read descriptors were also independently extracted
from the 18 table at 0x100f8740 and Plus table at 0x100f41d8. Identical table bytes
are recorded independently rather than inferred from export names.

Private source pins and wrapper contracts live under
`analysis/evidence/no-car-116/`. Wrapper 04 has two actual callbacks: mode 4 and
modes 20/21. The remaining wrappers permit modes 20/21, schedule a native worker
with 10000ms scheduler timing, and publish its uint32 result unchanged.

Run `python -m unittest discover -s tests -p test_utility_ex_fchv_actions.py -v`
for authored positive, malformed, native-status, host-fault, cancellation,
retention, timing, native output-buffer and actual TY-dispatch checks. These are
software checks using authored exchanges, not physical vehicle or J2534 proof.
Communication initialization and real hardware capability remain the concrete
communication layer's responsibility; a missing lower primitive fails visibly.

Mutable native buffer reads follow their recovered boundaries: FCHV11 dispatch
reloads action after initialization; FCHV04 dispatch, helper branches and final
manager selection reread the relevant fields; classic04 rereads its second frame
action. FCHV03 action8 rereads each priority and checks the deadline after every
priority, while actions6/7 keep their native order snapshots. FCHV12 captures its
wire mask before initialization but reads the live mask for temperature gating.

HOST exception/cancellation safety is explicitly authored behavior. The context
retains pending output-release frames per independent controller, marking an
activation before attempting it and clearing only a confirmed stop. Foreign
exceptions or cancellation release those controls/routines through `cleanup_exchange` without a cancelled
flag blocking cleanup, then use `cleanup_session` to restore normal mode and
finalize. The concrete cleanup lane has its own deadline and preserves the
global cancellation flag. A later cancelled
message also releases outputs retained by the preceding successful message.
Cleanup failures become notes on the original exception, preserving its identity.
Native normal-return retention and native ECU result codes remain unchanged.

A production-consumer test uses an unmodified `UtilityExContext.comm` path with
authored raw PassThru exports: public FCHV17 invocation initializes the real TY18
controller and session worker, retained action1 activates three controls and
routine16, and cancellation emits all four exact release frames plus normal
session before finalization. No active-output state or controller is injected.
This confirms the TY18 concrete lane; Plus and classic lower readiness remain
separately gated. Operation-local cleanup distinguishes an actual operation
failure from an unrelated exception currently handled by the caller.
