# CUW2026 retained body programming

The current allocation has17 exact native DLL identities and21 callable exports. Three getter exports moved to leaf85 and five P5 preparation exports moved to leaf86; their source evidence remains in the original25-module/29-export audit.
`MODULE_EXPORTS` records that allocation. `IMPLEMENTED_EXPORTS` records the
currently ported subset; it is deliberately separate. The overall software
gate is **OPEN** while any allocated operation is absent or unreviewed.

`bind_native_context` consumes a parsed calibration container, its selected
`NativeParameterBinding2026`, and a SHA-identified original or reconstructed
engine. Metadata and parameter selection use the actual2026 producers. Address
selection uses `communication_addresses_from_parameter`; no DLL-name fallback,
caller geometry, executable vendor library, transport discovery or device open
is involved. The injected `NativeRuntime2026` operates on an already owned
communication session. Binding rejects manual address or state overrides. Each binding is reproduced through `validate_against`; source-approved CPU-type state changes retain distinct selected-CPU catalogs and global-CPU module selection.

Implemented preparation paths (12 exports including the finish wrappers):

- Airbag and ClearanceSonar: CPU0 archive selects the bus, then the first
  selected address receives `27 03` with the first two-byte catalog password.
  The response has a two-byte seed and a `34` marker; the second password
  supplies the unsigned-short subtraction key. The host sends `27 04`, waits,
  sends the three native diagnostic-mask messages, then `10 02`. Bus1 changes
  the ECU block size before filtering and restores it before releasing the
  filter. Only Airbag has the `IGOffRetriableFlag`/notification return override.
- SecurityAirbag: native global ECU/service authorization material is bound
  through the actual2026 obfuscated-string projection; optional authorized attachments must match it. Each native CPU
  repeats the 16-byte `27 03`/`27 04` flow at the same first address. Only the
  first iteration sends the diagnostic mask. The actual shared `security_up_key` first obtains SecretInfo record0, then calls `decrypt_secret_info`, formats its16-byte result as uppercase hexadecimal and calls `calculate_security_key` with the seed. These two authorized crypto primitives cannot report stage success. Key NRC `7F 27 35` maps to native error1002. This path does not change
  block size. Its Airbag retry override preserves `prepared=False`.
- Body: `27 61`/`27 62` uses the six-byte native seed transformation. Its block
  size decision follows address extension, independently of CPU bus. Normal
  preparation sends the mask and `10 02`; its retry notification override does
  not depend on `IGOffRetriableFlag`. `ChangeToReprogGatewayMode` skips when
  `ExternalMemoryFlag` is set or CPU0 bus is not1, otherwise sends `10 60`
  without the diagnostic mask. The gateway output flag records an attempt even
  when native preparation failed. Its mode-response error is49.
- ChassisShrink and SecurityChassisShrink: the completion notification is
  assigned false before acquiring the filter. Both repeat the first address
  once per selected address, using selectors0/2, or1/0 for two-address EMPS13.
  `27 01` takes the selector and, for SecurityChassis, the native global
  authentication bytes. Plain Chassis applies four native conversion rounds
  using the catalog's four two-byte `SecurityKey` entries; SecurityChassis uses
  the shared two-stage SecretInfo crypto choreography. `27 02` is followed by a
  diagnostic mask and `10 02` on every iteration. Neither changes block size or
  applies an Airbag retry override. Unlike SecurityAirbag, SecurityChassis has
  no response34 marker or special1002 mapping.

- P4 PowerTrain: all selected filters are acquired first. `27 01` requests a
  four-byte seed and `27 02` sends the four-round key. Seed transport timeouts
  map to unavailable-target22; a three-byte seed NRC maps to23. Key-phase
  timeouts remain fatal driver errors. Only successful targets change mode
  after one diagnostic mask. MG3 repeats `10 02`; TVD51/PG2 CPU11 repeats
  `10 60`, with the native normal-mode wait between calls. An all-unavailable
  result requires the native964 retry flag; otherwise native error17 is
  assigned. The IGOff retry notification can change only the returned Boolean.
- CentralGW: its actual CUW callback15 executes the source-bound gateway
  authentication and wire algorithm in `CUWEngine2026.gateway_callback`. The
  selected calibration must match the concrete engine. A successful callback
  is followed by `WaitTimeAfterReprogrammingMode`; a false callback sets the
  module result status1 and reads the retry notification. This is a concrete
  native engine bridge, with no caller-supplied stage-success callback.

The Airbag, SecurityAirbag and DSS1 `IsFinishReprogramming` wrappers delegate
their exact shared implementation to `CommonFlash2026`. The probe retains the
native first history-group/first-address behavior. It never asserts physical
completion merely because a module was recognized.

Native error reports expose `native_return` as the actual direct export Boolean and `native_success=None` because these exports have no output success pointer. They preserve the returned Boolean, whether preparation
actually reached its final instruction, and only the output assignments made
by the native catch branch. Host cancellation, deadline, malformed primitive
results, invalid key results and host cleanup failures propagate explicitly. Source-confirmed cleanup CatchAll scopes in Airbag, Sonar, SecurityAirbag, Body, Chassis and PowerTrain suppress only explicit native-domain release errors while retaining the computed native Boolean; reports mark `host_result=cleanup_failed` and the runtime retains unreleased resources. PowerTrain exits its native filter cleanup loop at the first native failure. Body maps unknown native faults to9999 only inside its state5 filter/security/mask/mode region; PowerTrain does so only inside its per-address seed/key region. Unknown host faults always propagate their original exception. Filters
and block-size restoration remain tracked by the runtime after a failed release;
`runtime.close()` can retry cleanup. Cleanup attempts all acquired resources.

The synthetic tests exercise selection, CPU0 versus selected-CPU behavior,
literal wire bytes, response errors, retry differences, cancellation after
acquisition, faults at every preparation primitive and cleanup failure. The
preparation route also runs through the actual `J2534Device2026.primitive`
with typed `PrimitiveResult`/`NativeMessage` fake-driver traffic.
Security tests explicitly compose the two authorized crypto primitives beside
device I/O. `J2534Device2026.primitive` does not implement cryptography. The
normal production factory must supply that same concrete composition before
the security integration gate can close.

```sh
python -m unittest discover -s tests -p test_programming_2026_body.py -v
```

Nine allocated writer controllers now have source-bound candidate implementations.
They remain outside `IMPLEMENTED_EXPORTS` until their complete native inputs,
secondary-CPU continuation and independent branch reconciliation are verified.
The private algorithm tests execute six final-CPU paths over actual typed `J2534Device2026` I/O: Sonar, Airbag,
SecurityAirbag, DSS1, ChassisShrink and SecurityChassisShrink. Sonar and Airbag
also have exhaustive host primitive fault/cancellation controls. The Airbag
candidate received independent native driver-status mutation checks.

Writer contexts reproduce the actual calibration archive bytes, flash size,
LocationID and source password. Concrete engine validation reissues every CPU's
address vector before accepting current/finish addresses. Sonar/Airbag/DSS use
the first CPU's finish pair; Body variants use the current CPU's pair. Shrink
finish deliberately ignores extension and requests no response. CXPI uses its
own erase keepalive algorithm and `VerifyBlock2`.

Public `run_*_write` entry points require actual worker-issued target73c and,
where used, initial-command retry980; missing worker state fails before native
I/O. Callers cannot turn supplied observations into issued engine state.
The actual worker now provides these fields and retained getter CPU type984.
The authored binary fixture uses native `.bin` hexadecimal ZV frames. It does
not label zero-filled raw bytes as VBF or invent a captured hardware identifier
to pass the VBF selection gate. GetNewPassword reads the authored frame DWORD.

All worker-backed public fixtures first execute actual CID reception inside
owned outer phase0, which runs native34e10/3ddf0/3e710. Distinct authored NewCID
values prevent ambiguous reorder; second-target controls use distinct SECOND_A
and SECOND_B getter replies. No unmatched-target fallback supplies field73c.
Public contexts bind only after the native metadata rebuild.

All nine public entries have typed positive operand checks through the normal
phase1-to-phase2 replay factory on one engine/controller/runtime. Authored
second targets prove native73c selects their password rather than target0.
For the three Body variants, native36800 supplies retained CPU A while CPU B
is selected; different A/B endian flags prove the writer reloads the retained
CPU's row.

A separate check runs the actual generic CAN getter at CPU0, commits its
OLD_A/OLD_B CID bytes, selects CPU1 through the concrete controller-authorized
engine selector, then constructs prepare/write sessions on the same shared
primitive timeline. The getter acquires and releases its own connection; the
caller reopens the typed channel for preparation. This proves selected-target
composition without claiming automatic all-CPU execution.

During secondary-CPU ChangeNextCpu, explicit native errors retain the native
callback-before-rethrow order. Host errors and cancellation unwind immediately
without callback1 or advancing the engine. Authored source-CPU0 normal factory
checks cover all five affected modules: success queues a one-shot CPU1
continuation; native error10 and native unknown9999 also queue it before error
handling; OSError, InterruptedError and KeyboardInterrupt preserve their exact
objects and leave CPU0 with no continuation.

The retained PrepareRetry and IsFinishReprogramming preflights are checked for all nine executed normal
writer sessions: the recovery session retains the actual loaded module, key,
source hash and frozen row objects. Forged source metadata and a different CPU
are rejected. These checks consume no SDK events and do not execute an unavailable export or
assert retry/probe-loop chronology.

The separate134 canonical215-SDK-event trace now proves actual CID selection,
source5a835/CUW1ad30 startup, and public Sonar consumption of engine980true in
its10000ms ID-response read, with2048 bytes and every event consumed. This is a
bounded producer-to-consumer check. Supplying a flag or calling a worker
mutation hook remains unacceptable proof.

These checks remain narrower than full worker execution. Automatic continuation
consumption into the next export, remaining lifecycle branches and final
independent integration acceptance remain **OPEN**. The implemented full-export
registry remains separate from the nine callable writer candidates.
`writer-candidates-current.json` retains the private source
hash ledger. No vehicle or
adapter has been used: `PHYSICAL_UNCONFIRMED`.
