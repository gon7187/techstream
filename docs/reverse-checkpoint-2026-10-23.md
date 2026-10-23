# Native reverse-engineering checkpoint, 2026-10-23

This checkpoint records bounded static findings and authored host checks. It does
not establish adapter or vehicle behavior. Physical status remains
`PHYSICAL_UNCONFIRMED`; the [full-port matrix](full-port.md) remains open.

CUW addresses below refer to the recovered CUW2026 image with SHA-256
`acc95323a291671294fef648be1642b675b59015078532aeabaee4872e551261`.
The P6 getter image is
`8a1cea69f3c971fe8b148f062503fcfdc8135bb6a56aa3b16bca238313a0fae5`.

## Reviewed source contracts

- **P6 getter and import.** The selected `TCUWControlCommPhase.dll!Execute`
  receives `CStart + 0x14c` as argument 2 at CUW `0x1005ae52`. After its return,
  the worker stores callback `0x1005a6a0` in `CStart + 0x10`; the owner invokes
  it at `0x1003d00d`, and the thunk enters importer `0x1005a050`. The borrowed
  record vector is engine `+0x2e4`. The getter's companion writes apply the
  current node's DiagID to every newly received CID, up to the 34-record raw
  capacity. This is not a one-record-per-node mapping. Import scheduling and
  raw getter execution are distinct ownership boundaries.
- **D2A1 lifecycle.** Original CUW initialization and full cleanup zero the
  adjacent 16-bit word D2A0, thereby clearing D2A1. Target matching sets D2A1;
  retry result exactly `1` preserves it. The host's existing latch now clears
  at its reached late cleanup stage, after resource release. Early cleanup
  faults retain the latch.
- **Persisted recovery.** Callback `3ffa0` consumes recovery mode before the
  ordinary query path. The native `3cb90` loop re-signals the same worker;
  a one-shot phase-two call does not model this re-entry. The host correction
  uses its existing child/outer callback handoff. Query re-entry alone does
  not prove that a family programming export ran.
- **DRS dispatch.** In the matching version-18 dispatcher, the six `Execute`
  context slots are sender, response, and the values of manager fields
  `+0x28`, `+8`, `+4`, and `+0xc`. The final slot forwards the monitor pointer
  stored at dispatcher `this + 0x224` to `DataMonitorRun`. An earlier apparent null-slot contradiction was
  an ESP-relative stack arithmetic error. The internal monitor profile's
  identity with the selected-car member remains unproved.
- **P3 receiver.** The phase wrapper forwards `monitor_system_send` through
  virtual slot `+0x58`. Its constructed J2534 receivers resolve to
  `DataListIF!J2534DiagInterface::monitor_system_send`, rather than the base
  implementation. The external `DataMonitorPhase3!Run` caller remains open.
- **VBF caller ABI.** `CuwBackendService.dll` has a P/Invoke binding to
  `CUW.dll!ProcessBeforeReprogramming`: stdcall, zero arguments, `int32`
  result, matching native ordinal 32 / RVA `0x64c00`. Protected managed
  bodies still prevent assigning an exact GUI event or retry-dialog timing.
- **Calibration identity.** The no-car-5 getter dossier belongs to CUW2026
  `TCUWCalibrationFile.dll` version `1.0.0025.0`, not CUW18. Its `0xae9c`
  record stride must not be applied to the separately registered CUW18
  `1.0.0019.0` image. That image's layout remains unresolved locally.
- **GTK utility replay.** The ordinary source-bound recorded-replay path
  already creates `NativeDCM45Runtime` through `open_native_utility` and calls
  `runtime.open`. Its fixture smoke is a separate path. This corrects the
  earlier fixture-only attribution without certifying live CGW parity.

## Narrow delivered coverage

The [selected database review](native-selected-review.md) binds six contracts
to 32 exact version-18 `KgpDataCtrl.dll` exports. Constructors, mutators, other
tables and the module audit remain open. The frozen native universe includes
runtime/platform dependencies; its open-target count is not a count of missing
diagnostic features or an effort estimate.

The TechVim addition is a source-bound HRESULT status reducer. Full SDK
provisioning, controller scheduling and its runtime caller remain incomplete;
the reducer does not constitute a programming workflow.
