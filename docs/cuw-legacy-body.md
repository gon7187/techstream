# Original executable body and chassis controllers

`scripts.cuw_legacy_body.execute(context, io)` dispatches the recovered original
Airbag, Body, ChassisShrink, ClearanceSonar, DSS1, EPB, FC, OldSpecECB and
ElectricPowerControl Execute entries. Each entry admits an imported
`ExecutableContext`, the exact original12/18 executable bytes and concrete shared
CAN/J2534 primitives. Preparation and LocationID channels bind the same live
`ChannelState`, including read/send timeout and padding fields. It does not execute an original PE or call a provider-defined
programming/erase/preparation algorithm. Engine58 revalidates the actual original
factory selection before dispatching each supported entry.

EPC executes source address preparation, seed conversion and diagnostic session,
selected LocationID/password binding, source CPU identification and block tables,
erase/write/internal-verify/verify, finish and native completion. Its typed native
preparation and transfer scopes retain driver DWORDs separately from operation
categories. A preparation failure enters transfer only when the actual manager
writing latch is already set. Native transfer failure resets and publishes the
selected CPU progress, updates the native password latch and runs the synchronized
error dialog and concrete original channel reconnect. Host aborts preserve the
uncertain manager flags, restore the entry timeout and release owned filters.

EPC's pointers `+110/+114` bind manager18 `+ed6/+ed8`, corresponding to manager12
`+146/+148`. They are separate from saved RecoveryInfo `WritingEndBlock/Writing`.
The callers18 `478a38/478a3f` and12 `44d2c5/44d2cd`, together with constructors18
`58bd20/58bd2c` and12 `5409ac/5409b8`, establish this binding. Direct flag stores
are RAM mutations, not an invented recovery-save operation.

EPB preserves its separate native sequence: CPU0 security, five-message atomic
CheckID, timeout snapshot after preparation, process-latch-selected120000/10000ms
transfer timeout,500ms pre-ID delay, narrow raw memory, erase/write/verify and
finish80 without an ACK. It does not write EPC's manager flags, run internal verify
or change its recovery password latch. Native transfer failures clear cached CPU
progress without EPC's publication callbacks. Constructor timeout covers the
preparation-failure restoration path.

The remaining helpers cover CPU descriptors, external-memory mode selection, S0
range expansion, source family size/range tables and security/session algorithms.
`BodyTables` reads only exact supplied executable identities. It reconstructs
Delphi string initializer stores and private CBytes2 WORD constructors statically;
original tables and private authorization operands are not embedded in the module.

The shared diagnostic transaction retains full native headers, mode2 filtering,
busy retries, pending limits, timeout changes and tester-present cleanup. Typed
native failures remain distinct from host validation, deadline and cancellation.
Native copies that exceed the supplied imported image fail before destructive
commands. These are host boundary checks, not additional native ECU features.

Portable checks use authored inputs and synthetic geometry where explicitly
marked:

```sh
python -m unittest discover -s tests -p test_cuw_legacy_body.py -v
```

The private source replay in `runtime/no-car-69/check_execute.py` reads both exact
original executables, imports authored CUWs and runs the actual CID getter,
address publication, target initialization, channel lifecycle and engine dispatch.
FC currently uses an explicitly authored AddressDiscovery output; its actual CID
getter composition remains open. No writer geometry/security algorithm is mocked.
The 112 cases cover all nine families in both builds, native failures, cancellation,
external S0 ranges, mode0/1/2, source KindOfECU53, partial two-CPU completion,
selected CPU1 with saved cursor0, actual CGW startup/accepted retry and all nine
families with short/empty original LocationID text in both builds. Physical and
functional headers and CheckID use the original zero-padded byte-array parser;
the strict DLL row LocationID is not a validity gate. Results are
in `analysis/evidence/no-car-69/execute-original-source-replay.json`. Authored
calibrations and ECU replies are not original-calibration or vehicle evidence.

Body and DSS1 preserve separate source preparation, address/configuration,
per-CPU sequencing and manager latches. Body external transfers consume decoded
S0 ranges; its source KindOfECU53 omits verify and halves the progress denominator.
Body CheckID endian comes from retained manager18 `+ee0` / manager12 `+150`,
captured at the first factory entry before compaction, rather than from the
currently selected CPU. DSS1 always swaps CheckID and uses its actual constant
primary diagnostic mask. Runtime constructor CPU index and persisted recovery
WriteCpuIndex remain separate; these controllers do not invent cursor advancement.

Chassis and OldSpecECB use their actual private group tables. OldSpecECB retains
its failed range and the source progress rollback arithmetic during accepted retry.
Sonar preserves its source WORD access conversion, password retry and managered5
latch. FC preserves its source address-pair-selected repeated session, block-loop
retry and progress reset even when retry is declined. Airbag retries only CheckID
CPass category7 locally; accepted transfer retry runs original18 AutoIG (absent in12)
and the concrete source-issued CGW branch before rewriting.

`central_gw_startup`, `central_gw_exists` and
`central_gw_change_to_reprogramming` implement original12/18 legacy CGW detection,
actual private key decoding/AES128ECB, diagnostic security/session and cleanup.
Startup and recovery are the only admitted feature-state producers; arbitrary
caller booleans are rejected. The RecoveryInfo IsCentralGWExist setter updates
RAM only, matching `42eca0` / `417fd4`; it does not invent a file save. The shared
CCan consumer independently replays this real startup and accepted retry in both
builds (`analysis/evidence/no-car-68/ccan-actual-cgw-retry.json`).

Original18 modern CGW variant1 still raises explicitly at the actual registered
MainFrm `49bcf8` online-key sender. Its full security/routine/periodic chronology
cannot be advertised as complete. FC getter composition, independent source review,
full manager integration and physical adapter/ECU validation also remain open.
