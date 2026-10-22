# Native TY chassis bodies

`utility_ex_ty_chassis.run_body(export, args, context)` implements selected exact
18 TY source business operations over the concrete UtilityEx communication core.
It validates both the declared SHA-256 and actual supplied module bytes before
opening communication. `supports` describes reviewed source/export pairs only.
Unknown variants and operations fail closed.

The common engine owns wrapper mode guards, worker scheduling, deadline and
result publication. These bodies own request bytes, echo/length/bit predicates,
mutable native UI buffers, selected loops, restoration and manager ownership.
The context's sleep and communication primitives must enforce the common
scheduler's bounded deadline/cancellation contract. No hardware opens on import.

## Implemented source

Exact original SHA-256:
`79fc495c68eb099a7ebc0d1eefe0eafd80101ac0bc09a58d3f603ed556c84762`.

Source workers/helpers were checked against cached original x86 ASM, including
stack arguments omitted by the untyped decompiler. Implemented groups:

- AHC03: read service-mode bit (`c27b0`, helper `c28c0`), switch service mode
  (`c2830`, `c2990`), end extended session (`c2890`).
- EMPS09/11: selected mode-transition flags, concrete routine start/poll/stop,
  live cancellation field and source-specific restoration (`87510`, `b1730`).
- EMPS12: extended-session steering start (`8ad60`), start auto rack centering (`b18a0`, `b19f0`), poll result (`b1920`,
  `b1a80`/`b1b30`), read steering-angle bytes (`b19a0`, `b1bc0`).
- ABS32: support bit checks, EPB full release and delayed dual-byte readback
  (`89cd0`..`8a110`), preserving missing-support `99` and session error mapping.
- ABS31: selected support/routine checks, support-dependent output flag,
  neutral/calibration starts and the single native delayed retry
  (`897d0`..`89c10`). Routine cleanup errors do not replace the native result.
- ABS29: five support mask predicates and dealer-mode/readback with its
  distinct native status mapping (`88ff0`..`892f0`). The zero-argument
  support and shift exports are admitted for the exact TY18 and Plus images;
  their host-fault path attempts bounded normal-session cleanup after
  initialization and preserves the original exception through finalization.
- ABS33/34: selected support DID/routine chain, eleven paired sensor booleans,
  dealer/normal transitions and complete memory clear (`8a110`..`8a710`).
- ABS41: DID support, two timed selected solenoid phases, motor drive/stop
  (`92ca0`..`93590`). Solenoid timing preserves the native extra tick
  subtracted across DWORD wrap. Host cancellation uses the same stop/restore
  path as a native communication fault and returns `1000`.
- ABS47: dealer-mode entry (`b7a90`, `b8060`/`b8100`), calibration status
  (`b7b00`, `b81d0`), error and exit restoration (`b7b40`/`b7b70`), complete
  DID/RID support chain and sparse selected sensor flags (`b7950`..`b7fa0`).
- ABS48: bit confirmation, ECB prohibition, rear air bleeding, dealer/normal
  transitions, explicit stop, timeout and wait, vacuum-fill incomplete flag
  (`b82b0`..`b8cf0`). Vacuum writes preserve the actual returned payload, replacing
  only its second byte with `0x80`. ASM restores success predicates that the
  untyped decompiler incorrectly removed in `b8c10`.
- ABS49: SLM2 refresh and pattern-drive flag lifecycle (`b8da0`..`b9030`).
- ABS52: brake-pad thickness read/write/readback (`c10f0`..`c1520`) for TY18
  and Plus. Plus uses its own manager and retry configuration. Reads validate
  DID echo bytes without requiring a positive SID and
  publish each successful sixteen-byte block independently. Writes send the live
  UI bytes36..52, accept echoed responses of at least three bytes, sleep1000ms,
  then publish both readback blocks and compare them against the current UI bytes.
  A host exception after activation attempts bounded normal-session cleanup.

- TPW07: support checks, system-operation-mode read and saved-byte write
  (`8fd10`..`900c0`). Returned full diagnostic frames and their native lengths
  feed the subsequent write; first and second block bit changes retain native
  sequencing. Declared lengths are bounded before I/O.
- EKDSS01/02: selected routine argument/start/stop and cleanup (`a2df0`..`a30df`).
- 4WD07: complete selected capability bitmaps, native routine selector,
  first clear and remaining selected clear/poll stages (`88150`..`88ff0`).
- BSM13/14 and15/16: DID payload/length output, actual selected payload write,
  comparison and conditional second DID mutation/readback (`97550`..`97b80`).
- PSAABS01/02/03: selected communication routines, timed pending loops,
  two-pass operation, three selected active-test bytes, result mapping, strict
  timeout and stop chronology (`44070`..`44c00`).
- AWD04 Overwrite: native body `86380` publishes `1024` without communication.
- ASUS10: support-mask selected DID and change/readback for 18/Plus; fixed DID
  read/change for supplied12. Echo validation compares DID bytes only. Write
  replies require exactly three bytes; extra bytes return3 without delay or
  readback, while still attempting the normal-session restore.
  publication and restore-error precedence (`84d20`..`85030`).
- EPB05: complete support chain or dealer-mode/readback selected by DWORD0
  (`9b2d0`..`9b510`), preserving original status and restore policy.
- EPB04 and ABS44 share the actual same native worker (`9b190`..`9b2d0`).
- ASUS08 native end-session error mapping (`840c0`/`840e0`) remains distinct
  from ABS47 end-session status discard (`966f0`).
- EMPS09 support (`873d0`): conditional routine support read, two output DWORDs,
  source zero-fill semantics and restoration status precedence.
- ASUS13 TestStart, GetHeight, GetHeightSec50, HeightOffset,
  NormalMode/NormalMode005/NormalMode008/TestStop (`75eb0`..`76d20`): selected
  legacy-manager request chronology, live height polling, one selected reply
  byte, literal response predicates and fixed exit status mapping.
- ASUS04/05/13 and ARS01 support consume the actual A8 packed records and
  256-entry offset table. They preserve required byte/mask checks, native
  nonzero counts, selected offsets, status22 and source-specific status3 mapping.
- VGRS04 lock release, neutral mode start/end and DTC clear
  (`325b0`..`328a0`, `33020`): literal request lengths, timed sequence and
  distinct stop-error mapping.
- BSM03/04 and05/06 active tests (`34500`, `352c0`): selected request/reply
  layouts, strict five-second pending loop, optional secondary result decode,
  native word byte order and explicit stop chronology.
- 4WD03 support and prevention-mode change (`37bb0`..`38150`): native A8 kinds1/3,
  selected response count, readback bit and conditional rollback.
- ASUS06/07 condition, lift and pressure operations (`83540`..`83fc0`): actual
  seven-byte routine requests, selected phase bytes, pending timer, explicit
  stop/normal restoration and retained success sessions.
- ASUS08 mode and pressure read (`84280`..`8457a`): retained context state,
  native pressure thresholds and extended-precision truncation. All65536 raw
  values match an authored C long-double arithmetic control; no vendor code
  was executed.
- ABS17 support/read/synchronization (`28e40`..`29440`): actual selected offsets,
  packed A8 records, two synchronization modes and native failure publication.
- ABS30 and46 (`893d0`..`89730`, `b1100`..`b1320`): selected support/routine
  readback, two-stage live polling and distinct restoration/result precedence.
- EMPS07 (`5c4e0`..`5c850`): specific DTC gate, assist-map word and clear NRC mapping.
- DRS02 and03 (`36330`..`36c60`, `3a720`..`3b1d0`): all operations, target790
  selection, packed support joins, native selected layouts, periodic mode refresh,
  retained reads and bounded end-process waits. DRS02 still copies returned
  bytes on communication failure, matching its source.
- ASUS04/05 (`26ee0`..`279b0`, `4b6b0`..`4c490`): all selected support,
  start/stop/return, learning and timed height checks; literal request bytes,
  live cancel flag and native restoration-error precedence.

These are native return/status semantics, including surprising ownership:
ABS47 status polling and ABS49 cancellation/exit flags retain the manager;
AHC read and successful drive starts retain the selected extended session;
explicit cleanup exports restore and finalize. The caller must not infer that
all returning bodies close the manager.

## Native mutable buffer contracts

All arguments are one `bytearray`, unless an operation below takes no arguments.
The byte layout is native little-endian; it is not an invented UI model.

| Operation | Minimum bytes | Fields |
| --- | ---: | --- |
| AHC03 ReadModeStatus/SwitchServiceMode | 4 | DWORD at0; switch consumes truth value and overwrites readback |
| EMPS12 ReadRoutineStatus | 20 | cancel DWORD0, exit DWORD4, returned byte16 |
| EMPS12 SteeringAngleCheck | 19 | stop DWORD8, updated DWORD12, two received bytes17..18 |
| ABS33 SupportCheck/CheckSensorStatus | 22 | eleven boolean pairs with native response mask mapping |
| EMPS09 ModeTransition | 8 | DWORD0 enables delayed routine; DWORD4 selects pre-routine |
| ASUS10 Get/Change | 2 | output/current byte0; selected DID byte1 |
| EPB05 SendMessage | 4 | selected action DWORD0 |
| EMPS11 SendMessage | 8 | action DWORD0; live cancel DWORD4 |
| EKDSS01 SendMessage | 6 | action DWORD0; selected routine byte5 |
| TPW07 all operations | 0x204c | mode DWORD0; lengths DWORD4/8; full frames at12/0x102c |
| ABS47 CheckCalibrationStatus | 85 | cancel DWORD0; seven booleans at12,24,36,48,60,72,84 |
| ABS47 DIDRIDSupportCheck | 80 | seven support DWORDs at4,16,28,40,52,64,76 |
| ABS31 SupportCheck / RoutineStart | 8 / 4 | support output DWORD4; selected routine DWORD0 |
| EMPS09 SupportCheck | 8 | two output DWORDs at0 and4 |
| ASUS13 GetHeight/GetHeightSec50/HeightOffset | 12 | live exit DWORD0, cancel DWORD4 (GetHeight), selected reply-byte offset DWORD8 |
| ASUS13 TestStart | 16 | selected active-test payload length DWORD12 (0..0x101d) |
| ASUS13 SupportCheck | 16 | selected reply offset DWORD8; active payload count DWORD12 |
| ASUS04/05 SupportCheck | 12 | selected reply offset DWORD0; response/request lengths DWORD4/8 |
| ARS01 A8SupportCheck | 8 | two native supported-record counts plus2/3 atDWORD0/4 |
| VGRS04 StartLockRelease | 4 | selected request length DWORD0 |
| BSM03/04 ActiveTest | 36 | result/status/secondary/start lengths DWORD0/4/8/12; offsets16/20; output words24/26; routine byte28; result selector DWORD32 |
| BSM05/06 ActiveTest | 32 | result/status/start lengths DWORD0/4/8; offsets12/16; output words20/22; routine byte24; second-word selector DWORD28 |
| 4WD03 SupportCheck/ChangePreventionMode | 4 | selected response payload count DWORD0 |
| ASUS06/07 LiftRise/AirPressure | 8 | selected height/axle DWORD4 |
| ASUS08 ModeTransEnterHeightCtrlProhibit | 4 | selected mode DWORD0 |
| ASUS08 ReadPressureSensor | 20 | native double output8; threshold status DWORD16 |
| ABS18 SupportCheck/SetNeutralPos | 20 | selected offset DWORD0; reply lengths DWORD4/8/12; write length DWORD16 |
| ABS21 SupportCheck/ChangeMode/CheckSensorStatus | 20/24/20+ | 13 support flags; sensor payload at13; response length DWORD16; mode DWORD20; sensor output capacity checked before copy |
| BSM01/02 except exit | 9 | selected reply length DWORD0; component DWORD4; status byte8 |
| BSM07/08 | 12 | read/write lengths DWORD0/4; history output DWORD8 |
| BSM03/04 and05/06 SupportCheck | 36/32 | same selected layout as corresponding active operation |
| BSM27/28 SendMessage | 8 | action DWORD0; raw probe status DWORD4; separate saved target globals |
| ARS04 SendMessage | 8 | action DWORD0; live exit DWORD4 |
| EMPS13 SendMessage | 16 | action DWORD0; live exit DWORD4; stop selector DWORD8; completion DWORD12 |
| ABS51 SendMessage | 0x204a | action DWORD0; selected slot WORD4; lengths WORD6/8; payload slots10/0x102a |
| ARS01 ReturnActuatorCenterPos | 8 | read length DWORD0; active request length DWORD4 |
| ARS02 InitCompVal/ARS03 ActiveTest | 12 | read result length DWORD0; optional pressure reply length DWORD8 |
| VGRS04 SupportCheck | 4 | selected active request length DWORD0 |
| DRS04 SendMessage | 0x1064 | payload count DWORD0; payload4; write count DWORD0x1024; action DWORD0x1028; two28-byte support descriptors0x102c/0x1048 |
| ASUS08 StartCompressRaisingCtrl/StartTankPressLowCtrl | 20 | completion DWORD4; pressure double8; threshold status DWORD16 |
| ABS4WD01 both operations | 8 | independent target response payload counts DWORD0/4 |
| ARS05 SendMessage | 14 | action DWORD0; live exit DWORD4; live result selector DWORD8; saved configuration bytes12/13 |
| ABS17 SupportCheck/GetABSInfo/SychronizingABSInfo | 12/14/12 | selected offset DWORD0; read length DWORD4; write length DWORD8; two output bytes12/13 |
| ABS30/46 SendMessage | 4 | native action/live exit DWORD0 |
| EMPS07 ConfirmTheAssistMap | 2 | raw returned word bytes0/1 |
| DRS02 operations except stop | 28 | selected offsets DWORD0/4/8; read/start lengths DWORD12/16; counter DWORD20; output bytes24..26 |
| DRS03 operations except stop | 20 | read/start lengths DWORD0/4; counter DWORD8; output bytes12..14; selected offset DWORD16 |
| ASUS04 ModifyVhight | 20 | selected request length DWORD8; height100/200 DWORD16 |
| ASUS04 LearnKneeldownVheight/CheckReturnedVhight | 13 | selected reply offset DWORD0; read length DWORD4; output byte12 |
| ASUS05 ModifyVheightDownStart/ModifyVheightStop | 12 | selected request length DWORD8 |
| ASUS05 LearnKneelDownVheight/CheckReturnedVheight/CheckModifiedVheight | 13/13/14 | reply offset/length DWORD0/4; output byte12; modified-check cancel byte13 |
| ABS49 PatternDriveExecutingFlag | 8 | cancel DWORD0; exit DWORD4 |
| ABS52 ReadBrakePadResidualThickness | 36 | independent returned sixteen-byte blocks at4 and20 |
| ABS52 WriteBrakePadResidualThickness | 52 | same outputs; selected sixteen-byte input at36 |
| 4WD07 all operations | 80 | selected mode DWORD0; cancel DWORD28; support DWORD32/36; selected component DWORDs40..76 |
| BSM13/14 SendMessage | 0x1024 | returned payload at0; length DWORD0x1020 |
| BSM15/16 SendMessage | 0x102c | DID bytes0/1; input payload2; length DWORD0x1024; selected ID DWORD0x1028 |
| PSAABS03 StartActiveTest/ConfirmStatus | 16 | selected test bytes8..10; native timeout DWORD12 |
| ABS41 DriveSolenoid | 4 | selected valve DWORD0 |

All other implemented exports take no arguments. Buffers are validated before
I/O. Incoming replies are bounded by native `0x1020` capacity.

## Verification and remaining scope

Authored synthetic checks live in `tests/test_utility_ex_ty_chassis.py` and test
positive/fault/short/echo/cancel/readback/cleanup and native manager-retention
branches. They execute the real authored algorithms over individual fake
exchange/session primitives. They do not prove physical vehicle behavior.

The full assigned partition and every omitted export remain explicitly OPEN in
private `analysis/evidence/no-car-102/coverage.json`. The supplied12 ABS17/18/21, VGRS04 and EMPS07 bodies and Plus ABS18/21 bodies were independently reviewed against their own workers and helpers; all supplied12 pairs are now reviewed; omitted Plus pairs remain OPEN.
The four-source union contains no owned chassis exports for the supplied DS4
identity. Reviewed GTSPlus bodies additionally include AHC03, ABS48 RetrunWait,
ASUS08 EndExtendedSession, ABS41 DriveMotor/StopMotor, ABS44/EPB04 SendMessage,
ASUS13 except SupportCheck, ABS17, EMPS07 and the five VGRS04 lock/neutral/clear operations.
Plus uses its actual legacy manager setter `142f0`. Its ASUS13 start/stop
payload prefixes are `30 06 ff 04` / `30 06 ff 08`; the stop takes the same
16-byte selected input layout as start. The18 stop remains argument-free.
AWD04 Overwrite has wrapper
`7540` admits modes20/21, worker `88a30` publishes `1024` without communication.
Its exact source hash is
`821bbfd9957679ceef4ac32c239b8840c984e98ac61050ce7348ac2bc88b04ce`.
The union has 178 unique owned export names and 438 exact source/export pairs;
365 pairs have authored bodies and 73 remain OPEN. End-to-end communication/scheduler
closure additionally depends on leaves83/108 and parent-selected integration.
This module is partial and the full leaf gate remains OPEN.

Native ARS01/02 DTC consumers use the concrete `read_dtcs(0x80,0x1000)` primitive, filter wire words against `55c9` or `5b01/5b04`, and restore the selected VGRS target after finalization. BSM history/test-mode setters use source busy limit `121d0` for18, `b960` for12 and `14320` forPlus. ARS04 and EMPS13 pending loops are reconstructed from ASM because cached decompilation removes reachable loops.

The exact callable wrapper packet is `analysis/evidence/no-car-102/reviewed-wrapper-packet.json` (365 source-bound rows), with original modes, RET-derived outer arity,10000ms thread dispatch, callbacks and C/ASM hashes. Unused wrapper buffers are accepted and preserved for verified arity1 exports, including AHC03 EndExtendedSession. The supplied12 concrete legacy setter is `b940`; its lower initialization join remains OPEN.

Plus EMPS12 AutoRackCentering, SteeringStart and SteeringAngleCheck now retain all three original wrapper modes20/21/22 and select the corresponding Plus manager. SteeringStart initializes/configures, opens sessions1 then3 and retains only success. AutoRackCentering keeps the modern unused caller buffer untouched; mode22 requires the native0x1038-byte UI layout, copies the complete raw DID reply at0x13, writes its length at0x1034 and sends the saved payload in the exact write request before the routine start. SteeringAngleCheck reads the live exit DWORD8, publishes reply bytes3..4 unchanged at17..18 and completion DWORD12, then always restores normal and finalizes. A host cancellation or exception after Auto initialization or during the angle read attempts bounded normal-session cleanup before finalization, while preserving the original exception. Their body replies validate bounded lengths and echoed fields without requiring positive service IDs; original primitive statuses remain primary. EMPS12 ReadRoutineStatus remains outside this reviewed Plus set.

4WD06 uses the live initialization/cleanup bytes16/17, action DWORD12, cancellation byte32 and eight returned wheel bytes18..25. Its three control stages preserve the native1046 double-stop branch. 4WD08 uses action DWORD48, selected mode DWORD52, wheel bytes36..43 and live continue byte44; its500ms stability timer restarts when the speed changes between zero and nonzero. Native5000/7000ms counters and stop-error precedence remain exact. Both use source wire threshold103.

TPW06 uses40bytes (action DWORD32, manual/component selectors DWORD36/28), TPW08 uses28bytes (action DWORD0, flags byte12, completion DWORD16 and live exit DWORD24), and TPW13 uses36bytes (action DWORD0, five IDs bytes6..25 and mode DWORD32). TPW13 preserves the full2033 payload on rollback, and TPW08 preserves the native fast cleanup configuration leak on support failure.

4WD05 SupportCheck resets its capability fields before initialization and classifies four native modes from exact35/36-byte DID/routine frames, preserving missing-feature1001 and successful-normal-session error precedence. Supplied12 ASUS04 ModifyVhight uses its own b940 legacy setter; DRS02/03 stop preserve their distinct error-versus-response-length precedence.

Supplied12 ASUS06/07 condition, lift, air pressure and height/tank operations were independently reviewed, including omitted ASM payload bytes,20001/40001ms polls and literal pressure thresholds2205/1779. Successful air/condition paths retain the selected native manager; lift and tank restore and finalize.

AHC04 implements every selected action with primary1011d4f0/secondary1011c400 managers, target750/channel36 or3b, exact21-byte routine payloads and live UI status DWORD8. Its UI buffer needs0x104d bytes (action DWORD0, live selection DWORD4, configuration length DWORD20/payload24, supplied routine payload0x1038). Dual init failures, rollback, manager retention,35/70-second poll deadlines,25-second selected poll and dual keepalive are native source branches.

Plus ABS33 normal restoration and ABS47 three fixed-status exits include both wrapper branches: modes20/21 use101392d0; mode22 uses1013e7d0. The packet records each callback and separate original body hashes. ABS33 source reply minimum is4 for modern and5 for NK; restoration errors are discarded before publishing native fixed result.

BSM09/10/19/20 and BSM11/12/21/22 implement every native action, selected ECU scanning and0204/2055 payload-preserving toggles with full selected-ECU rollback. Buffers need26/25bytes respectively; action DWORD0, live exit byte4, initialization byte5, selected ECU DWORD16, global capability/list bytes22/23 (old) or21/22 (new). Old support preserves the stale payload flag even when the final read fails, matching ASM.

Four exports consume nested masks/history pointers through the source-owned NativeMemoryArena. Their exact hex offsets and original C/ASM hashes are recorded in `analysis/evidence/no-car-102/native-memory-requirements.json`; a flat bytearray is insufficient. TPW03 descriptors are inline at0x24; each descriptor mask pointer is at+4. The implementation validates arena source/owner before acquiring a manager, and bounds every pointer read/write to a live allocation. Actual caller/transport integration remains a separate gate.

Supplied12 BSM01/02 testmode and BSM07/08 history operations use exact b940 pending and b960 busy limits256, independently checked against original workers/helpers. Status bytes remain written on the same native error branches; clear readback errors map2000 and wrong testmode echo returns the native signed status.

Supplied12 ASUS04/05 are fully source-reviewed, including A8 selected indexes, distinct26001/50001ms readback deadlines, cancellation byte13, source initialization/configuration order and normal restore precedence. The exact own b940 legacy setter replaces the18setter only for that source contract.

The TY18 partition now includes all 178 owned names. TPW03 supports seven inline read descriptors and one write descriptor, including reverse mask support checks, state-dependent five-ID reads, mapping validation and the declared write count with a zero-filled tail. AWD04 preserves support/value/status precedence and frees/rebuilds the live history pointer using 27 native DID queries and exact four-byte record headers. 4WD05 reads live bounded history records and preserves native discarded wire errors. The four pointer bodies require an explicitly attached arena; they never invent pointer projections.

Additional independently reviewed supplied12 bodies include ARS01/02 DTC and offset operations; ASUS08 mode/pressure/compressor/tank and ASUS10 fixed2101 read/change. Plus ASUS10 uses the same proved discovery and change flow as TY18. Supplied12 ASUS08 tank uses one first-stage attempt,100ms delay and40000ms polling, distinct from18 retries. ASUS10 write replies require exactly three bytes in all variants; an extra byte returns3 without delay or readback, and the normal-session restore is still attempted. TY18 ASUS08 mode transition uses normal1 followed by extended3, as its original ASM requires.

All87 supplied12 pairs now have reviewed bodies. The remaining DRS/TPW/ARS/4WD/PSA algorithms and domain helper chains have instruction comparisons against18 in private evidence;12 BSM03/04 omits the optional6A/68 selector3 checks. All legacy bodies select their actual source pending setter. Plus ASUS04/05 all13 source/export pairs use142f0 and their original literal request lengths, read side effects, live cancellation and timer behavior. Actual12/Plus lower transport joins remain OPEN.

Plus source review additionally covers all DRS operations, BSM01/02 testmode, BSM07/08 history, BSM03/04 and05/06 support/active operations, TPW03 bounded masks,4WD03/ABS4WD01 prevention and all12 ARS01/02/03 operations. BSM conditional angle constants and ARS center coefficients/limits were read from the exact static Plus PE. Plus DRS wrappers include an explicit modes4/20 guard; the packet preserves it.

Plus ASUS06/07 all8 pairs preserve the exact condition/lift/air/tank payloads, selected20/40-second polls, two configured fields for condition/air and2205/1779 pressure thresholds. These helpers check response length and echoed fields; positive-service validation belongs to the actual lower communication result. Source-bound body tests preserve successful status with an echoed response independently of byte0, and reject a changed echo.
