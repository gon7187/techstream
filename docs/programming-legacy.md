# Native legacy P4/P5 programming stages

`scripts.programming_legacy` implements the stage bodies of 26 CUW18 libraries: ten flash writers, thirteen prepare writers and three CID getters. Their 30 callable exports include Body's gateway-mode entrypoint and three finish probes. CUW12 supplies 25 of these libraries and 29 exports; SecurityPowerTrainPrepare is CUW18-only. This is replay execution over injected providers. It neither loads original DLL code nor opens a vehicle interface.

Select the native source build using `legacy_module_profile(module_name, sha256)` after `calibration_catalog.inspect_module(path)`. This wraps the shared exact-hash registry; a filename or RT_VERSION string alone cannot establish the source build. Pass the returned `native_build` to the stage runner. Catalog dispatch supplies the selected module and exact native address pairs. Parameter keys, CPU data, retry flags, passwords and authorization responses remain explicit caller inputs.

## Provider contracts

`LegacyTarget(request, channel)` binds an exact two- or three-byte native transmit address to a channel whose ECU/provider binding already selects the corresponding receive address. CID getters and fixed-prefix prepare helpers require two-byte addresses. CUW18 P4PowerTrainPrepare accepts the extended three-byte form; CUW12's helper uses a fixed four-byte CAN-ID prefix and rejects it.

P5 diagnostic operations use `programming.NativeProgrammingChannel`; P4 operations use `programming_vendor.VendorDiagnosticChannel`, including the second target of mixed P4/P5 operations. Their native pending/retry policies differ. Neither channel retries a transport exception as if it were a trusted ECU response.

Flash writers use `programming_vendor.VendorCAN`, which preserves raw writes, standalone `3c` acknowledgements and status polling. `finish_channel` is a separately bound provider for the native finish transmit/response addresses. Non-VFOREST writers require `get_timeout() -> uint32` and `set_timeout(milliseconds, remaining_seconds)` callbacks. They snapshot, configure even a zero-valued parameter, and restore the old timeout in cleanup. Cleanup receives a nonnegative remaining budget even after cancellation. VFOREST has no global timeout configuration/restore; its optional initial-command timeout still requires the setter. CXPI additionally requires a `set_bs(value)` callback, paired enable/reset in cleanup. Nonzero native waits require an explicit wait provider; they are not silently skipped.

Prepare runners accept raw diagnostic-mask writes, wait, BS configuration and gateway confirmation callbacks where the selected native path requires them. Diagnostic mask is three writes of payload `a027` on identifier `0x720`. A BS enable attempt is paired with reset even when the enable provider applies the change and raises. `key_provider(module, seed)` returns an explicitly authorized response of the exact native width; authorization material is never derived. Security variants additionally require their explicit ECU auth, nonce and key fields.

## Executed families

| Family | Native behavior retained |
|---|---|
| P4 Airbag / ClearanceSonar prepare | `2703` with the two-byte supplied password, two-byte seed/key and trailing `34`; optional BS, mask, `1002`. |
| P4 Body prepare / gateway | Six-byte seed/key using `2761`/`2762`; extended-address BS path; gateway `1060` only for the native bus/external-memory branch. |
| P4 ChassisShrink / SecurityChassisShrink prepare | Native CPU selector order, including ECU kind `13`; four-byte or sixteen-byte authorization, mask and mode per selected CPU. |
| P4 SecurityAirbag prepare | Sixteen-byte supplied ECU authorization and seed/key; per-CPU mode changes and first-CPU mask. |
| P4 PowerTrain / mixed P4P5 prepare | Distinct old/P5 probes, explicit unavailable-target branches, native seed waits, mask and selected mode/routine calls. |
| P5 PowerTrain / BodyMicon / Solar / SecurityPowerTrain prepare | All-target `1002` probes, native accepted-target filtering, four/six/sixteen-byte security, mask and `31011003`; native ten-millisecond spacing. |
| Airbag / Body P4/P5 / DSS1 flash | CheckID, memory descriptor gate, exact block mapping, erase, write, in-verify, optional verify, finish/CPU transition. Body nonverify skips verification while writing the full image. |
| ChassisShrink / SecurityChassisShrink / Sonar flash | Memory-derived block completion and grouped ranges; explicit CPU descriptor/shrink matching; native CPU transition and finish ACK policy. |
| SecurityAirbag / SecurityChassisShrink flash | Supplied sixteen-byte nonce/key split over native raw frames, ordinary block flow, final falsification check. |
| Body CXPI flash | Wide erase and three prepare-address `3e02` sends separated by four total two-second waits; native 128-byte verify2 chunks. |
| P4 VFOREST flash | Native ZV group lengths, `42` write and `17` verify headers, per-group fragments and status; no synthesized erase phase. |
| P5 / P5WithSetBS / mixed P4P5 CID | Real `22f181` or P4 `0900` support probe followed by `0904`, native count/16-byte ANSI CID records, bounded address association and version-specific auxiliary helpers. |

The Body endianness field is an explicit context input because native code reads a separate caller metadata table. It is not guessed from `CPUParameters.BigEndianFlag`. The Chassis EMPS comparison uses the actual imported native value `13`, not a display label.

`BlockSizeInfo` parses native decimal `start:sizeKiBxcount` groups. Block helpers retain next-group gap sizing, memory-derived final counts, one-based command ranges and zero-based S0 endpoints. Host checks reject overlaps, address overflow, truncated images, zero progress and excessive allocations before destructive block commands.

## Version and failure semantics

CUW12 CID getters do not issue the auxiliary helper queries added in CUW18. In CUW18, P5 query kind 2 invokes slave CID, assembly, serial and CBest helpers. Typed native failures of these four optional helpers produce empty optional fields and structured errors while retaining successful CIDs. The P4 assembly helper has no equivalent native catch and remains fatal. Timeout skipping accepts only explicit native transport codes 9/16 for the exact permitted P5 address, never host cancellation or deadline failure.

CUW12 Sonar sends finish without awaiting an ACK; CUW18 awaits it. VFOREST failure clears progress in both builds, but only CUW18 emits the native reset callbacks. The other nine writers emit reset callbacks in both builds. Native constructor offsets and CPU record strides are represented by validated typed context fields rather than copied memory layouts.

The native context flags remain distinct: `native_retry_flag_728` enables the one-or-eleven initial-command attempts in Airbag/SecurityAirbag and Body/CXPI; `native_retry_flag_72c` controls retry-password cleanup; `native_flag_740` selects the Chassis/Sonar ten-second initial timeout. Airbag retries only native initial-ACK error 7, waits `WaitTimeAfterInitialCommandError`, and toggles between the two explicitly supplied authorized passwords (`password`, `alternate_password`, `password_is_new`). Body retries retain the selected password. Untyped host transport failures, malformed data, cancellation and deadlines never become retry authorization.

`progress("count", cumulative_bytes)` and `progress("percent", integer_percent)` execute immediately after each data-fragment write and before its ACK, matching native observable progress. Confirmed `transferred_bytes` advances after successful write/status completion. A progress callback cannot turn an unacknowledged fragment into confirmed transfer.

A failure after an erase/write attempt returns `recovery_required` with an image-bound checkpoint, phase and uncertain flag. Supplying that checkpoint never automatically replays destructive commands: native retry metadata and ECU state require explicit reconciliation. Cancellation or deadline expiry takes precedence over optional native unavailable-target branches. Cleanup failures remain visible and cannot yield `complete`. Native wrappers that historically returned success after an exception are not used to certify a failed host stage.

Reports omit seeds, keys, passwords, image contents and wire history. Transport provider histories can contain authorization traffic and remain private. A `complete` result means the supplied deterministic provider acknowledged that one CPU stage. It does not authorize programming, establish vehicle compatibility or prove an installed calibration. Physical behavior is `PHYSICAL_UNCONFIRMED`.

## Authored example

```python
from scripts.programming import NativeProgrammingChannel
from scripts.programming_legacy import LegacyTarget, legacy_get_cids

requests = []
def exchange(ecu, request):
    requests.append(request)
    assert request == bytes.fromhex("22f181")
    return bytes.fromhex("62f18101") + b"DEMO-CID" + bytes(8)

result = legacy_get_cids(
    "TCUWP5CanCIDGetter.dll",
    [LegacyTarget(bytes.fromhex("0100"), NativeProgrammingChannel(exchange, "demo"))],
    native_build=18,
)
assert result["cids"] == ["DEMO-CID"]
assert requests == [bytes.fromhex("22f181")]
```

Run `python -m unittest tests.test_programming_legacy`. Fixtures are authored bytes and injected transports. Private corpus verification reconciles 51 exact source identities/59 exports, all 328 supplied parameter sources and 271 nonempty block-layout rows. Original OEM tables, images, decompiler output and packet material are excluded from public fixtures.

## Imported calibration inputs

`bind_legacy_context(container, node, observed_cids, selection, identity, attachments=None, observations=None)` binds a parsed CUW and an actual catalog selection to `LegacyInputs`. It derives the selected CPU image, block layout, decoded S0 header, LocationID, matching TargetData, native password source, communication addresses and preparation fields. The exact static module identity chooses CUW12 or CUW18 behavior. The DLL selection uses CPU0 metadata; per-CPU writer parameters use the selected CPU row. Invalid geometry, mismatched catalog keys and ambiguous observed CID/password matches fail before transport callbacks.

Ordinary S-record images retain all S1/S2/S3 records, sort them by unsigned address, fill address gaps with `ff`, and copy them in that order. The native span ends at the final sorted record; an earlier record extending beyond that end is rejected. The reported flash size is the sum of record data lengths, separately from the materialized address span. Non-S-record images require the native `.vbf` filename classification. `bind_native_cpu_context`, `materialize_legacy_image` and `native_cpu_passwords` expose these same bounded rules to other native families.

The original executable adapter explicitly passes `original_executable_build=12` or `18` to the shared CPU binder. Those executables retain a string `LocationID`, including the P5 literals `98` and `216`, and obtain addresses from their own source-derived header producer. This mode retains the original string, exposes a byte location only for exactly sixteen hexadecimal characters, and omits DLL catalog address evaluation. Ordinary DLL and newer-engine callers keep the strict eight-byte LocationID contract. Executable metadata-version admission belongs to the original executable adapter.

Imported global Vehicle ECU/service authorization and per-CPU nonce/key material remain private values. An explicit attachment may supply missing authorization material; conflicting supplied/imported bytes fail. No authorization algorithm is derived. Reports omit image data, passwords, keys and decoded header bytes. Password resolution follows the selected native family and execution branch; unused new-password fields are not parsed.

`LegacyInputs.bind_targets(factory)` binds catalog addresses to the correct old or P5 diagnostic policy. Injected `lifecycle(operation, parameters, remaining_seconds)` callbacks represent native timeout, filter and connection operations. CID getters connect/disconnect; prepare/write exports use their existing connection. Cleanup failures remain visible as recovery-required results. The selected address list preserves the native seven-byte vector record order: offsets `+7/+10` used by SBR master setup refer to the second address, not an inferred auxiliary field.

P5 legacy GetCID and preparation calls use the native 180-second whole-second pending timer.
A native elapsed-limit expiry invokes the channel’s explicit
`pending_timeout_write(ecu, b"\x3e")` write-only provider once. A host deadline
or cancellation never sends that cleanup. Optional auxiliary native expiry
retains the successful CID; host timeout and cancellation stop the operation.
If that expiry is reached without a write-only provider, the operation fails
explicitly rather than reporting completion.

Archive data is materialized only when the native branch reads it. CID getters, CentralGW and P5 preparation do not need a fabricated CPU image. A preparation context may retain `cpu_image=None`; the bus-type helper requires bytes when `CANCommunicationSpeedAddress` actually requests an image byte. VFOREST alternate parameters are resolved only after the current firmware descriptor fails its CPU match; other legacy writers never load an unused AlternateCPUType row.

Finish routing follows each family’s original caller: Airbag, SecurityAirbag, Sonar, DSS1, Chassis and SecurityChassis use CPU0’s functional request; Body4/Body5/CXPI/VFOREST use the selected CPU. Chassis/SecurityChassis/VFOREST take two address bytes, CXPI takes three, and the other families follow the native extended flag. CXPI’s two-byte `0720` source has a zero third byte in the initialized native record. An acknowledged finish still reads the selected physical response address. This routing is derived separately from the native seven-byte address vector order.

All injected callback boundaries check host cancellation and deadline, including the final cleanup callback. KeyboardInterrupt or a failed cleanup cannot produce a completed destructive stage; remaining cleanup operations are still attempted. Error reports retain bounded exception-type chains, including the original provider classification when a host limit takes precedence. Exception messages and authorization data are omitted. Read-only CID errors retain their primary exception and attach structured cleanup details. `RequestCANIDAllowingTimeout` is resolved from the selected catalog only on the native status9/16 skip branch; malformed unused allowance fields do not invalidate a positive response.

CUW18 getter results include `address_metadata` entries with native flag zero and uppercase request IDs, capped at 32 CID entries. CUW12 omits that later native output. The separate `cid_addresses` list is explicitly a host observation of which target returned each CID.

The authored imported-CUW regression runs the complete parser → catalog → adapter → injected runner path for all 51 module/build combinations. These checks cover CUW12/18 source contracts; newer recovered engine builds require their own native comparison and are not implied by this identity binding.

`bind_legacy_finish_probe(container, node, selection, identity)` binds CPU0’s physical address for the three recovered IsFinishReprogramming exports. It validates the actual write catalog/module identity without decoding image or password fields. `legacy_is_finished(..., lifecycle=...)` starts that filter, sends `3e`, accepts any one response payload, and stops the filter. A native transport failure yields the negative probe result; host cancellation, deadline, interruption or uncertain cleanup remains an explicit error. This probe does not certify an installed calibration.

CXPI write inputs expose `tester_present_request`: the actual `write_messages` primitive from the current CPU’s first preparation address, protocol6, TX flags128, count1, and its five-byte address prefix followed by `3e02`. The caller supplies only the primitive transport execution; the three sends and native waits remain in the recovered erase helper.

Native semantic failures retain their original numeric codes. Common CPU/memory checks use10, erase12, write13, in-verify14, verify15 and falsification73; VFOREST write/verify use29/30. The native VFOREST catch replaces the transport exception’s code while retaining its original class. Diagnostic errors additionally retain `native_cuw_code` without replacing an NRC’s `.code` or response bytes: seed16, key17, common mode18/49, P5 mode41 and routine25. Optional legacy data helpers use the actual3/92/94 caller codes. Native pending/busy limits remain distinct from host deadline or cancellation. Host input/budget failures are not assigned guessed native codes.

Body gateway results expose `gateway_result_valid` separately from `gateway_result`. The original external-memory or nonmatching bus branch returns true with validity false; an executed native helper returns its result with validity true. Host interruption and failed cleanup invalidate the output. The skipped branch does not parse unused image, seed/key-provider or wait fields.

## Static provenance

The SHA-256 prefix and RVA identify each CUW18 stage body; the full original identities are retained in the shared static metadata registry. These are static provenance references, not runtime DLL dependencies.

| Module stem | SHA-256 prefix | Body RVA |
|---|---|---|
| TCUWP4CanAirbagFlashWriter | 7686ca90fa12 | 11c0 |
| TCUWP4CanBodyFlashWriter | 98752a7f8314 | 1170 |
| TCUWP4CanBodyFlashWriterForCXPI | 1d73ad1719cd | 1260 |
| TCUWP4CanChassisShrinkFlashWriter | 90fe884150c4 | 1160 |
| TCUWP4CanClearanceSonarFlashWriter | 63c0214218f1 | 1120 |
| TCUWP4CanDSS1FlashWriter | 481143e2358e | 1120 |
| TCUWP4CanSecurityAirbagFlashWriter | b8e9c81b300b | 11c0 |
| TCUWP4CanSecurityChassisShrinkFlashWriter | e5ba42abbb60 | 1160 |
| TCUWP4CanVFORESTFlashWriter | 0721243b7f96 | 1160 / 1ad0 / 1c20 / 1f20 (export 2340) |
| TCUWP5CanBodyFlashWriter | d03dc43c7224 | 1170 |
| TCUWP4CanAirbagPrepareWriter | 0a2898843e98 | 10e0 / 1400 |
| TCUWP4CanBodyPrepareWriter | 0326c4515d3f | 12e0 / 16b0 |
| TCUWP4CanCentralGWPrepareWriter | 125b3c800353 | 1000 |
| TCUWP4CanChassisShrinkPrepareWriter | ea8baa28a29f | 1160 / 1410 |
| TCUWP4CanClearanceSonarPrepareWriter | 0f7df48a01c0 | 10e0 / 1400 |
| TCUWP4CanPowerTrainPrepareWriter | a88fac87421d | 11e0 / 1ac0 |
| TCUWP4CanSecurityAirbagPrepareWriter | 82cfc42a6b76 | 10e0 / 1400 |
| TCUWP4CanSecurityChassisShrinkPrepareWriter | 88f7e7387544 | 1160 / 1420 |
| TCUWP4P5CanPowerTrainPrepareWriter | 0a64261d70e6 | 10f0 / 1270 / 16a0 / 1bb0 |
| TCUWP5CanPowerTrainPrepareWriter | c8ce54595b9f | 1130 / 1560 / 16e0 |
| TCUWP5CanPowerTrainPrepareWriterForBodyMicon | 2c3d784965b8 | 1130 / 1390 / 1510 |
| TCUWP5CanPowerTrainPrepareWriterForSolar | 3e73eb6eb0c7 | 21f0 |
| TCUWP5CanSecurityPowerTrainPrepareWriter | 07c6f2e162e3 | 20a0 |
| TCUWP4P5CanCIDGetter | 4690a7f1cb65 | 1460 / 1810 / 1cf0 |
| TCUWP5CanCIDGetter | b4cc069894ee | 1c10 |
| TCUWP5CanCIDGetterWithSetBS | 792d2d13d712 | 1c10 |

Shared native block primitives are imported from `TCUWCanCommonFlashWriter` and `TCUWFlashWriterUtils`, not inferred equivalent across different family DLLs. Their recovered Python implementations live in `programming_vendor`; diagnostic data codecs live in `programming`. Security transformations remain an explicitly supplied authorization-provider boundary.
