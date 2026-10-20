# Native programming build identity

A native module is recognized by its SHA-256 **and its canonical module name**.
Its PE `FileVersion`, a parameter row's `FileVersion`, the DDB envelope version
and the calibration file format version are separate values. None substitutes
for the CUW software build.

```python
from scripts.native_modules import identify_native_module

identity = identify_native_module(module_report["sha256"], module_report["name"])
build = identity.cuw_build
exports = identity.callable_exports
```

This operation reads no file and performs no I/O. Use the digest obtained by
statically inspecting the original bytes. Unknown digests, modified originals,
renamed modules and mismatched names fail. Recognition identifies the source;
it does not certify implementation coverage or authorize programming.

The registry records the supplied CUW12 and CUW18 corpus: **55 and 79 modules**,
respectively, with **55 shared names and 24 additions**. These are 134 corpus
entries and 133 unique byte identities. `TCUWParameterForBCB.dll` is byte
identical in both builds (`2088b7066c749eab0bf60278afaf15fdf2acc65e7e033f07121bbba524e0a7e4`).
For that shared helper, `cuw_build` is `None` and `cuw_builds` is `("12", "18")`.
A caller must not guess a build from this helper. Operation modules have distinct
original identities. `family` is the canonical module stem; `callable_exports`
contains code exports, excluding exported data symbols.

## What comparison establishes

Whole-file differences include import-name hints, export timestamps, resource
versions and relocated addresses. These are recorded separately from operation
behavior. The comparison parses PE directories and relocation records; it does
not erase arbitrary constants or treat decompiler text similarity as proof.

Five shared modules have identical code and runtime data after accounting only
for parsed relocation/import metadata:

- `TCUWCRC.dll`
- `TCUWCommunicationAddress.dll`
- `TCUWException.dll`
- `TCUWParameterForBCB.dll`
- `TCUWParameterForVC.dll`

Even in this group, resource versions remain separate: `TCUWException.dll`
changes `FileVersion` from `1.0.0006.0` to `1.0.0018.0`. The original lexical
dependency-version checks must still be applied.

Sixteen further shared modules have equal readonly/runtime data and narrowly
bounded instruction differences: native context field offsets, CPU record
strides and equivalent register expressions. They are MMC CID/prepare/write,
Solar write, eight P4/P5 flash writers, CentralGW prepare and three P5 powertrain
prepare variants. The host implementations use explicit typed context values,
so they do not read either native layout. This establishes no automatic
compatibility for changed imported helpers.

The other 34 shared modules require function and caller analysis. Complete
static CUW12 function output and matching CUW18 function output or instruction
proof were retained for every shared pair. Static analysis does not observe a
vehicle, adapter, vendor DLL execution or timing on hardware.

## Behavior that differs

| Native operation | CUW12 | CUW18 |
| --- | --- | --- |
| Diagnostic pending response | Uses 5000 ms when the saved timeout is below 5000 ms | Takes the replacement timeout from an additional argument; the condition remains below 5000 ms |
| Unified request-download response | Expects `74 20` and a two-byte maximum block length | Reads the encoded length width, bounds the result and rejects block lengths below three |
| Unified P5 helper calls | Supplies constant `180` in the server-maximum argument | Supplies the selected calibration's `GetP4ServerMaxTime` value |
| Unified prepare | Earlier session/gateway sequence | Adds emissions, gateway classification, P5 CentralGW and automatic ignition-off control paths |
| Unified CID getter | Reads software IDs with the original filter/addressing lifecycle | Adds compatibility, auxiliary identity, charge-bus and FCM paths |
| P4/P5 CID getters | Earlier software-ID paths | Adds assembly, slave, serial or CBest reads at family-specific call sites |
| Powertrain finish (excluding Solar) | Supplies no response ID to the common finish operation | Selects whether to await a finish response |
| M16C, VFOREST and non-Solar powertrain error cleanup | Clears count/percentage without the newer progress notifications | Uses common cleanup with count and percentage callbacks |
| Clearance Sonar finish | Supplies no response ID | Supplies the response ID and awaits the native acknowledgement |
| P4 powertrain security helper | Fixed four-byte native ID prefix | Uses the supplied native ID prefix length |
| Recovery preparation | Earlier callback sequence; failed retry always sets connection error kind | Adds driver-data/ignition-off callbacks and an optional error-kind policy |
| Recovery reconnect | Uses CAN protocol 6 | Adds Ethernet reconnect using protocol `0x800f` |

The diagnostic helper's new argument is an ABI change. Callers that explicitly
pass 5000 preserve the earlier pending-response timeout; a changed signature
alone is not a wire behavior difference. Likewise, the P4 security helper's
layout change produces the same request for the verified four-byte prefix.

Both Unified prepare builds conditionally suppress software-ID read failures
using the supplied native caller flag. Recovery confirmation re-reads the current
ignition-off retry setting after the confirmation setting; it must not reuse a
cached earlier parameter value.

The common error cleanup's instruction order is: clear count, callback slot 10,
clear percentage, callback slot 11. Both notifications are part of the CUW18
operation; neither should be invented for the corresponding CUW12 catch path.

Solar retains finish-response handling and both error progress notifications in
both builds. Its shared host implementation must not inherit the non-Solar
powertrain differences.

The 24 CUW18 additions include HINO, SBR, Ethernet, ReproStd, security M16C and
security VFOREST modules. No matching original module is present in CUW12.
A CUW18 module must not acquire a CUW12 identity from its filename or a parameter
row. Protected 2026 identities use the separate reconstruction provenance below.

The separate North America caller inventory contains four CUW12 and seven
CUW18 applications/integration DLLs. `Cuw_iQ_EMPS.exe` is byte identical between
the supplied builds. `Cuw.exe`, TIS access and EuroServer access differ; RKS
access, its wrapper and completion notification are CUW18 additions. Their
application and remote-service behavior is separate from plug-in recognition.

## Recovered 2026 provenance

The registry also recognizes 132 protected originals and their 132 reconstructed
inspection images. Each original is joined to its exact companion digest and
recovered engine digest. `cuw_build` is `"2026"`; `artifact_form` distinguishes
`"protected-original"` from `"reconstructed-inspection"`. `engine_sha256` and
`companion_sha256` retain that provenance. These images are static inspection
artifacts; recognition makes no assertion that they can execute or that an
operation matches CUW18.

The unprotected `CalculationHmacAPI.dll` is separately recognized by its exact
original SHA-256 `e1e6cc8a531e8a3f3c899e3f11a48d4e0556e0903bc15cb944ef289c2f79eeef`.
Its sole callable export is `MakeSendKeyCGWHmac` at RVA `0x1010`. Its build is
`"2026"` and `artifact_form` is `"original"`; no companion or recovered image is
invented. The original has no resource directory and therefore no native
`FileVersion`. This is a source-ported dependency, not a programming entry point.
Across all registered forms there are 398 unique hashes.

The recovered set shares 73 names with the CUW18 plug-in corpus and contains
59 additional names, including application/support modules. Thirteen shared
modules change their export surface. Phase6, SIL, DH, DCMPRL, Suzuki and FHI
operations require their own reachable-flow analysis and host implementations.
No recovered module has been established equivalent by whole-file or normalized
section hashing. Four unsplit files in the supplied directory are outside this
132-pair reconstruction inventory. They are the HMAC dependency above, managed
`Newtonsoft.Json.dll` (no native exports), and the Windows runtime dependencies
`msvcp140.dll` / `vcruntime140.dll`. The runtime libraries are not CUW operation
modules and their names do not authorize a programming dispatch. Their original
static export surfaces remain separate audit obligations; registry recognition
does not claim a port of the Windows runtime.

## Provenance and verification

The module registry contains only hashes, names, build membership, artifact provenance and public
export names. It contains no native payload, decompiled implementation,
calibration image or security material. Source section digests, exact changed
instruction records, full static function comparisons and conservative paths
from code exports to imports are retained separately in the private audit.

A direct static path does not prove an indirect callback, exception handler or
runtime branch was exercised. Exception cleanup was checked against its retained
handler code and common cleanup instructions. Tests of host code use authored
inputs and explicit I/O providers. Physical operation remains
`PHYSICAL_UNCONFIRMED`.

Run the public identity checks with:

```sh
python -m unittest discover -s tests -p test_native_modules.py -v
```
