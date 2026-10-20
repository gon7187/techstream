# CUW2026 P5 powertrain preparation

The five exact `StartPrepareWrite` exports are allocated to
`programming_2026_p5_prepare.py`; none aliases a CUW12/18 implementation:

- `TCUWP4P5CanPowerTrainPrepareWriter.dll`, RVA2060.
- `TCUWP5CanPowerTrainPrepareWriter.dll`, RVA22c0.
- `TCUWP5CanPowerTrainPrepareWriterForBodyMicon.dll`, RVA2120.
- `TCUWP5CanPowerTrainPrepareWriterForSolar.dll`, RVA22f0.
- `TCUWP5CanSecurityPowerTrainPrepareWriter.dll`, RVA21b0.

Private `analysis/evidence/no-car-86/source-bindings.json` binds original module,
reconstructed engine, decompiler text and complete assembly hashes. Native
keys, resources and proprietary source remain private. The public tests contain
only authored metadata, passwords and wire observations.

`bind_native_context` joins actual2026 calibration metadata, the selected
`NativeParameterBinding2026` and `communication_addresses_from_parameter`.
Only the native controller retry flag964 is accepted as an observation.
Source-validated SetCPUType state is retained through the actual31 binding;
classic preparation takes per-CPU parameters while its DLL still comes from CPU0. The
runner requires an owned `NativeRuntime2026`; import never opens a device.
The native cores take two bytes from each seven-byte communication record and
pad to four bytes, including the Security variant. Extension bytes are ignored
by these cores; the shared typed provider does not reinterpret that behavior.

The four P5 cores install all filters, probe `10 02` at each address and retain
only responders. Timeout status9/16 maps55; an exact three-byte negative maps56
(BodyMicon's native catch checks SID27, the others SID10). No responder is error41
unless controller retry964 is already set. Each retained address executes
`27 01`/`27 02`, then one diagnostic mask is sent and `31 01 10 03` runs at each
retained address with10ms between addresses. BodyMicon uses the shared six-byte
seed conversion. It unconditionally sets ECU block size1 before installing
filters, including the empty-address case, and restores block size0 before
releasing filters. Native restore faults preserve the stored Boolean while host
ownership remains failed and retryable. Powertrain and Solar use four ordered native conversion rounds
with four selected two-byte SecurityKey entries. Security uses the global
calibration authorization projections and the shared two-step SecretInfo crypto
primitive; NRC35 on its key response maps1002. No primitive returns business
success or decides whether a preparation completed.

P4P5's native flow acquires all filters and uses address0 for P5 and address1
for P4 (the source arrays are offset by the native0x408 CBytes stride). It runs
the P5 probe/key flow and a separate P4 seed/key flow, preserving the independent
retry skip branches. The P4 seed/key timeout maps22. Only its retained seed response
three-byte SID27 negative maps23; a key negative after a positive seed remains17. Its selected waits run before/after the P4 key. Unless both
paths skipped, it sends the mask, the P5 routine and10ms wait when applicable,
then the P4 common `ChangeMode(0)` when applicable.

Solar assigns its notification Boolean true before the routine. A later native
fault selects result status2 and sets retry964 when that notification is true;
otherwise status1. Solar's native cleanup catch continuation still reaches
these delayed status/retry assignments after a native filter cleanup fault. Powertrain and BodyMicon alone apply their exported
`IGOffRetriableFlag` plus notification968 Boolean return override. Their report
can therefore contain `native_return=True` with `prepared=False`.
`native_return` reports the recovered native Boolean, separately from host
cancellation, deadlines, malformed primitives, missing authorization and cleanup
failure, which propagate exceptions. Unknown native business exceptions also
propagate, except the P5 address-probe catch-all that maps them to9999.
The native cleanup catch-all preserves its already-stored Boolean after a
native StopFilter exception. The report preserves that `native_return`, sets
`host_result=cleanup_failed` and `host_succeeded=False`, and retains failed
ownership for explicit cleanup retry. Host cleanup attempts every acquired
filter; this is stricter than native cleanup, which leaves its loop on failure.
A host cleanup exception still propagates. No physical programming completion is claimed.

```sh
python -m unittest discover -s tests -p test_programming_2026_p5_prepare.py -v
```

The suite exercises all five exports through actual typed
`J2534Device2026.primitive`, authored selected CUW and parameter sources,
wire bytes, native and host fault/cancel at every primitive position, pending
responses, multiple addresses, ignored extension bytes, retry flags and cleanup
retry. Synthetic SecretInfo test issuance is explicitly scoped to the tests;
production uses authenticated PE authorization. A separate private-corpus test
checks that actual authorization path. A further private integration composes
`NativeSecurityComposer2026` callbacks21/22 with typed J2534 and selected CUW
metadata, checking the real AES-derived key on the wire and seed/key/routine
faults. Private corpus tests skip when their files are unavailable.

Independent full source review and production consumer composition remain
**OPEN** until their owners verify the current hashes. Hardware behavior remains
`PHYSICAL_UNCONFIRMED`.
