# Actual CUW2026 M16C and VFOREST programming

`scripts.programming_2026_m16c` implements the selected writer chronology of
`TCUWCanM16CFlashWriter.dll`, `TCUWCanSecurityM16CFlashWriter.dll`,
`TCUWCanSecurityVFORESTFlashWriter.dll` and `TCUWP4CanVFORESTFlashWriter.dll`.
The first module also exports `PrepareRetry`. These four actual2026 modules have
five callable exports; no family-specific getter or prepare-writer export is
invented. Shared getter/preparation dispatch belongs to the importer.

`bind_native_context` accepts an authenticated actual2026 module identity and
`NativeParameterBinding2026`, the imported CUW, observed CIDs and explicit native
runtime state. The image, parent CPU, selected target passwords, addresses,
geometry and security fields come from the actual2026 metadata and catalog.
The binding is reproduced against the original catalog bytes and retains verified
native CPUType mutations. CPU counts, parent lookup and transitions use the global
CPU array across nodes; each selected parameter binding retains its node/local mapping.
The shared native
ControlCommPhase producer builds each CPU group from that CPU's exact parameter
row, selector and LocationID. M16C consumes its parent's physical and functional
records. Parent endian selection uses the parent's exact parameter file. Recovery
skips unused password/CID/endian work while retaining the catalog dependencies
needed for native address production. VFOREST alternate CPU
selection loads its own exact file after the firmware comparison fails.
Authorized nonce/key attachments must agree with any imported values.

`run_native_context(context, runtime)` performs raw typed J2534 I/O using
`NativeRuntime2026`; it composes directly with `J2534Device2026.primitive`.
Optional `progress_observer(field, cpu_index, value)` and
`writing_observer(value)` are application callbacks, separate from J2534 I/O.
Callbacks are checked against the shared cancellation/deadline before and after
execution. They must return `None`.

M16C password and page writes retain native two-message batches. A partial batch
fails without resending an uncertain subset. Each block is erased, then each
256-byte page is written and verified before the next page. Status polling keeps
the distinct A4/A8 responses, busy values and error masks. `PrepareRetry` permits
four A4 probes, three A8 probes and three zero-filled dummy pages. SecurityM16C
retains its actual2026 post-write wait and falsification check. VFOREST retains
record boundaries, 1024-byte fragments, write/verify status values and the
security-only falsification check. P4 VFOREST retry extracts its password from
the archive; SecurityVFOREST honors the native explicit new-password field.

Only acquired filters are released. M16C write restores the prior receive timeout;
VFOREST and `PrepareRetry` preserve their distinct native timeout behavior.
Native operation failures clear progress, compensate an active writing observer,
attempt every owned cleanup and propagate the original error. Numeric native phase and raw
driver errors remain distinguishable. Base CPassThru faults have no driver status;
only explicit CJ2534 faults provide it. Ordinary provider Python errors remain
host failures and retain the original exception, without an invented native return.
Native catch-all outcomes apply only to explicitly native exceptions. A host fault
at finish retains the progress and flag assignments already executed. Earlier
fault cleanup explicitly resets count/percent observers to zero; this host cleanup
does not invent a native terminal result. Each fault carries a frozen `NativeWriterState2026` with redacted native result,
error domains, retry decision and output-flag assignments. `None` denotes an
unchanged native output or a host-only failure without a native assignment.
Native finish exceptions are suppressed by the original engine; their state keeps
the original successful return and finish flag while the host still raises the
failure. Cleanup-only faults likewise preserve the native operation outcome
without claiming host success. `native_state.report()` and successful
`native_result` provide a JSON-safe view. Successful results contain metadata provenance and counts,
not firmware or authorization bytes. Context representations omit those values.

The focused check is:

```sh
python -m unittest discover -s tests -p test_programming_2026_m16c.py -v
```

Fixtures are authored synthetic CUW/catalog/wire data. Tests cover all four
complete writers through the actual J2534 implementation, native batch writes,
recovery, retry-password distinctions, alternate files, malformed inputs,
cancellation and cleanup. Source/exception/status review and all-family importer dispatch integration
remain separate acceptance gates. Native memory-unsafe input cases
fail closed at host bounds. Vehicle compatibility is `PHYSICAL_UNCONFIRMED`.
