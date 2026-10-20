# CUW2026 retained HINO and SBR

`programming_2026_vendor` implements the three retained CAN HINO variants and
SBR through injected communication primitives. It never loads a vendor DLL or
opens a device. Results retain `PHYSICAL_UNCONFIRMED`.

`bind_native_context` requires an exact registered 2026 module identity, the
actual 2026 parameter binding, imported calibration metadata and resolved native
addresses. `run_native` repeats that binding before I/O. Changed payloads,
download geometry, source hashes, parameter rows and targets fail validation.
Archive overrides are rejected. Ordinary HINO writing requires the actual shared
`native_pending_timeout_ms` returned by preparation; the initial preparation
value is the source literal 5000 and the session response replaces it. Classic
exporters copy the first two bytes of each native address component into a
four-byte CAN header, as their source does.

Supported family exports are `StartGetCID`, `StartPrepareWrite`,
`StartFlashWrite` and the actual DSS/SBR writer `PrepareRetry` exports. HINO DSS
preparation uses the shared recovered HINOUtils implementation. Ordinary HINO
and VCS seed transformations execute locally. VCS retries preserve three
attempts for driver errors 9/16 or returned negative responses. DSS and VCS
getters send the native tester requests before identification. The DSS writer
retains its unusual address/size byte slices; VCS reset sends `11 01`.

SBR implements functional session setup, gateway authorization and routines,
masking, communication control, master/slave selection, seed handling,
programming sessions, erase/download, counter-and-address transfers, exit and
sumcheck. Functional waits, periodic workers, timeouts, filters and progress
callbacks remain explicit. The generic writer producer builds one address vector
per global CPU across nodes using that CPU's parameter row and LocationID, with native NULL CID and
callback inputs and shared read-only address history. Internal SBR CPU iteration
retains its original writer parameter row while advancing the actual CPU files
and address vector. The GUI callback's separate global parameter object does not
replace the writer's private control-module row.

SBR's eighteen callable utility exports have exact identity dispatch through
`bind_sbr_utility` and `execute_sbr_utility`. Cipher/Feistel operations use supplied
private material; no secret table is published. The exported substitution table
is shared by bound utility instances and starts with the source image's 32 zero
bytes. The AES/provider boundary receives the native secret type, actual seed, AES flag and encryption flag, and must return the exact
key width. Gateway authorization must return 256 bytes for the observed
16-byte seed. These providers cannot return diagnostic success.

Native diagnostic and driver failures produce canonical separate error fields,
including base native errors with no driver status. Getter pointer returns use
`native_return=None` and expose the actual output BOOL as `native_success`;
other family exports preserve their direct BOOL return. Host
cancellation, malformed contexts, deadline failures and resource failures remain
explicit exceptions. Filter/periodic cleanup is attempted after failures.
Padded transfers that would read beyond the supplied archive fail rather than
inventing padding bytes.

The focused checks use authored CUW files, actual metadata/parameter/address
producers and the typed J2534 adapter with a synthetic primitive driver:

```sh
python -m unittest discover -s tests -p test_programming_2026_vendor.py -v
```

The 45 current checks cover all eighteen SBR utility exports through the typed
J2534 adapter, HINO variants,
gateway and writer chronology, two CPU targets, altered contexts, malformed
responses, callback12 observations, five-second P4 delays, global cross-node
CPU selection, preserved CPUType state, cancellation and cleanup. Independent source and composition review passed for this scoped implementation;
the hash-bound verdict is `analysis/evidence/no-car-67/vendor-review.json`.
A passing replay is not proof of vehicle compatibility.

The private factory proof `runtime/no-car-61/verify_factory.py` additionally
imports authored CUW and original module identities through the normal engine,
controller and typed J2534 adapter. Its nineteen controls cover all twelve family
modules, both retry exports, base/driver native errors, cancellation, deadline and a native ANSI CID.
The factory binds the actual General parameter parser profile and captured local
clock callbacks. ANSI identifiers retain exact bytes in `identifier_records`.
The ordinary HINO preparation result supplies the writer's negotiated pending
timeout. Hardware behavior remains `PHYSICAL_UNCONFIRMED`.
