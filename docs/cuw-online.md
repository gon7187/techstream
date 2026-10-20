# CUW online key controller

`scripts/cuw_online.py` ports the CUW2026 `41080 → 53010 / 537b0 /
54e10` controller and `415b0 / 41600 / 41640` modal callbacks. It does not
load a DLL, contact a service or manufacture an authorization result. Existing
12/18 service contracts remain separate; a2026 implementation is not their fallback.

The controller accepts an issued `EngineWorker2026`, encoded source `RKS.ini`,
and an `OnlineReplay2026` primitive chronology. The worker supplies actual engine
VIN, configured region, current file format and the all-loaded-file selector.
`4a6f0` scans loaded files, so a Daihatsu file can select its license while a
different file is current. The Subaru test reads current FILE data+20 (format9),
not Vehicle.KindOfECU at+b8; format9/Kind1 and format10/Kind9 are checked separately. Daihatsu takes precedence over Subaru FORMAT9; region2
selects Suzuki only after those checks. Region2 uses seed8/key64, otherwise
seed16/key256. The keypair selector follows region2 independently of license.

`start(seed)` fills the exact160-byte inline request at controller+251. The
wrapper reads offsets0,3,38,53,100,118,120,127. A short VIN is right padded to17
bytes, and absent VIN sets modal6. `SoftwareID` has35 bytes including terminator
in this structure: Ethernet's fixed32-byte native-memory read has a separate source-owned
adapter and cannot be substituted. Host bounds reject overflowing fields instead of reproducing unsafe
native writes. Each import commits only when all eleven strings are present and nonempty,
matching `55490`; failure preserves the previous store, including its known
zero-initialized state before any successful import.

Browser mode1 retains `3a190`'s captured `HKLM\SOFTWARE\Microsoft\Internet Explorer`
open/read/close primitives and `svcVersion` decimal-prefix check (>10). No
registry write occurs. Browser calls use the existing `RKSAccess2026` implementation and the existing
service replay browser/clock primitives. Native watcher11 repeats;12 ends the
watcher and maps to modal10;13 maps to modal9;0 maps to modal4. A successful
browser approval does **not** supply a signature. Only the recorded native
`SetReprogrammingKey@4` input, or imported signature XML through wrapper64,
sets controller result1 and issues `OnlineKey2026`. The native raw-input path
checks512 hex characters, or128 for region2. XML import retains the managed
512-character contract before native decoding and the region-specific copy.

`query_string(captured_utc_datetime, filetime_remainder)` implements53c30,
including its selective27460 URL encoding and four residual FILETIME digits.
Mode2 consumes a recorded `shell.open` primitive result; it never opens a URL.
`request_parameters()` implements `StartRequestReprogrammingKey` mode3's33+7
byte result and modal5. `export_data(directory, captured_local_datetime)` preserves
`VIN_YYYYMMDDhhmmss.xml`, exports through wrapper5c and sets modal4. Its cleanup
removes only the previously exported path owned by this controller. This host
ownership restriction deliberately avoids deleting unrelated existing XML files.
`request_status` applies `643d0`'s native status mapping. Closing the controller
closes its owned browser and clears retained native key bytes. Returned immutable
key bytes remain the caller's responsibility.

## Worker replacement

`rebind_worker(old, new)` follows the engine's stopped-child `5f030 → 59070`
replacement transaction. It accepts only the closed previous issued worker and
the current open replacement from the same engine, runtime, controller and
retained FILE vectors. It changes only the worker capability. The engine-global
online object, request, native key bytes, browser accessor, RKS singleton, modal
state and unused replay binding retain their identity and contents. The hook
also accepts the reverse transaction after the engine restores its previous
worker; it never validates a closed previous worker as current.

The engine transaction includes a runtime-retained unused online controller even
before native global438 has been published. Replacing a worker neither consumes
its capture nor accounts elapsed time. A later native callback consumes the same
capture and advances the outer clock once.

## Offline capture

A capture has schema `techstream-online-controller-replay-v1`, provenance
`authored` or `captured`, exact engine SHA256, configuration/source/seed SHA256,
and ordered `steps`. Each step has `method`, `args`, `result`, `fault`, and
`elapsed_ms`. Digests bind the input; they do not authenticate a capture author.
Keep private source configuration, signature XML and key inputs outside public
artifacts. Reports must contain only digests and state transitions.

Controller operations have empty `args` and consume the recorded input from
`result`:

- `online.request`: object containing URL and explicit allowed origins, followed
  by the existing `browser.*` primitives.
- `online.watch`: null, followed by an owned browser snapshot.
- `online.start_query`: object with base URL, ISO UTC time and FILETIME remainder,
  followed by `shell.open` with the fully composed URL and native integer result.
  Native ShellExecute results<=32 set modal8, larger results set modal5.
- `online.SetReprogrammingKey`: lowercase hex encoding of the captured ASCII
  key-input bytes; never a Boolean success result.
- `online.LoadXMLFileForReprogrammingKey`: lowercase hex encoding of captured
  signature XML bytes.
- `online.request_parameters`: expected native40-byte output, hex encoded.
- `online.cancel`: null; native active browser2/3 returns through41640, otherwise
  native result3 terminates the controller.
- `online.finish`: null, followed by any required owned `browser.close` cleanup.

Only one capture can be consumed. A host deadline, cancellation, captured elapsed
time and cleanup all remain enforced. `calculate(..., timeout=, clock=,
cancelled=)` accepts the outer runtime budget; `consumed_elapsed_seconds` allows
the outer programming replay to account for this nested chronology exactly once.
Host faults propagate rather than being converted into native success. A capture
mismatch during swallowed native cleanup still invalidates the entire run.

`python -m unittest tests.test_cuw_online` covers authored vectors. These are
software checks, not proof of licensed-service acceptance or physical vehicle
programming. Static source hashes and private integration evidence are in
`analysis/evidence/no-car-113/` and `runtime/no-car-113/`.

## Repeated native RKS imports

One engine owns one `NativeRKSConfiguration2026`, representing54f50's singleton.
`engine.load_rks_configuration(bytes)` routes through that same store. The
store's `load()` returns nativeFalse on parsed INI errors, missing fields
or empty required fields. Such attempts leave every native field and the retained
SoftwareID memory span unchanged. Before the first successful import, the exact
zero-initialized native SSO objects remain available; this is source-derived
initialization, not a fabricated credential. Type/aggregate-size violations remain
host errors. Decoded NUL bytes delimit the5c7d0 C string. DataFile's input
terminator makes an odd final encoded pair calculable; an earlier decoded NUL
allows safe prefix parsing. An odd decoded allocation without a terminator would
read unknown heap bytes and is rejected as a host failure, preserving prior state.

A valid55490 import updates the nine other fields, but writes SoftwareID and
SoftwareVersion only while their native strings are empty. Thus loading A with
`SoftwareID=ABC`, then B with `SoftwareID=XYZ`, keeps ABC for both the online
request and Ethernet fingerprint while adopting B's license/keypair fields.
Closing an online controller does not reset this shared RKS store.

The online controller consumes the engine store, including when its optional
encoded-file argument is supplied. The normal27 factory preloads that argument
before phase entry. Configuration is refreshed at41080 request creation, so an
import between controller construction and `start()` takes effect. A capture
bound before that change is rejected before input consumption.

`source_sha256` identifies the latest successful input file; `last_source_sha256`
identifies the latest completed native import attempt. A HOST failure is never
cached as completed, so identical unsafe input must fail again on retry. The replay configuration binding also
includes the effective retained fields when they differ from the latest file.
Consequently a recording made after A→B cannot silently run on a fresh B
singleton with different SoftwareID/Version. The retained typed Ethernet identity
continues to identify the original string-producing import.

The source-known SSO32 span and a heap string with at least31 bytes remain
supported. A31-byte heap ID supplies31 bytes plus its terminator. Heap spans
containing uninitialized bytes are rejected as host policy, including after a
reload that would otherwise appear to replace them. No unknown heap contents
are padded or invented.

`runtime/no-car-113/verify_rks_reload_factory.py` runs five authored scenarios on
the actual normal47→27→114→60→48 factory. Its observer only reads the native
request at the real key-input entry. Four cases verify the independent literal
Ethernet fingerprint and native256-byte key at the transport boundary, with the
125 ms capture counted once. The fifth verifies unknown16-byte heap memory is
rejected before any fingerprint is sent. Run with `PYTHONPATH=.` from the repo.
The report is `analysis/evidence/no-car-113/repeated-rks-normal-factory.json`.
