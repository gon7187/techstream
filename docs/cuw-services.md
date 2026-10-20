# CUW service callers, RKS handoff and completion notice

`scripts.cuw_services` implements the local software in CUWAccessTIS,
CUWAccessEuroServer, CUWAccessRKS, its mixed CLR wrapper and the local
ReproCompletionNotifier. Constructors and imports perform no I/O. This module
never instantiates COM, executes a vendor PE, discovers devices or opens a
network connection. Its tested providers supply synthetic/replayed bytes,
DOM snapshots and local window events.

The licensed TIS/RKS server, account session and server-side key computation are
external dependencies. An unavailable server does not remove the client code.
No seed, credential or request was sent to a real service during verification.
Physical and licensed-service acceptance remain **PHYSICAL_UNCONFIRMED**.

## Service interface

`build_service_request(operation, data, endpoint=...)` creates immutable HTTP/COM
transport input: endpoint, SOAP action, UTF-8 SOAP envelope and native connector
properties. `ServiceClient(transport).run(...)` marshals, exchanges and parses it.
The injected `ServiceTransport.exchange(request, timeout=seconds, cancelled=...)`
returns `ServiceHTTPResponse(status, body, source)`; `close()` releases that
owned transport. It receives bytes and transport metadata, not an opaque
"get a key" business callback. There is no default transport or automatic retry.

| Operation | Structured input | Native SOAP action suffix |
| --- | --- | --- |
| `tis-check` | `TISRequest` | `getHealthCheckResults` |
| `tis-save` | `TISRequest` | `saveEcuProgram` |
| `euro-online` | `EuroRequest` | `OnlineCheck` |
| `euro-save` | `EuroRequest` | `saveEcuProgram` |
| `euro-key` | `ProaceRequest` | `GetKeyForUnlockECUForPSA` |

Action namespace: `http://www.openuri.org/`. The SOAP 1.1 header contains the
native `StartHeader` conversation element with namespace
`http://www.openuri.org/2002/04/soap/conversation/`. Native connector metadata
retains `EndPointURL`, `ProxyServer=<CURRENT_USER>`, `Timeout=30000`, `SoapAction`
and the actual opaque `ConnectTimeout` byte `0x04`. The last value is a native
DOS-header pointer artifact, not a proven numeric timeout. Transport deadlines
are specified separately in seconds, default 30, maximum 600.

The TIS `milInput` preserves DealerCode, VehicleConnectSession, Version, Vin,
Date, Language, Type, SoftwareId, UserType and calibration rows. Type is
`ReprogramCheck-CUW` or `ReprogramResult`. Save adds NewCalibrationId and the
explicit IsFlashSuccess boolean; a server response never invents a flash result.
At most ten calibration entries are admitted. Empty old IDs of types 73/74
remain representable. Version 12 stops at another empty old ID; version 18 skips
that entry and continues. New IDs stop at the first empty value.

`TISRequest.product_version` selects the recovered 12/18 contract. Version 12
uses numeric UserType and its NA/EU lookup table; version 18 requires the literal
UserType string. The standalone `CalibrationID(kind, value)` preserves native
numeric types and text. Unknown numeric lookup values serialize as empty text,
as the native lookup does. Inputs exceeding fixed field extents are rejected,
not silently truncated.

Euro online requests carry SoftwareId. Euro save adds DealerCode, Date, mapped
EU UserType and CalibrationEvent with Vin, Time and paired old/new calibration
entries. PROACE key requests preserve the literal `proace_request` body and
hyphenated `user-language`, `gts-guid`, `request-id`, `repairing-requests`,
`unlock-seed` and `unlock-request` names, with exactly two supplied frame pairs.
Seed and other values are escaped as XML data, never injected as markup.

`parse_service_response(operation, bytes, source=...)` checks the response
operation and namespace and records the source and SHA-256. TIS results preserve
up to 50 MilMessage records with MessageId, Title, MessageContentType and Message.
Euro online/save success requires the exact native strings `OnlineCheck message
OK.` / `Message received OK.`; other messages return native status 50. PROACE
parsing follows `milmessage/repairing-requests/requests/unlocking-content`, reads
return-code children level/value/comment and admits unlocking-value only when
the return code is exactly `000000`. This value comes from the supplied response.
It is never generated locally. SOAP faults return native status 3 and observed
fault data. HTTP failures cannot become successful application replies.

XML is bounded to 1 MiB, 4096 nodes and depth 32. DTD/entity declarations,
malformed text, duplicate required fields, ambiguous SOAP bodies and mismatching
operations fail. Parsing a server response establishes its structure and source,
not cryptographic authenticity or permission to program an ECU.

## Managed RKS and mixed wrapper interface

`RKSAccess` replaces the five wrapper exports with an instance-owned interface:

| Original operation | Python interface |
| --- | --- |
| SetDataForReproKey | `set_data(RKSData(...))` |
| ExportDataForReproKey | `export_data(path)` |
| RequestReproKey | `request(url, allowed_origins=...)` |
| ImportReproKey | `import_key(path)` |
| GetWatchingResult | `watch()` |

`RKSData` contains X-Version, terminal SoftwareID, SoftwareVersion, LicenseKey,
VehicleIdentificationNumber, RequesterKind, KeypairID and SeedValue. `rks_xml`
emits the native ReproKeyRequest/TerminalInfo nesting, UTF-8 declaration,
two-space indentation and CRLF. An explicit `set_data` call is required; stored
fields may be empty, as in the native wrapper. There is no global process-wide
seed cache. Request data cannot change after browser handoff.

Exports create new files with mode 0600 and preserve an existing destination.
A failed write may leave a partial newly created destination for caller inspection;
it never replaces an existing file or reports that partial file as successful.
All BYOD imports use bounded `local_files.read_regular`, rejecting device/FIFO
inputs before opening them as data. The original Signature import contract is
retained: a scalar `Signature` root, exactly 512 ASCII alphanumeric characters.
Errors retain native codes 7 (missing file), 8 (XML/root), 9 (length), 10
(characters). A `ReproKey` carries the supplied value and source/hash; values and
request secrets are hidden from ordinary object representations. Shape checks
cannot authenticate a signature or prove it belongs to a particular ECU/seed.

The `Browser` protocol exposes only owned-window primitives: create_window,
navigate, snapshot, set_value, wait and close. Every operation receives an
explicit remaining timeout and cancellation predicate. `BrowserSnapshot` carries
the owned window identity, current URL, Busy/ReadyState and a bounded tuple of
`DOMElement(tag, name, element_id, value, kind)`.

`request` opens one visible browser window through the supplied provider,
navigates to the explicitly supplied URL, waits for Busy=false/ReadyState=4,
finds the unique `textarea` named `ReproKeyRequest`, sets its value and checks an
exact XML readback. It does not submit the form, type a password or silently
complete authorization. IE protected-mode HWND reattachment becomes a stable,
owned provider window identity; unrelated windows are never enumerated or closed
by the Python client. The provider owns process/browser reattachment.

Requested/current origins must match the explicit allowlist after scheme, host
and port normalization. Userinfo, URL controls, authority percent/backslash
tricks, foreign windows, duplicate textareas and stale approvals fail closed.
Caller-supplied extra origins support a known login redirect without a wildcard.

`watch()` checks the owned DOM input `result_code`: exactly `0` gives native
status 0, null gives 11, missing/other values give 12. The local trust policy also
requires a hidden input and a ready document, rejecting duplicate result inputs.
No key is extracted from that status. Actual Signature import is a separate step.
The caller must close the handoff when finished. Errors/cancellation close only
the owned window; a failed close retains its handle for explicit cleanup retry.
The default handoff deadline is the native five minutes with 100 ms polling;
explicit host limits allow at most 600 seconds/6000 poll iterations.

## Local completion notice

`CompletionNotice(host).run(NoticeConfig(title, message, color1, color2,
interval_ms, sound_mode))` implements the native fullscreen/topmost local
notification using window/render/event primitives. Colors retain Windows
COLORREF BGR integer layout; adapters translate that to their renderer. Native
color2 is drawn first, then color1, alternating at the supplied interval.
Sound mode 0 is the MailBeep alias, mode 1 is 1728 Hz for interval_ms, other
32-bit modes are silent. The interval is explicitly bounded to 1..60000 ms.
The host owns actual font/layout rendering and audio.

Any key, left/right click or close event dismisses. Cursor movement dismisses
when either coordinate differs from the initial cursor by more than 50 pixels;
exactly 50 does not. Foreign-window and unknown events fail. No network, remote
completion service or worker thread is involved. The cooperative loop replaces
the native worker/join lifecycle and closes its owned window on every exit.
A close failure retains the handle for `close()` retry and leaves state uncertain.

Provider calls must honor their timeout/cancellation contracts; Python cannot
preempt an arbitrary blocking callback. Cleanup ignores cancellation but has an
explicit five-second provider budget. One-shot executions never retry ambiguous
requests or claim successful cleanup after an error. GTK/browser/HTTP platform
adapters are separate integrations, not fake successes in this module.

## Static anchors and verification

Native TIS: exports 0x1010/0x10d0; v18 XML builder 0x2150 and message reader
0x2580/0x29e0. TIS v12 UserType table stepping is verified in assembly
0x22fa..0x2315 (8-byte rows); decompiler pointer arithmetic is not authoritative.
Euro v18 PROACE builder 0x3410 and response reader 0x2e90 follow the literal XML
contracts above. Managed RKS methods are tokens 0x06000014..0x0600001a;
wrapper exports are tokens 0x06000004..0x06000008. The notifier entry is 0x1000,
window procedure 0x11d0 and color/audio worker 0x1440.

Tests use authored XML, fake HTTP/COM bytes, browser DOM and window events:
`python -m unittest discover -s tests -p test_cuw_services.py -v`.
They execute positive, malformed, failure, cancellation, deadline, source
preservation and resource-cleanup paths. No OEM resources, executable bytes,
decompiled C, credentials or original key values are part of public fixtures.
