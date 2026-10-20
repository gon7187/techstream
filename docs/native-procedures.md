# Imported native procedures over recorded evidence

`open_utility(path, key_library=None)` reads the original four-byte envelope and
UTF16 XML, or SRP AES data using an explicitly supplied SHA-verified original
library. It never loads the vendor DLL or exposes its key.

`replay_utility(profile, resource_path, recording_path, *, function_id, dialog,
cancelled, key_library=None, record_files=None, translation_file=None)` runs the
selected XML function. `replay_script(profile, resource_path, recording_path, *,
cancelled, record_files=None)` executes the original CSDF object with the same
strict recording boundary. Neither function opens an adapter. Valid executions
produce JSON reports; malformed inputs/context fail before execution. Provider,
transport, dialog and VM failures produce failed reports with remaining events;
native status and partial response bytes are retained. Native errors are never
reported as successful measurements.

`create_example_files(directory)` writes authored XML/CSDF and their recordings
for normal application use. It returns paths under `utility`, `utility_recording`,
`script`, `script_recording`. The XML function is `demo`: changing radio `INT02`
to `2` enables key `1`, then the recording consumes initialize, PDU and finalize
in that exact order. Existing differing files are never overwritten.

## Recording schema

The exact top-level fields are `schema: "techstream-native-procedure-v1"`,
`source: "authored_synthetic" | "recorded_unverified"`, explicit `ecu`, `context`,
and chronological `events`. The context has exactly these fields:

- `broker`: canonical decimal string keys to uint32 values, or explicit `null`
  for CSDF. XML requires the broker keys validated by `UtilityBindings.from_profile`;
  ECU identity, addressing and transport selectors are never inferred from names.
- `script_ecu_id`: explicit u8 value for CSDF GetECUID; unused XML may retain null.
- `support`: null, or `{selected: [protocol,key1,key2], records: [...]}`. Each record
  contains `key: [kind,key1,protocol,key2]`, 256 `offsets`, hexadecimal `support`
  and `received` buffers. Missing cache observations are never manufactured.
- `initial_variables`: explicit native-ID map for CSDF, for example
  `{"32768": {"tag": 3, "payload": ""}}`. Native IDs begin at `0x8000`.
  An explicit empty map is allowed; no variables are automatically filled.
- `did_ranges`: null or explicit inclusive `[first,last]` observation pairs.
- `language`: `{locale: "XX" | null, missing: "preserve" | "error"}` selects the
  actual XML LANGUAGE map; no locale is guessed.
- `limits`: positive bounded `seconds`, `steps`, `exchanges`.

A PDU event is `{kind: "pdu", transaction: ..., options: null}`. Its transaction
is an unchanged NativeReplay row: ECU/request/response hex, or ECU/request,
nonzero native `status` and `partial_response`. An empty request is receive-only.
All PDU rows are structurally validated once by NativeReplay, then an outer index
enforces their chronological order among driver events. No unrelated event is
skipped to make a replay work.

A driver event is `{kind: "driver", operation, arguments, result}`. Operations:

| Operation | Exact arguments | Result |
|---|---|---|
| initialize | `[decimal_broker_snapshot, refresh_bool]` | uint32 native code |
| finalize | `[]` | uint32 native code |
| configure | `[name, uint32_value]` | null |
| keepalive | `[bool]` | null |
| abort | `[]` | null |

Every callback consumes a matching event and exact arguments. There are no
no-op initialization, finalization, configuration or abort callbacks.

CSDF PDU events require `options` with exact `retry_count`, `address_type`,
`plural`, `sequence_code`, `response_count`. Plural replies continue through the
following explicitly recorded empty-request PDU events. Sequence failures retain
the controller code and make the overall report partial even if the script
handles the failure and exits. Native transport errors remain typed exceptions.

## Dialog, localization and files

The dialog uses `UtilityRuntime.screen()`. It returns a key string,
`{key: ..., values: ...}`, `{display: values}` for native DISPACTION without a
keypress, or `{elapsed_ms: ...}` for progress. Screens expose current radio
`value`, `progress_elapsed_ms`, and monotonically increasing `block_instance`;
reentering the same block resets its progress with a new instance. Ended screens
have no instance. The procedure adds `deadline_monotonic` and `remaining_ms`.
The dialog provider must honor this deadline and the caller's cancellation
signal; the GTK bridge does so. Checks run before/after dialog callbacks. Python
callbacks are not put into abandoned daemon threads to pretend to enforce timeouts.

LANG tokens resolve only through the selected resource language. External IDS
keys are explicit unresolved translations unless the caller supplies a catalogue.
`load_translations(path)` accepts exact JSON fields `schema:
"techstream-utility-translations-v1"`, `source: "authored_synthetic" |
"recorded_unverified"`, explicit `locale`, and `translations: {"IDS_...": "text"}`.
Duplicate keys, malformed strings and excess sizes are rejected. Translation
files join the report's guarded source paths. These are provided texts, not
invented translations. The same `translation_file` accepts an original
`U_*.ddb`: kind6 section1 has 164-byte rows containing two UTF16 key fields
(80 bytes each) and a string ID at160; section0 supplies the actual text.
The native K1 lookup selects the first matching primary key. No locale is
inferred from a filename; the explicitly selected original file supplies text.
IT3UtilityTY2 `0x3F706` resolves the RSD symbol, `0x3F71A` invokes
GetUtilityString_K1, and GetUtilityString_DT `0x10E5` requests type `0x601`.
UtilityDB `0x3EB6` reads the row's string ID at `0xA0`. These mappings resolve
original common and procedure labels without substituting unrelated DDB indexes.
Both native language sections are capped at100000 rows, and aggregate decoded
section bytes at16 MiB, before constructing the language string list. These are
local resource limits. Resolving a complete screen has one16 MiB UTF8 text budget
and100000 node/token limit; each literal/replacement is counted before appending
or joining, including across separate fields. A deadline check follows resolution
before the host dialog is entered.

`read_utility_symbols(path)` parses the original UtilityResID_NK.rsd format:
u32 group, u32 resource identifier, u16 UTF16 byte length, name bytes. Native
IT3UtilityTY2 RVA `0x3EFD0` proves this layout; `0x3EF30` selects common group20000
and a utility group. Symbol IDs are **not** direct indexes into an arbitrary
language DDB. The U-language symbol table provides the native localized-text
bridge; missing symbols or an omitted translation file stay partial.

`record_files` maps explicit logical byte names to explicitly attached local
paths. Native RMLib names never become arbitrary filesystem paths. Source paths
include the resource, recording, selected profile databases, optional key library,
attachments and translation catalogue. Reads use the shared pinned regular-file
reader, rejecting FIFOs/devices without blocking. Files and aggregate attached
inputs are bounded at 16 MiB while reading, events at100000, with total exchange, VM-step and
wall-clock bounds. XML utility workers are cooperatively stopped and joined;
recorded abort and native cleanup events remain mandatory, with a bounded five
second cleanup window. A cleanup failure cannot leave a successful report.
`input_sources` records the byte length and SHA256 of each immutable input used
by the parser; resources are never reread or restatted to generate provenance.
`profile_sources` retains the already parsed profile database hashes. Replacing
a file after it is read cannot change the reported hash of executed bytes.
KeyboardInterrupt during execution becomes a cancelled report. Cleanup attempts
the bounded worker join even when abort is interrupted, retaining the original
execution error and separately reporting cleanup errors.
Native worker `BaseExceptionGroup` failures are captured with structured child
errors (at most100 nodes and8 levels), including interrupt plus release failures;
they cannot replace a previously recorded primary execution error.

The original-resource corpus uses explicitly authored contexts and replies. It
establishes production helper integration, not vehicle behavior or an inferred
native caller initialization policy. Private evidence is under
`analysis/evidence/no-car-19`; physical status is always `PHYSICAL_UNCONFIRMED`.
