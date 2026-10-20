# Selected active-test replay

`scripts.active_replay.ActiveReplay` runs the selected native active-test List,
Init and phase algorithms against a chronological application-PDU recording.
It opens no adapter. Results retain `PHYSICAL_UNCONFIRMED`; an acknowledged
command or successful release is not reported as a mechanical test pass.

```python
from scripts.active_replay import ActiveReplay

replay = ActiveReplay.load(recording_path, selected_profile)
try:
    tests = replay.available_tests()
    initialization = replay.initialize(signal_id, family=selected_family)
    report = replay.run_test(signal_id, {
        "value": 5,
        "auxiliary": 0,
        "display_index": None,
        "input_hex": "",
        "button_index": None,
    }, family=selected_family)
    replay.write_report(new_report_path)
finally:
    replay.close()
```

`initialize()` exposes the actual selected limits, units, controls, display
choices, routine inputs/buttons, status patterns and initial/current-value
availability. It adds `input_byte_count` from nonzero selected output-mask bytes
and `button_byte_count` from the selected button-mask length. `argument_fields`
identifies supported scalar, byte, button, auxiliary and scalar output-mask
arguments from the actual selected family, version and data-ID mode. List and Init are
cached: rendering a dialog twice does not repeat captured support or initial
read exchanges. `display_index` selects an enabled scalar display's native press
value; `button_index` selects an existing routine button's byte data. Values,
indices and input lengths are validated before start.
Scalar `value` is a signed 32-bit native `long`, from -2147483648 through
2147483647, compared against signed Init limits. The wire assembler receives its
unchanged low 32 bits after validation. Integer display choices use the same
contract. Routine byte arguments replace the scalar assembly branch, so an
unused scalar placeholder is not checked against those limits. This portable
API contract does not reproduce Win32 scrollbar comparison quirks or infer
signedness from physical conversion metadata.

## Recording contract

The JSON document has `schema`, `context`, `native`, and `events`, with optional
`driver_events` for actual lower driver primitives.
The schema is `techstream-active-workflow-v1`. Duplicate fields, unknown fields,
malformed hexadecimal data, out-of-range native integers and files exceeding
16 MiB are rejected. `native` follows [native exchange replay](native-replay.md);
its support object must be empty because this workflow owns the support context.
Transactions are consumed in order, including native errors and receive-only
continuations. A mismatch does not consume the expected transaction.

Context fields are all explicit:

| Fields | Meaning |
|---|---|
| `ecu`, `family`, `init_family`, `protocol`, `bus_id`, `driver` | Captured native caller/connection context; legacy List variants without their own Init export require the observed Init family. |
| `version`, `category`, `management_sha256`, `ecu_sha256` | Exact selected profile identity. A different profile fails before exchange. |
| `pid_lengths`, `did_lengths` | Observed lengths keyed by lowercase two/four-digit hexadecimal identifiers. |
| `enabled_dids`, `enabled_rids`, `pid_support` | Explicit observed identifier lists. Presence of a DDB definition does not establish availability. |
| `bit_ranges` | Objects containing `pid`, `start`, `end`, `supported`; a required missing observation fails. |
| `positions` | Actual legacy support-position byte lists keyed by two-digit hexadecimal PID. |
| `routine_info` | Observed native driver boolean controlling the normal RID payload prefix: false uses offset4, true uses offset5. Required for Routine status events; it is not inferred from the protocol. |

`family` supports `p3`, `dk`, `p4`, `old_body`, `sa`, `p5`, `routine`, and `psa`.
`init_family` identifies a recovered `p3`, `dk`, `p4`, `p5` or `routine` Init
export. `driver` identifies `j2534`, `dk_iso9141`, `dk_kwp`, `fuel`, `psa`, `p5`, or
`dual`, and must match the selected native phase. The observed bus selects the first actual versioned ProtInfo row;
bus identifiers are compared without truncating to their low byte.
Bus zero is rejected: the native P4 loader treats it as an absent connection;
requiring a nonzero captured connected bus for other phases is conservative
host validation.

Events describe recorded worker ticks, not arbitrary command bytes. Each event
has `action` (`start`, `step`, `status`, `stop`) and uint32 `tick`. Exactly one
start is first and one stop is last. Stop additionally requires boolean
`initialize`. The PDU stream independently proves every resulting exchange.
Queue numeric states, repeat deadlines, replies and remaining exchanges appear
in the report. `status` reads the selected current-value signal or routine D7
status. Normal Routine status uses separate selected normal/abnormal lists:
size2 compares a big-endian WORD; other nonzero sizes compare the first byte to
the selected WORD's low byte. Unmatched status remains unmatched. Reports retain
normal, abnormal and native stop-pattern matches separately.

For KWP/Fuel stop with `initialize: true`, the recording must include the actual
NULL send followed by receive-without-buffer. `driver_events` records these
primitives separately from diagnostic PDUs: a NULL request is JSON `null`,
distinct from an empty hexadecimal request. Each event includes `operation`,
`after_exchange` (the exact consumed PDU count), `ecu`, `timeout`, and `status`.
Send adds `request`, `protocol` (observed bus ID), and `initialize`; receive adds
`buffer`, `maximum`, `argument_5`, `flags`, `data`, and `source_id`. Arguments must
match the native call exactly. Timeouts come from selected A7 communication
settings, with native key1/default1000ms send/200ms receive fallback. Native
ignores both initialization status codes; the report retains them and still
executes the receive after a failed send. Unconsumed driver evidence fails the
workflow. Reports contain deep snapshots of both PDU lifecycle and driver
observations.

## Native associations

| Path | Recovered association |
|---|---|
| Legacy P3/P4/DK/OldBody/SA | Selected ActTest92 and Pattern24 drive the native instruction interpreter. Phase3 D340 passes signal WORD32, value DWORD36 and auxiliary byte40 from the caller structure, then the generated payload after its first byte to the selected DataListIF driver. |
| Ordinary driver | CCommEventAT 216D0 prefixes `30`; 21910 copies the complete queue PDU. 21950 validates the native reply and sets done/wait/advance states. 21850 queues the actual one-byte release; it does not infer a reverse value. |
| DK ISO9141 | CCommEventDkIso9141AT 5F30/6130 builds and validates its own service. Driver stop7620 terminates its local worker without inventing a release PDU. |
| PSA | Selected optional DB23C override joins ActTest WORD56 to its first CommMode row. The native PSA queue mutates repeat/control and derives its own stop payload. |
| Ordinary P5 | ActTestP5 DB244 DID WORD52 selects DataIdForAct DB243 WORD2. First selected function9D/64 templates and the selected pattern enter `active_arguments_p5`; `P5ActiveQueue` owns send/repeat/release state. |
| Special P5 context | In version18, when native protocol high bits equal20, D5FA..D769 derives payload length from the maximum selected same-DID action end bit. Other contexts, including version12, require actual observed DID length. This calculation does not establish availability. |
| Routine | Versioned Routine DB247 and resolved command/output/button variables enter `routine_arguments_p5` with first selected D5/D6 templates. D7 supplies initial support/status probes. |
| Normal RID status | Phase5 7F20 builds the descriptor from selected Routine signal/RID/spec/status-group fields and the first selected button group's press length. Engine1C50/2FB0 and normal/abnormal consumers retain the native status-list semantics. Special signals9C42/9C46 expand to their selected child pairs in both versions; version18 also expands9C49. |

Phase5 D599/DE10/E35E/E5AB and RoutineInit2260 consume the first selected
frame. The separate initial-value CA/6B readers preserve their stricter native
single-frame requirement and failure fallback. These are different native
contracts. [Active metadata](active-tests.md) and
[Toyota session](toyota-session.md) document the shared codecs.
Version12 uses its actual ProtInfo, PatDisp and Routine widths; the proven common
legacy/Routine packers preserve the same wire layout. Version12 rejects the
version18 scalar output-mask override. Combined P5/Routine lists can
contain the same signal ID in both families; those selections require an explicit
`family`. Reports identify the actual chosen DDB frame-template provenance.

The SA list finalizer requires `sa_library=` pointing to a locally supplied,
SHA-verified original library. Reading data does not load or execute the DLL.
Missing material fails before its seed exchange. Operands and derived key
requests are excluded from session traces and reports; the source library is
never copied into examples or exports.

## Cancellation, cleanup and examples

Cancellation is checked before and after I/O. Cleanup has a fresh bounded
budget and bypasses cancellation to consume the actual captured release.
Failed cleanup remains visible and retains ownership for retry. Concurrent
`close()` requests cancellation, serializes against the active owner, and
performs recorded cleanup. Reports use exclusive creation, so existing source,
symlink, hardlink and previous-report destinations cannot be overwritten.

`create_active_examples() -> dict[str, bytes]` produces authored synthetic demo
resources plus P3, P4, DK, OldBody, SA, PSA, P5 and Routine recordings. Write its
relative paths into a new directory, select `Techstream_DB_NA` and category1.
Legacy examples use signal1/value5, P5 signal2/value5, Routine signal3/value5;
PSA uses signal1/value0. The SA example still requires a local verified key
provider. The factory imports production demo code, never test fixtures.
`create_signed_active_examples()` additionally supplies signed [-5,5] profiles
and `active-p3-negative.json`, `active-p5-negative.json`, and
`active-routine-negative.json`, which execute scalar -1 using exact captured low
bytes. It regenerates every affected selected-profile hash and manifest entry.

Verification: `python -m unittest discover -s tests -p test_active_replay.py -v`.
The tests cover selected metadata-to-wire execution, real probes, repeat timing,
faults, cancellation, cleanup races, strict parsing and source preservation.

`selected_routine_monitors(profile, signal_id)` exposes the recovered selected
normal RID producer independently of a replay. It returns one or two immutable
`RoutineMonitor` descriptors; the caller supplies an already selected Routine
ID and retains responsibility for mixed PID/active/Routine list dispatch.
Missing D7 templates, child rows or required button groups fail explicitly.

Physical behavior remains unconfirmed. These recordings verify selected native
software behavior and captured replies, and cannot establish actuator movement.
