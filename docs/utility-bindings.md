# Native utility callback bindings

`scripts.utility_bindings.UtilityBindings` is a `UtilityRuntime.library` callable.
It implements the eighteen recovered UtilityExNeoNK/IT3UtilityNeoNK callbacks
against an explicitly selected `ToyotaSession`, support cache and transport/UI
providers. Importing or constructing it performs no I/O. No vendor DLL is loaded.

For production selection use the recovered native factory:

```python
bindings = UtilityBindings.from_profile(
    selected_profile,
    selected_session,
    broker=selected_broker_snapshot,
    initialize=transport.initialize_utility,
    finalize=transport.finalize_utility,
    configure=transport.configure_utility,
    keepalive=transport.keepalive,
    support=observed_support_cache,
    abort=transport.abort,
)
runtime = UtilityRuntime(resource, library=bindings)
```

The broker snapshot requires literal native keys `74`, `AB`, `6F`, `70`, `73`
(hexadecimal): addresses, transport selector pair, ECU ID. These are selected
runtime inputs; a model label cannot supply missing protocol observations.
The exact selector-pair allowlist comes from UtilityEx RVA `0xa490`; P5 extended
session availability follows `0xcd60`. `initialize(snapshot, refresh_bool)` and
`finalize()` return actual driver statuses. `configure(name, value)` changes the
selected backend's utility settings. `keepalive(enabled)` controls its real
periodic-message lifecycle. Providers must implement the selected transport's
bounded operations; absent providers are errors, never default success.

Native Init/Final initialize/finalize the communication driver; they are not
diagnostic request frames. Native workers generate their own request templates.
The factory implements those recovered templates and response predicates, and
records their native RVA, selected ECU database SHA and category in each new
`CommandSpec`. It does not invent universal DDB function IDs. If an actual
selected DDB frame has identical request bytes, its real provenance is appended
as `matching_selected_ddb`; unmatched templates retain native provenance.
The returned binding owns a new `.session` with a complete command trace and a
`.provenance` profile/broker snapshot. The original session is left unchanged.

P5 start sends the native base session then extended session requests;
each needs a two-byte reply and matching second byte (native errors 3 and 7).
End sends the base session request and stops keepalive when requested, including
when its exchange fails. Mode change requires the native six-byte reply and
retains the original current-mode cache. ECU IDs `0x1f2` and `0x1ae` select the
proven alternate native worker templates. No decoder turns a missing vehicle
dependency into a valid-looking wire operation.

The lower-level constructor below remains available for explicitly selected
operation descriptors and authored replay providers:

```python
bindings = UtilityBindings(
    session,
    operations={
        "initialize_0": "selected-initialize-without-reset",
        "initialize_1": "selected-initialize-with-reset",
        "finalize": "selected-finalize",
        "mode_1": "selected-mode-one",
        "mode_3": "selected-mode-three",
        "start_extended_0": "selected-start-false",
        "start_extended_1": "selected-start-true",
        "end_extended_0": "selected-end-false",
        "end_extended_1": "selected-end-true",
        "thread_0": "selected-poll-zero",
        "thread_1": "selected-poll-one",
        "thread_2": "selected-poll-two",
        "thread_3": "selected-single-send",
    },
    ecu_id=selected_ecu_id,
    protocol=selected_protocol,
    support=selected_support_cache,
    configure=transport.configure_utility,
    abort=transport.abort,
)
runtime = UtilityRuntime(resource, library=bindings)
# A real UI button action latches one consumable native progress event:
bindings.press_progress()
```

Operation values name existing session descriptors, or tuples naming an explicit
sequence. Thread operations require exactly one descriptor with the full request
header; use raw reply checking and zero payload offset so the recovered worker
can inspect the original response. Select request variants from evidence for the
selected ECU. Bindings never infer a service ID or discover an adapter. Missing
operations, cache, ECU metadata or configuration providers fail explicitly.

The owner must serialize other direct uses of the same session with these
bindings. Inside one binding, synchronous operations and background workers have
exclusive transport ownership; concurrent attempts return busy status 15. The
exchange provider must impose its own blocking-I/O timeout. Python cannot kill an
unbounded exchange safely. Cooperative cancellation, deadline checks before and
after I/O, exchange budgets and bounded waits constrain all host operations.

| Native callback | Arguments and observable result | Native RVA |
| --- | --- | --- |
| ChangeSessionMode | One integer; low byte must be 1 or 3; selected operation status, or 3 for a successful reply shorter than six bytes | UtilityEx 0xe3d0 |
| SetNrLimitTime | One DWORD forwarded to the configuration provider | UtilityEx 0xe590 |
| SetResponseNoCheck | One integer; configuration flag is true exactly when the argument equals 1 | UtilityEx 0xe860 |
| SetUseReqMode30_3BFuncFlag | One integer; nonzero configuration flag | UtilityEx 0xff80 |
| ChkA8SptInfoForBitWrap | 5..8 integers; final argument receives native support lookup result; callback returns 0 | UtilityEx 0xf720 |
| GetSptTableDataPosRecvData | 5..8 integers; last two receive lookup-found and selected receive byte; callback returns 0 | UtilityEx 0xfb90 |
| InitialCom | One in/out integer; nonzero selects initialize_1; operation status replaces argument; callback returns 0 | UtilityEx 0xfde0 |
| FinalCom | One output integer receives selected finalize status; callback returns 0 | UtilityEx 0xfe30 |
| SleepThread | One integer, milliseconds; bounded and cancellable wait | UtilityEx 0x100b0 |
| StartExtendedSessionP5 | One nonzero/zero selector; selected operation status; missing session returns 99 | UtilityEx 0x101a0 |
| EndExtendedSessionP5 | One nonzero/zero selector; selected operation status; missing session returns 99 | UtilityEx 0x102a0 |
| StartComThread | One index 0..3; 15 while running; index 3 waits for completion | UtilityEx 0x103a0 |
| StopComThread | One integer; always requests cooperative stop, nonzero additionally invokes transport abort | UtilityEx 0x10430 |
| GetThreadStatus | No arguments; running 15 or final status; completed host failures propagate | UtilityEx 0x10510 |
| GetThreadRecvData | Offset and output integer; zero-based byte from the full terminal reply | UtilityEx 0x10520 |
| GetEcuId | One output integer receives selected ECU ID | IT3Utility 0x14a0 |
| GetComProtocol | One output integer receives selected protocol low byte | IT3Utility 0x14e0 |
| GetProgButton | No arguments; consumes the latched UI flag, returning 0 or 1 | IT3Utility 0x1560 |

Integer descriptors are native tag 1, whose pointer at +4 refers to a DWORD.
These eighteen wrappers do not accept byte-buffer tag 4 as an integer. Wrong
arity/type returns native 99 before I/O, except the IT3 GetEcuId/GetComProtocol
getters whose native invalid-descriptor result is -1. Literal numeric arguments have mutable
temporary storage whose writes are discarded. Existing `INTxx` arguments mutate
the runtime's candidate storage; runtime atomically validates the complete result
and then assigns CALLFUNC `OUT`, including when `OUT` aliases a by-reference arg.

## Support cache

`SupportCache(records, selected=(protocol, key1, key2))` uses keys
`(record_kind, key1, protocol, key2)`. Each `SupportRecord` owns 256 native offsets,
observed support bytes and received bytes. Offset `0x1020` is the native absent
sentinel. The buffers have the native maximum capacity `0x1020` bytes. No cache
entry is a fabricated ECU support observation.

`ChkA8SptInfoForBitWrap` takes `(support_id, one_based_position, mask, record_kind,
[protocol, key1, key2], output_result)`. The support ID is reduced to its low byte.
The native table has length at offset+1. Lookup checks the selected bitmap byte
for nonzero and all mask bits. Native results are 0 supported, 22 unsupported,
83 invalid context, 84 absent cache record and 99 malformed bounds.

`GetSptTableDataPosRecvData` takes `(support_id, received_position, record_kind,
[protocol, key1, key2], output_found, output_byte)`. A matching record returns
found=1 and receive byte at `offsets[support_id & 255] + received_position`.
Missing/invalid context returns found=0, byte=0. Host bounds checking rejects
reads outside observed buffers instead of reproducing native unchecked memory
access. Omitted context selectors default to zero. Protocol zero requires both
keys zero and resolves to the selected context; nonzero protocol requires key1,
and protocol 8 requires key2 while other protocols require key2 zero.

## Background worker lifecycle

The recovered index table selects workers at RVAs 0x4200, 0x4440, 0x4660 and
0x4010. Indices 0..2 poll every 200 ms until reply[4] differs from 1, preserving
the full terminal reply for `GetThreadRecvData`. Replies require five bytes and
reply[1:4] equal to the selected request header; short/mismatched replies produce
status 3. Each worker releases the selected extended session after polling.
Index 3 sends once and waits synchronously; a matching reply of at least four
bytes succeeds without release, while a failed/short/mismatched reply releases
and produces status 111 when release succeeds. No synthetic permanently idle
thread or constant-success callback is used.

Host exceptions trigger release with a fresh bounded budget even if cancelled;
worker and release failures are both retained. Original workers 1/2 discard some
release statuses; this host surfaces failed release as an exception so a possibly
live session is visible. Other intentional host policies are rejecting unchecked
native buffer reads and returning busy for competing configuration/I/O calls.
These deviations are explicit safety behavior, not native equivalence claims.

## Evidence and verification

Contracts were recovered by static inspection of the privately retained original
18.x UtilityExNeoNK and IT3UtilityNeoNK PE artifacts, including the wrapper RVAs
above and support helpers 0xd790, 0xdc40 and 0xa9c0. The private evidence index is
`analysis/evidence/no-car-10/contract-evidence.json`; original disassembly and
artifacts remain ignored. No OEM binary or decrypted script is a public fixture.

Run `python -m unittest tests.test_utility_bindings`. Authored vectors cover all
eighteen callbacks, native errors, missing dependencies, literal/by-reference
arguments, actual XML callback integration, masks, contexts, buffer bounds,
poll repetition, busy races, cooperative stop, abort, deadline and cancellation.
Static recovery plus fake transport tests prove software behavior only.
Transport timing and actual ECU behavior remain `PHYSICAL_UNCONFIRMED` until an
adapter and vehicle are available. Calling a missing provider is a software
configuration error and cannot be reported as a successful vehicle operation.
