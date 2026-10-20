# Native Plus FCHV action workers

`scripts.utility_ex_fchv_plus` implements the four literal supplied Plus exports
`Ex2FCHV_24_SendMessage`, `Ex2FCHV_25_SendMessage`,
`Ex2FCHV_27_SendMessage` and `Ex2FCHV_28_SendMessage` for SHA-256
`821bbfd9957679ceef4ac32c239b8840c984e98ac61050ce7348ac2bc88b04ce`.
The 18 image and family-name aliases are rejected. Both the TY aggregator and
this provider independently verify the supplied immutable image bytes.

`run_body(export, args, context)` preserves one caller-owned `bytearray`. Native
minimum sizes are respectively `0x38c`, `0x38c`, `0x24` and `0xb8`, with the shared
64 KiB bound. This is the native DWORD/byte layout, not a serialized operation
or a host callback that declares the business operation successful.

The original four wrappers accept only broker modes 20 and 21, launch the
source-specific worker through the native scheduler with a 10,000 ms timeout,
and publish the worker's status without normalization. The common UtilityEx
engine owns that wrapper and scheduling contract. The provider owns each body,
its selected diagnostic calls and its mutable UI publication flags.

| Worker | Concrete behavior |
|---|---|
| 24 | Twenty 44-byte diagnostic rows; support bitmap and secondary tank support; masked valve activation; routine 0x1119 pressure drive and 0x1116 activation; five-state advance; prioritized normal and timed data publication; cancel/error and return-to-session helpers. |
| 25 | Independent support length and action-3 branch; action 3 directly starts routine 0x1119 and sets state 4, while action 2 retains the bitmap handshake; remaining shared source helpers retain their literal behavior. |
| 27 | Support masks and current valve snapshot; enable/disable handshake over four odd bytes; two signed pressure preconditions from the exact three-record descriptor table; two distinct recurring monitor selections; native stop/status publication and session-retention rules. |
| 28 | Three 56-byte caller descriptors; support mask checks, signed start precondition, handshake and initial three-row read; recurring read and stop; explicit release, deferred disable, and fallback enable action. |

All communication uses the exact Plus global manager `native:101392d0` and the
concrete shared communication engine. Wire helpers construct individual `22`,
`2f` and `31` requests; they verify native length and echo fields and preserve
raw driver status and NRC-specific mappings. Manager configuration uses the
three source setters. Successful intermediate actions keep the existing manager
and extended session where the native code does. Terminal paths finalize once. All normal-session sites in these four workers map
to Plus `130f0`: they stop keepalive even when the session reply fails.

Native polling uses the recovered start latch, unsigned DWORD timing with the
native extra tick subtraction at wrap, literal 200 ms polling and the 5,000 ms
boundaries. The activation helper uses strict `> 5000`; the other bounded
handshakes use `>= 5000`. Long-lived data producers stop through their mutable
native stop fields, through host cancellation, or through the common scheduler.
Direct native sleeps use `context.native_sleep`, preserving one primitive call
and its full duration; explicit host cancellation checks surround that call.
No artificial iteration limit substitutes for source timing.

FCHV27 reloads the mutable action after its initial initialization predicate.
Its control helper snapshots masks for activation and polling, while its separate
release helper reloads the live caller masks. FCHV28 captures masks before any
initialization callbacks and uses that entry snapshot for activation, polling and
normal-error release. These boundaries preserve concurrent caller mutation.

Host cancellation and exceptions attempt to stop routines and valve outputs retained across successful
messages, restore the caller's saved valve mask, restore the normal session
and finalize. Safety output state lives in the engine context across all four workers.
Activation is tracked before its primitive; only confirmed stops clear it.
Canceled entry to a later message releases previous outputs without clearing
the global cancellation flag. Cleanup uses the explicit bounded
`cleanup_exchange`/`cleanup_session` primitives, attempts every release and
finalization even after secondary `BaseException`s, and attaches those errors to
the original exception. A host fault in normal restoration or finalization also
triggers this release; successful native normal-return traces are unchanged. Native
status returns keep their source-specific cleanup and retention semantics;
notably the FCHV28 initial sample error returns `0x3ff` while retaining its
manager, and FCHV27 action 5 returns zero even when its no-wait write fails.

Unused FCHV28 support indices are ignored unless the row DID second byte is
`0x9b`, matching the source dereference guard. Used native descriptor offsets,
indices and bitmap expansions are bounded
before Python memory access. The original unsafe out-of-bounds behavior is not
reproduced. Localized resources, secret material and decompiled bodies are not
embedded in this module or this document.

Run the reproducible checks:

```sh
python -m unittest discover -s tests -p test_utility_ex_fchv_plus.py -v
python runtime/no-car-117/source_check.py
ruff check scripts/utility_ex_fchv_plus.py tests/test_utility_ex_fchv_plus.py runtime/no-car-117/source_check.py
pyright scripts/utility_ex_fchv_plus.py tests/test_utility_ex_fchv_plus.py runtime/no-car-117/source_check.py
```

The private source checker compares retained C/ASM hashes and every instruction
byte against the exact supplied PE using static reads. The literal tests exercise
all four workers, native error/malformed/timeout/stop/cancellation and lifecycle
branches, and the current real TY aggregator dispatch with the supplied image.
These checks establish authored offline producer behavior. They do not by
themselves close G2/G3, prove the outer scheduler or actual transport end to end,
or demonstrate vehicle behavior. OEM PE execution, licensed network/auth and
physical hardware were not used.
