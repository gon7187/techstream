# Selected signal LSB observations

`SignalLSB` implements the original Common12/18 `InitLSB` and
`ChangeSignalLSB` coefficient adjustment over a concrete `MonitorSupportCache`.
Importing it opens no transport. Supply the selected profile, explicit original
`source_build=12` or `18`, and chronological support transaction/stream primitives.
The DDB version does not select a Common build.

`p4` and `p5` accept a selected logical PID, precision exponent, bit width and the
three current DWORD values. They return an immutable `LSBObservation` with named
`multiplier`, `divisor`, `threshold`, `changed` fields and a `.values` tuple.
P4 requires the exact category byte `4`; P5 requires `0x14`/`0x15` in12 and also
`0x34` in18. The first selected DB227/DB240 row supplies query identifiers and bit
ranges. Missing optional resources and native discovery/communication failures
preserve the input coefficients; cancellation, exhausted budgets/deadlines and
changed source identities propagate as failures.

P4 discovers supported PIDs and byte masks, checks the selected range, replaces
byte1 of the selected function`0x6B` request, expands the compressed reply using
the cached byte flags, and extracts the observed factor. P5 discovers DIDs,
evaluates native selected signal support and replaces bytes1/2 of selected
function`0xCA`. The concrete cache preserves actual selected communication/timer
records and the per-ECU request cache. No application callback supplies the LSB
factor or a success flag.

Each producer owns a source-bound native TEMP cache. Reusing a producer reuses its
TEMP observations; a fresh producer starts a fresh TEMP cache. The shared global
P5 support map and Ever responses remain shared. Metadata callers that construct
a fresh native LSB object for each row must likewise construct a fresh producer.
Both paths bind their native instance cache with constructor-default
NoInit/NoSession flags and restore the caller's TEMP scope and flags afterward.

Both originals contain literal floating-point base`10.0`; the multiplier is the
low DWORD of `trunc(pow(10, precision)) * observed * row.DWORD0`, reduced with the
row.DWORD4 divisor using the original signed remainder algorithm. The threshold
is `(1 << (width & 31)) - 1`, including x86 shift-count wrapping. Signed division
faults fail explicitly instead of crashing the host. Invalid bit ranges do not
produce an observation. The host rejects unsafe malformed resource/reply bounds.

Normal monitor metadata overwrites the threshold after this native call. Freeze
metadata retains the changed threshold. Consumers must retain their own caller's
ordering and verify the producer belongs to the selected source and ECU.

Source identities: Common12 SHA256
`d2542b8bf82347080ed73f84285a8d14d0c592fb9713abfc50448725b414a126`, Common18
`07547a9e47378d37c3ef7d96c2f33f6c62c4151626d98d3f3ff03b7c74909de7`.
P4 core addresses are12`0x10019c50` /18`0x1001f120`; P5 cores are
12`0x1001a540` /18`0x1001f9b0`. Build18 adds the raw`0x34` P5 gate and the
Subaru DID discovery dispatch, absent in12. Private source assembly remains in the
local evidence tree; tests contain authored DDB resources and wire responses.

The selected12/18 source and arithmetic received parent and independent53 review.
The native-instance TEMP correction is covered by19 authored selected-resource
tests, including actual25 consumer integration and two same-DID PIDs with reused
and fresh producers in both builds. Independent re-review of this correction is
pending. Broader25/52/87 consumer and shared-support closure remains separate and
open. Physical ECU behavior remains `PHYSICAL_UNCONFIRMED`.

Check: `python -m unittest discover -s tests -p test_signal_lsb.py -v`.
