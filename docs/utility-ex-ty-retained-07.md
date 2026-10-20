# Native retained TY RES, GS, LDR and PCM

`scripts.utility_ex_ty_retained_07` supplies `supported_exports(sha)` and
`run_body(export, args, context)` to the existing TY aggregate. It admits exactly
45 assigned source/export pairs: nine operations in the 12 image and eighteen in
each of the 18 and Plus images. The original immutable module bytes must hash to
the selected identity. No DLL is loaded or executed.

The caller supplies one mutable native-layout `bytearray`. Its identity is
preserved, including partial outputs on native failures. RES and GS use the
selected classic controller and its support snapshots. RES SIL saves the native
protocol and target globals in the original output offsets, temporarily selects
the SIL object, and restores the globals after finalization. Its keepalive loop
observes the mutable stop DWORD. GS actuator polling preserves the native 25-second
comparison and always releases an actuator once polling has begun. LDR09 retains
its initialized extended-session controller between start and completion calls;
LDR10–12 preserve per-target support checks, variable output slots, routine polling,
verification and normal-session cleanup. PCM reads the native capability and eight
big-endian calibration values and updates the native double output fields. Plus
retains its explicit float32 quotient conversion. PCM capability=true arithmetic
requires `context.state["host:x87_control_word"]` and, for Plus,
`context.state["host:mxcsr"]`. These are primitive host environment inputs, not
inferred image constants. Missing or reserved precision state fails explicitly. Unmasked inexact
exceptions are unavailable rather than converted into a successful numeric result.
The calculation rounds each x87/SSE operation at the supplied precision and
rounding mode using standard-library rational arithmetic; it does not depend on
Python's process FPU mode.

The common UtilityEx engine owns wrapper mode admission, worker scheduling and the
10-second wrapper deadline. RES/GS require mode 4, LDR mode 20, and PCM mode 21.
The business provider adds cooperative host cancellation and rejects transmit or
receive indexes outside the original fixed allocation rather than reproducing
an unsafe native buffer overrun. Communication primitives retain native status
codes; there is no callback capable of declaring an entire business operation
successful.

Authored tests exercise literal requests and replies, support descriptor counts,
mutable outputs, native error codes, invalid buffers, source identity mismatch,
cancellation, retained LDR lifecycle and SIL restoration. Run:

```sh
python -m unittest discover -s tests -p test_utility_ex_ty_retained_07.py -v
```

Private evidence under `analysis/evidence/no-car-126` binds every assignment to
its exact wrapper, callback and cached C/ASM hashes. The static byte check verifies
15,141 cached instruction lines against the three authenticated original images.
Private originals and decompilation are not public fixtures.

Acceptance remains open until independent full branch review and the concrete
selected/lower-controller composition checks pass. Primitive-injected unit tests
are not proof that those lower layers are complete. The original process/worker control-word producer still requires source/host
qualification. An authored instruction-level x87 oracle verifies all twelve
precision/rounding combinations against the portable arithmetic, including the
7/7 halfway counterexample; no original code is executed. Physical adapter and vehicle behavior is unconfirmed.
