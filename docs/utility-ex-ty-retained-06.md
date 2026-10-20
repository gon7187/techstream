# TY retained FC, HAL, MGR and IC

The provider owns exactly 45 assigned `(source_sha256, export)` pairs: 16 TY18,
13 TY12 and 16 TYPlus. No DS4 body, MGR12 alias or TY core97 export is enabled.
The common UtilityEx engine owns exported mode guards, worker scheduling and
result globals. This provider consumes the same original mutable native buffer
and context and calls individual selected/fixed communication primitives.

FC04 preserves packed support descriptors, physical response offsets, target
7D1/7C4 selection, native 30/21 frames, ten alternating confirmation requests,
120-second status retry and 300-second heater budget. Mutable keepalive DWORD
+60 stops the loop. Stop requests retain the business status.

FC05 uses distinct TY12 26-row/1E8-byte and modern 44-row/309-byte layouts.
Immutable support and threshold tables are read statically from the SHA-checked
caller supplied original PE. Support discovery writes individual native fields,
builds the inclusive polling index, chooses control type 10/11, and checks required
rows. The polling worker decodes bit and multibyte values, runs inclusive native
threshold comparisons after activation, renews valve control every 3000ms or on
mode change, observes the mutable stop DWORD and sends the final 30 request.

HAL preserves support response and DTC filtering, nested DTC priority, height
selection 1..5 mapping 8/6/4/2/1, failed-command DTC fallback, 1500ms wait and
synchronization 12000ms wait. Cached C loses several success paths; paired ASM is
authoritative for native 70/04 and 7B/01 echoes.

MGR01 enters normal then extended session, executes 31011112 and lets restoration
failure override the business result. MGR02 preserves four-byte write/compare
and NRC 6B mapping. MGR03 preserves variable payload write/compare/read, output
zeroing, native counts and caller-owned retention beyond the written region.

IC reads DB70..79 into ten 10-byte records and DD00 into bytes 100..103. Successful
normal records return 1001; any literal flagged condition returns 0. The18 and12
callbacks are 81C80/66FC0, established by wrapper PUSH instructions and recovered
static objdump, despite erroneous C string classification. This is static source
reconstruction, not evidence of OEM runtime execution.

Validation: `python -m unittest discover -s tests -p test_utility_ex_ty_retained_06.py -v`;
`PYTHONPATH=. python runtime/no-car-125/verify_source_packet.py`;
Ruff and Pyright over owned Python files. The source packet independently checks
all 45 wrappers and callback ASM instructions against the exact original PE bytes.
Original modules are only read and remain private and unchanged.
The additional `check_public_consumer.py` runs all 45 real public wrappers through
the actual83 context/worker/status and97 dispatcher into this body. An authored
individual lower initialize fault37 checks status and literal buffer retention;
it is not a concrete communication completion claim. Nineteen body checks and
73 core97 consumer checks pass.

G2 remains open until actual selected and fixed TY communication lowers execute
the complete facade composition. G3 requires independent branch review and that
same concrete producer/consumer join. Authored trace controllers prove body
behavior only; they do not establish device/car or OEM execution success.
