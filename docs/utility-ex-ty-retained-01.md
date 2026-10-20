# Retained TY PSABSI, RWG and EVP

`utility_ex_ty_retained_01.supported_exports(sha256)` admits exactly the 41
assigned pairs: TY12 has 15 PSABSI and three RWG, TY18 additionally has EVP,
and TYPlus has three RWG and EVP. Every entry requires its own selected source
identity; no other source, core97 export, or name-only fallback is admitted.
`run_body(export, args, context)` accepts native mutable buffers and runs inside
the shared scheduler. The wrapper owns its 10000ms scheduling contract.

The selected manager owns initialize/finalize, target selection, native setters,
individual transactions and A8 support snapshots. This leaf owns the business
branches, packet construction/validation, descriptor35 transfer and bit layout,
request/poll loops, native error mappings, mutable UI/security state and buffer
mutations. It never calls an opaque business callback. Direct source Sleep calls
use `native_sleep`, with cancellation checked before and after the host boundary.

PSABSI requires mode19, RWG/EVP mode4. PSABSI05 KeyRegister consumes the low byte
of the DWORD at native offset0x28, despite its decompiled body having a void
signature. It neither initializes nor finalizes the retained connection.
PSABSI05 UnlockRequest retains on successful unlock and on the already-locked
0x2330 branch; failure inside the initialized business phase closes it.
ExitCommunication releases that selected manager without initializing it.
Native result globals100ab770/10118e38/10134ab8 are published at callback completion;
ProgramADC publishes before finalize, including its initialization failure.
Other bodies close the manager, preserving the source order of configuration,
initialization, target selection and polls.

PSABSI08 WriteVIN preserves the buffer at offsets0x12/0x17, complete response
copies at0x1a/0x103a, native response lengths at0x205c/0x2060, and the mutable
security structure at0x2064. Security stage transitions1/0x1771/0x1772/0x1773,
seed/key words, action5000 and action0x138a remain visible to the host using the
same buffer. There is no fabricated PIN or secret derivation.

ASM is authoritative where the cached C loses control flow. In particular,
18 RWG26ab0 and VIN5c3c0 have successful lower-response branches omitted from C;
RWG26910 contains the real 500ms loop through23/26/27 reads until a sentinel or
10000ms timeout. All three source variants execute that loop. A timeout preserves
1000, and stop30 does not replace the prior business result.

`analysis/evidence/no-car-120/wrapper-body-packet.json` binds each exact wrapper
to C/ASM, mode, arity, scheduler, callback and its business helper closure.
`source-preservation.json` records hashes before and after packet extraction.
`runtime/no-car-120/source_packet.py` rebuilds that private evidence without
writing to the original image or cached source directories.

Validation: `python -m unittest discover -s tests -p test_utility_ex_ty_retained_01.py -v`.
The authored packet tests cover all41 pairs and exercise the actual97 aggregator
with original source bytes for identity validation, plus all41 actual83 public
invoke/thread/status joins with identical packet chronology and mutable outputs. Only static reading of those
images occurs. These tests replace the manager with individual transaction
fixtures; they do not establish a concrete lower transport or physical hardware.

G2/G3 remain open pending complete independent source-branch review and actual108/132 lower/lifecycle composition. No OEM module, Wine,
J2534 device, vehicle or licensed network has been executed or contacted.
