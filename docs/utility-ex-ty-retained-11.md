# Retained TY HNFCM, ADS, DSEAT, ITS, DR and ASECT

The provider implements exactly the 50 assigned `(source_sha256, export)` pairs in `analysis/evidence/no-car-130/assigned-source-pairs.json`. It admits 8 original12, 21 original18 and 21 GTSPlus pairs. It does not replace the existing TY97 core exports or infer exports from similar names.

`run_body(export, args, context)` verifies the selected immutable image identity before executing authored Python business logic. `supported_exports(sha)` is the exact admission surface. Native wrapper mode guards, 32-bit return values and the 10,000 ms scheduler contract belong to the selected UtilityEx engine83. The wrappers and actual97 provider aggregation are joined.

The native communication manager remains the I/O boundary. These bodies use the shared selected P3 controller and the separate fixed UDS managers; they do not invoke original DLL code. Parameter blocks remain caller-owned mutable bytearrays. HNFCM camera reads accept the ordinary native bytearray and write the 27-byte output inline at `0x368..0x382`. Extended-session helpers first request normal session `1001`, stop on its failure, then request extended session `1003`.

HNFCM implements three support snapshots, descriptor mask and count projection, camera output copying, target-specific write masks, the 10-second settling delay, status/result reads, and the native cleanup-result precedence. DSEAT keeps its manager/session after successful start and consumes it on polling completion or cancellation. Original18 and GTSPlus have different polling routine identifiers. DR copies the first result immediately and preserves it if the second read fails. ITS keeps its native status mappings and reply predicates.

ADS implements read/modify/write calibration, retained routines, mutable polling stop flags, all three capability gates, 16 flag outputs, payload length and readback comparison, and the two source-bound security keys. The security helper uses the installed OpenSSL AES block primitive through `ctypes`: the original CryptoAPI helper imports a 128-bit AES key, selects ECB, and encrypts one unpadded 16-byte seed block. Keys are read only from the authenticated user-supplied image, never included in this module or evidence outputs. The AES primitive has a NIST known-answer test.

ASECT implements all native actions, phase transitions, retained intermediate returns, the one-time restart branches, NRC remapping, cancellation, normal-session restoration and finalization. Operation-local HOST exception objects survive secondary cleanup failures; unrelated exceptions being handled by the caller cannot hide a sole cleanup failure. Invalid memory spans are rejected at the host boundary.

## Evidence and verification

- `analysis/evidence/no-car-130/reviewed-wrapper-packet.json`: 50 exact wrapper/body bindings, native guards, arity and scheduler contracts.
- `analysis/evidence/no-car-130/exact-pair-packet.json`: original-image wrapper/callback instruction-byte proof. Callback addresses come from actual ASM `PUSH`, including callbacks absent from C call expressions.
- `analysis/evidence/no-car-130/business-source-byte-proof.json`: 230 reachable bounded business/security functions, 11,595 instructions and 37,554 bytes verified against the original images. Shared lower calls are explicitly boundary edges.
- `runtime/no-car-130/verify_source.py`: runnable static provenance verification.
- `tests/test_utility_ex_ty_retained_11.py`: 31 checks including literal wire/output, malformed inputs, native status, HOST identity, cancellation, retention, nonzero security seed, actual97 dispatch for all 50 pairs, and actual83 public scheduler dispatch for all 50 pairs.

G1 checks pass. G2 remains open until the concrete selected/fixed native communication lifecycle from108/132 is composed and checked. The current all50 consumer tests use authored communication replies and do not prove that lower layer. G3 requires independent full source/branch review. No original executable code, Wine, JVM, device, vehicle or licensed network service was run. Physical behavior remains `PHYSICAL_UNCONFIRMED`.
