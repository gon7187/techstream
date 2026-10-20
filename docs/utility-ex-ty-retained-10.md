# Retained TY VC, PI, DSC, HVB and VIF bodies

This provider is selected by the immutable supplied module SHA-256. It implements
50 of the 51 assigned source/export pairs. Plus D_EFI15 is deliberately
unadvertised until its distinct selected P5 interface is connected. Its business
helper is ported and tested through typed primitive communication, including
protocol3 to1 restoration, raw frames, polling and native result2706.
No OEM DLL is executed, and import opens no device or network connection.

`run_body(export, args, context)` executes native worker business logic; it does not
replace wrapper mode admission, asynchronous scheduling, or immediate return ABI.
The actual `utility_ex_ty` aggregator dispatches to this provider. Wrapper evidence
is supplied separately to the outer `utility_ex` engine owner.

Arguments are the caller's original mutable native bytearray. DSC01 needs 42 bytes,
DSC02 one byte; VC01/VC02 use 12-byte DWORD layouts; VC03/VC04 use 16 bytes; HVB
uses 11 bytes; PI uses its native row area and count at `0x4b8`; VIF02 uses `0x28c`
bytes. PI02 reset has no arguments. Invalid host buffers fail before communication.

The implementation preserves partial output mutations, native result globals, the
HVB retained connection results 1005/1022, and same-manager continuation calls.
Plus HVB mode22 uses its distinct P6 manager, minimum lengths and negative-response
retry logic; its mode20/21 business path remains separately selected. Cancellation
raises the original `Cancelled` object; cleanup attempts cannot replace an active
host or cancellation exception. Absolute PI restores callback-global and target
state even when finalization fails. These exception rules are explicit host policy.

The source decompiler discarded reachable successful branches in several helpers.
Literal assembly restores VC writes, learning completion, security seed inversion,
HVB polling and jump-table results. Native DID checks intentionally do not acquire
an invented positive service-byte check. Native zero-initialized receive buffers
are preserved where the source reads beyond a short returned message.

Private evidence records all 51 exact pairs, all literal callback PUSH operands
(including alternate Plus HVB callbacks), their original image-byte checks, and C
and ASM file hashes. Public tests contain authored protocol messages only.

Validation: `python -m unittest discover -s tests -p test_utility_ex_ty_retained_10.py -v`.
The tests cover literal frames, native layouts, negative responses, malformed
messages, partial writes, retained continuation, cancellation and host exception
identity, and the actual TY aggregator consumer. Source identity in public tests
uses explicitly labelled authored-image substitution; original-image proof lives
in private evidence.

G2 and G3 remain OPEN. Complete no-car acceptance requires the remaining D_EFI15 P5 interface admission, concrete fixed/selected lower lifecycle composition, outer wrapper
checks, and independent complete branch review. Passing authored fake-communication
tests does not establish device, vehicle, or full native equivalence.

SZEIU reuses the independently ported exact Plus `100d1cc0` helper from retained03.
The helper reads the native identity and AES key material only from the verified
supplied image. The two-target timed routine flow uses concrete keepalive methods;
unknown metadata and cryptographic provider failures remain explicit failures.

VC05 preserves the776 support rows,23 read targets,7 or20 mask groups,
three-attempt writes, reset retry and retained two-phase state. VIF01 preserves
its global previous-descriptor mutation and resulting group termination; native
unbounded metadata walks are rejected at host buffer boundaries.
