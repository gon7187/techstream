# Source-bound TY MS2 security

`scripts.utility_ex_security.security_access` composes the supplied TY18
`c5e80/c6330/c6440` and Plus `d0e40/d0c90/d0d90` helpers over the selected
communication objects' diagnostic `exchange` and `keepalive` primitives.
The required `preliminary_comm` argument is native argument 8; the positional
`comm` is native argument 7. Preliminary authentication and all failure restoration
use argument 8; the second session pair/capability/authentication use argument 7.
It performs both session pairs, capability DIDs `0240/0250/0251`, preliminary
level 7 security, routine `0200`, and the selected second authentication.
The communication owner retains initialization/finalization ownership.

Only the exact authenticated TY18 and Plus images are admitted. Source-owned
keys and legacy substitution data are read from caller-supplied authenticated PE
bytes; none is distributed. `source_key` projects data RVAs and
`source_immediate_key` projects instruction operands in native destination order.
An owning native caller must obtain its `key` through these projections, including
its exact local-immediate layout. Reports must never serialize key or seed bytes.
Original12 and DS4 expose no MS2 operation exports in the recovered inventory;
they are not silently aliased to another image.

AES uses the existing system-libcrypto AES128 ECB block primitive, without padding.
The encryption selector is exactly `direction == 1`; other AES directions decrypt.
Legacy security performs sixteen Feistel rounds over the supplied 32-byte key,
with source-owned 32-byte substitution lookup, level-specific input/output
permutations and reverse rounds exactly when `direction == 2`.

Native status behavior is retained: malformed replies and crypto failure return
3, unavailable capability returns 22, zero seeds skip key transmission, and a key
exchange error re-requests the seed up to three times. Seed errors return directly.
The exchange wrapper retries only native statuses 2 and 7, sleeps after each such
failure (including exhaustion), publishes the final NRC on exhausted status 7,
and preserves the native zero-attempt no-exchange behavior. Initial session
errors are discarded by the native session-pair helper. A mode-3 reply starts
keepalive before native minimum-length and echoed-subfunction validation.

Cancellation/deadline checks, rejecting oversized receive buffers, and attempting
session-1 restoration on Python transport exceptions are explicit Linux host
policies. Native returned failures also restore session 1, preserving the original
status. Cleanup never changes connection ownership. The finite exchange deadline
assumes the injected transport itself uses bounded I/O.

Run `python -m unittest discover -s tests -p test_utility_ex_security.py -v`.
Public tests use authored inputs and a published NIST AES vector; they do not
contain OEM keys or execute OEM binaries. Physical ECU/adapter behavior remains
`PHYSICAL_UNCONFIRMED`.
