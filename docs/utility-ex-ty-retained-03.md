# Retained TY OCC, ACC, MG, ADX and SZABS

`utility_ex_ty_retained_03` provides the 47 assigned source/export pairs through
`supported_exports(sha)` and `run_body(export, args, context)`. It is joined by
the shared TY dispatcher. Unknown identities and unassigned pairs fail before
communication. Module bytes must match the selected SHA-256.

The owned algorithms cover OCC load-range and weight buffers, sensor support,
zero-point procedures and security; ACC support/history; MG configuration and
verification; OCC and ADX retained routine polling; and all 22 SZABS actions,
including dual managers, progress fields, diagnostic gating and AES security.
Argument buffers retain caller identity and little-endian native field offsets.
OCC05 exit has no arguments; other wrappers accept one native mutable buffer.
Worker creation, admission modes, timeout and status publication belong to the
shared UtilityEx engine. Individual transport, session and keepalive primitives
belong to the native communication facade. No business completion callback is
accepted.

The SZABS security identity table and AES keys are read only from the verified
caller-supplied PE image. Encryption uses the installed OpenSSL libcrypto AES-128 ECB
primitive with no padding, keeping extracted keys inside the Python process; original executables are never loaded or executed.
The keepalive setup preserves the source interval, request, response size and
recovery flag, including the two-manager cleanup distinction.

Validation:

```sh
python -m unittest discover -s tests -p test_utility_ex_ty_retained_03.py -v
ruff check scripts/utility_ex_ty_retained_03.py tests/test_utility_ex_ty_retained_03.py
pyright scripts/utility_ex_ty_retained_03.py tests/test_utility_ex_ty_retained_03.py
```

Public tests use authored protocol replies and a synthetic PE, including a
known-answer AES block. Private evidence records exact wrapper/body C and ASM
hashes and instruction-byte comparisons with all three original supplied PE
images. Source packet presence and passing authored traces do not establish
complete selected transport composition.

Status: software implementation and authored checks are present. G2 remains
open until the selected TY lower and fixed worker lifecycle are joined; G3
requires independent complete source-branch acceptance and actual selected
producer/consumer composition. Physical adapter and vehicle behavior remain
unconfirmed.
