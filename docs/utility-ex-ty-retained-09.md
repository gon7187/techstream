# Retained TY HNPCS, DMC, HNAHB, SIS and PSAALM

`scripts.utility_ex_ty_retained_09` provides native Python business algorithms for
37 exact source/export pairs: eight TY12, fifteen TY18, fourteen TYPlus. The
source SHA identities come from `scripts.utility_ex_ty`; a name on another image
never enables a body. The common TY aggregator selects this provider.

The public API is `supported_exports(source_sha256)` and
`run_body(export, args, context)`. The context must satisfy `TYContext`, including
immutable module bytes matching the selected SHA, native sleep, persistent state,
and concrete communication primitives. The outer UtilityEx wrapper owns mode
admission, the 10,000 ms worker, result globals and host fault lifecycle.

All HNPCS operations and HNAHB/PSAALM use the selected classic communication
manager. DMC uses TY18 `1011d4f0` or TYPlus `101392d0`; SIS uses TY18 `1011e618` or
TYPlus `10134b78`. No entire business operation is delegated to a host callback.
The implementation includes native support-record masks and nonzero counts,
in-place caller outputs, exact echo/length checks, HNPCS stop-on-error,
DMC retained start/poll and mutable 16-byte security-key calculation, image
read/write length at offset `0x1020`, SIS cached capability flags and actions
0–8, native cancellation DWORDs, terminal statuses, and source cleanup/retention.
Direct native Sleep remains one call through `native_sleep`. DMC01 and SIS
extended-session prerequisites exchange normal session first and stop if it
fails. Cleanup attempts restore and finalize while preserving the exact primary
HOST or cancellation exception object.

Inputs are mutable `bytearray` objects; their identity and unmodified bytes are
preserved. HNPCS support/count operations use DWORD output fields. HNPCS send
and learning use a DWORD request length; Plus clear uses its length at offset 4.
HNPCS04 support outputs occupy offsets 4 and 8. HNAHB support returns a DWORD
record length, then history-clear consumes that length. DMC01 consumes action
at offset 0 and stop byte at offset 4. DMC02 image operations require `0x1024`
bytes. SIS01 requires six bytes; SIS02 requires `0x31` bytes, including cancel
DWORD at `0x24` and capability flags `0x28`–`0x30`. PSAALM takes no arguments.
Native lengths exceeding allocated buffers fail before a Python allocation or
exchange can expose unrelated memory.

The cached disassembly is essential: TY12/TY18 decompilation removes successful
HNPCS echoes, DMC poll terminal branches and SIS01 terminal paths. Their literal
ASM conditions are retained. A malformed response never fabricates success.
Private `analysis/evidence/no-car-128/wrapper-packet.json` records the literal ASM
PUSH callback, source hashes, wrapper predicates and verified original PE
instruction bytes for every assigned pair. Originals are static inputs only.

Run the public authored checks with:

```
python -m unittest discover -s tests -p test_utility_ex_ty_retained_09.py -v
```

These checks cover positive/negative/error paths, short/wrong echoes, support
masks, buffer mutation, retained start/poll lifecycle, native cancellation,
injected faults, rejected identities and the actual TY aggregator dispatch.
They inject individual communication primitives and do not establish concrete
lower transport completeness. Owner 83 has admitted all 37 wrappers. Private actual83 consumer checks cover
mode/arity admission, worker start/status, actual TY dispatcher, caller-buffer
identity and native result globals. Full G2/G3 stay open until owners 108/132 join
all concrete TY lifecycle/session paths and independent source review passes.
Hardware results are unconfirmed.
