# Retained TY AHS, power seat and image view monitor

`scripts.utility_ex_ty_retained_04` implements exactly 35 source/export pairs:
nine AHS operations in each of TY12, TY18 and TYPlus, and three PSEAT operations
plus IVM01 in TY18 and TYPlus. Unknown identities and unassigned exports fail
before acquiring communication. The caller supplies the original module bytes;
their SHA-256 must equal the selected source identity.

AHS runs on the selected classic communication manager in mode 4. Its support
records preserve sparse native offsets and count nonzero bytes. The routines
mutate the caller's original bytearray, preserve AHS01 target changes, save and
restore busy retry limits, retain native frame lengths, map the documented
negative replies, poll with wrapping DWORD ticks and evaluate the native DTC
priority order. Direct native `Sleep` calls use `native_sleep`, with explicit
host cancellation checks around primitive operations.

PSEAT and IVM use the exact source's fixed UDS manager in modes 20 and 21.
PSEAT preserves its initialized manager after a successful start, polls result 1,
accepts result 2, observes the caller's mutable cancellation DWORD, and restores
the normal session and finalizes on completion. IVM preserves its original data
and length inside the caller's buffer, temporarily sets bit 7, drives both native
routine stages, restores the data, and updates the completion DWORD. Statuses
1005 and 1007 deliberately retain the manager for the caller's next action.
The module never substitutes a whole business-operation callback.

The TY18 C decompiler omits several successful ASM branches. In particular,
PSEAT `100be8e0` accepts result 2 and IVM `100c4e00` publishes completion 2.
The authored implementation follows the instruction stream. AHS successful echo
branches likewise come from ASM rather than the simplified C output.

Native buffer layout used by the public entry point:

| Operation | Minimum caller buffer | Mutable output |
|---|---:|---|
| AHS01 support | 16 bytes | DWORDs at 0, 4, 8 and 12 |
| AHS01 confirmation | 18 bytes | bytes at 16 and 17 |
| AHS01 adjustment | 16 bytes | no output fields |
| AHS02 support / calibration | 4 / 6 bytes | support DWORD at 0 |
| AHS03 support / initialization | 4 / 8 bytes | support DWORD at 0 |
| AHS04 support / synchronization | 8 / 8 bytes | support DWORDs at 0 and 4 |
| PSEAT | 8 bytes | caller may change cancellation DWORD at 4 |
| IVM | 0x204c bytes | response at 0; retained data at 0x1020; length at 0x2040; action at 0x2044; completion at 0x2048 |

`python -m unittest discover -s tests -p test_utility_ex_ty_retained_04.py -v`
runs authored literal positive, malformed, error, cancellation, retention,
exception and cleanup checks. Private-only checks verify the exact 35-pair set,
original image hashes, cached C/ASM hashes and instruction bytes, and execute
all 35 original source identities through the actual UtilityEx selected engine
and TY aggregator against authored primitive communication traces. Public clones
skip the private-original checks when those files are absent.

This is not a G2/G3 closure claim. The concrete TY classic selected lower and TY
fixed-manager lifecycle must be connected by their owners, then the actual lower
composition and independent source branch review must pass. The tests using
primitive communication traces do not establish driver, adapter or vehicle
behavior. Host cancellation/fault cleanup and rejection of out-of-allocation
native lengths are explicit safe host policies, rather than Windows forced
thread termination or native memory corruption emulation.
