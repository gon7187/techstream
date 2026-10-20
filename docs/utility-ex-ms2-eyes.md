# Native MS2 EYES controllers

`utility_ex_ms2_eyes` implements `Ex2MS2EYES_01_SendMessage` through
`Ex2MS2EYES_07_SendMessage` for the separately authenticated TY18 and Plus
UtilityEx2TY images. It composes communication, sessions, reads, routines and
`utility_ex_security` authentication; it never loads or executes the source DLL.
`utility_ex_ms2` delegates these bodies lazily. The original mutable native message
is kept throughout the wrapper, worker and business controller.

| Export | Native message minimum | Controller |
| --- | ---: | --- |
| EYES01 | `0x104` | action at `0x0c`; support flags at `0x00/0x04`, bank at `0x08`; paired DID values, skipped3020, completed count at `0x100` |
| EYES02 | 4 | authenticated routine2003, status polling, 30s timeout, stop and normal session; nonzero action abort |
| EYES03 | 8 | retained routine1001/100F, 60s polling; terminal status at `0x04`, normal cleanup on finish |
| EYES04 | 20 | actions1..4, session/routine ownership at `0x04/0x08`, timeout latch at `0x0c`, progress at `0x10`; source retention status1000/5000/0 |
| EYES05 | `0x4a4` | three managers, OBD09/02 VIN check, 13 source-selected records, read/write/compare, 11 bounded attempts |
| EYES06 | `0x188` | support or authenticated13-record read; count `0x180` and action `0x184` |
| EYES07 | TY18 `0x15c`; Plus `0x27c` | summary/change globals or selected capture blocks, PRE header, RC4 encryption and local file output |

Message sizes are byte counts; field offsets are hexadecimal.
EYES01 bank values outside1/2, EYES05 inline payload lengths beyond4 and
EYES07 capture-bank indexes beyond0/1 fail before communication; the original
32-bit pointer/stack overrun behavior is not reproduced. Oversized received
records fail closed. No untrusted process pointer is dereferenced.

EYES07 uses the embedded directory at `0x38`: TY18 has an ANSI native field;
Plus has a UTF-16LE field. The timestamp is written at `0x13c` for TY18 and `0x240`
for Plus. Data is encrypted using the source's four-byte seed, MD5 key derivation
and the 40-bit RC4 default of the named Microsoft Base provider. The actual RC4
input key is the first 5 MD5 bytes followed by 11 zero salt bytes; flags 0 does not
mean no salt. This follows Microsoft [Salt Value Functionality](https://learn.microsoft.com/en-us/windows/win32/seccrypto/salt-value-functionality)
and [CryptDeriveKey](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptderivekey).
An authored plaintext/key vector is checked independently with OpenSSL. Both
source helpers use flags 0 and have no CryptSetKeyParam salt override. Keys are projected
from authenticated caller-owned bytes and are never logged or serialized.
Existing capture files are preserved: the native host uses exclusive creation
and returns2004 on a collision, instead of reproducing the OEM's remove/overwrite.
This deliberate host safety difference also prevents replacing a preexisting
capture during the three source retries. The output directory must already exist.

The actual source paths retain managers for EYES03 successful start; EYES04
start1000/progress5000/action3 success; EYES05 selected security/VIN/read states;
and EYES07 security/allocation/read error2000/2002. Auxiliary EYES05 is always
finalized. Cancellation and host faults finalize owned managers and preserve the
original exception even if cleanup fails. A sole cleanup error remains visible.
The shared source worker owns scheduling and result-global publication.

## Verification and remaining software work

Run `python -m unittest discover -s tests -p test_utility_ex_ms2_eyes.py -v`.
The authored vectors cover both source versions, message mutation, polling,
retention, bounded cleanup, NRC, cancellation, host-fault identity, capture encoding
and collision preservation. They do not pretend their fake raw responses are
vehicle observations.

The private `runtime/no-car-146/prove_source.py` checks the14 wrapper/body pairs,
reachable business-helper C/ASM and source instructions against the supplied PE
bytes. It never executes them and does not serialize key material.

G2/G3 remain OPEN pending independent branch review and full producer/consumer
acceptance. All seven TY18 exports now run through the actual83 →97 →118 →146
→108/132 implementation with authored raw SDK positional outputs. This includes
EYES03/04 retained start and finish, EYES05 VIN/records → retained authentication
→ VIN/write/compare, and seven actual raw SDK host-fault identity checks. The14
exact-source wrong-mode wrapper checks return99 before any SDK call.

EYES05 source12f40/12cf0 selects diagnostic mode3, which creates a CAN broadcast
class. TY18 broadcast composition is now implemented: its explicitly authored
broker fixture has primary7a2, security763 and auxiliary physical7e0 with functional
outgoing7df. Using7e0 for both primary and auxiliary correctly hits the native
pool's duplicate-target rejection; no production rule is weakened. This fixture
is not proof of the original utility caller's target74 metadata producer.

All seven Plus lower attempts remain guarded by the actual source check. Full
Plus lower composition and caller/metadata provenance are software acceptance
work, not physical-only acceptance. No device, original executable, network
service or JVM is used by these checks.
