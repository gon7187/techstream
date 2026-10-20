# Native TY body operations

`scripts.utility_ex_ty_body.run_body(export, args, context)` executes reviewed
business code over the common concrete UtilityEx communication manager. The
common engine still owns export mode checks, thread scheduling and publication.
`supported_exports(sha256)` is the exact-source registry. Imports never open a
device, load an OEM library or contact a service.

The original callable build is UtilityEx2TY SHA-256
`79fc495c68eb099a7ebc0d1eefe0eafd80101ac0bc09a58d3f603ed556c84762`.
The reviewed GTSPlus subset uses SHA-256
`821bbfd9957679ceef4ac32c239b8840c984e98ac61050ce7348ac2bc88b04ce`.
Every call verifies supplied original bytes against its exact identity. No
filename, release number or similarly named export enables another build.

| Native operations | Algorithm and evidence RVA |
| --- | --- |
| SMRT62 support/read, diagnostic start and terminate (18 and Plus) | `b3c40..b414f` / `b98a0..b9e43`: DID `1023` availability guard, DID `203d` native payload and length, selector bit packing, routine `1504`, 100 ms command gaps, retained start session, cancellation and distinct restore precedence |
| MS2SMRT05/07/08/09 (18 and Plus) | `af490..af6ff`, `afee0..b042f` / `b51b0..b640f`: selected support-bank continuation, explicit `7b4` target, support alternatives, DID `11b2` write, selected `137a` raw reply buffer, routine `5000`, four-attempt transport retry, exact 60 second absolute and 10 second elapsed native deadlines, NRC globals and restore precedence |
| BDY51 key-registration/status bodies (16 operations including support) | `2b150..2c1d4`, `2c4e0..2c8ff`: selected response/context updates, exact /15 count arithmetic, owner/key state decisions, DTC `9402/9401/9405` matching/clear, request/end and retained/finalized lifecycle, native cancellation and 61000 ms removal timer |
| SMRT33 registration/start status; SMRT35 support/read/check/terminate | `22670..229df`, `231b0..2365f`: exact eight-byte A5 writes, selected support-bit enumeration, 500 ms/31001 ms registration sampling, 4000 ms communication checks and retained-controller stop semantics |
| MM09 soft error history / MM10 disc errors | `249f0..24daf`, `250e0..2524f`: sparse support mask expands sequential payload bytes into native output slots; disc output receives raw reply even on transport failure |
| CSN05 tire circumference read/write and CSN10 reset | `5dfc0..5e39f`, `97250..9738f`: native selected reply/mask banks, consecutive masked write values and selector bit packing; exact action-guarded routine `1105` and session lifecycle |
| FCM13 information | `c49a0/c4a10/9dd00`: zero and fill the native 16 byte DID `10d2` output, normal-first extended session and cleanup |
| FCM04 front radar sensor memory start/check | `b6ba0..b6f5c`: check DID `10a0` bit 80 and DID `1017` bit 40, routine `110e`, result/cancel/cleanup state shared with the independently checked Navi loop |
| FCM07 Navi initialization start/check | `b27c0..b29e2`, `851f0`, `8d860`: initialize, configure retry/pending fields, normal then extended sessions, routine `1209`, 200 ms result polling, native result and cancellation cleanup |
| FCM12 PCS forced brake start/check/stop | `be4e0..be807`: routine `160c`; distinct start failure 1004, result 1000/1002, cancellation 1001 retaining the session, explicit stop 1003; stop/restore status precedence |
| MM41 transfer to pairing mode | `c1980..c1ac3`: initialization/session failure maps to 1000; 200 ms delay, routine `1110` payload zero, response echo/length validation and unconditional finalization |
| APP03 IR projector phases 1–4 | `98ea0..990cf`, `b7ba0`: routine `1702` values 0/2/1/0, normal/extended session setup and per-phase native setup/request/restore status precedence |
| PLG03 selected charge diagnostics | `c1ad0..c1e7a`: support flags, selected protocol `2a/2b` and table byte, two-stage start with 1500 ms delay, 200 ms result polling, native cancel DWORD, retained session after successful start/result, dual routine stop and normal-session/keepalive cleanup |
| PLG01 classic lid guard/diagnosis/status | `3c440..3cac0`: selected payload lengths and indices, charge-lid bit guard, exact command `3b2401`, result code mapping and native transport-error precedence |
| PLG01 UDS support/start/poll/diagnosis/final | `7e020..7e6f0`, `83880`: PID `0101` availability and `1700` mutually exclusive support flags, routine `110f`, exact `7f3122` mapping, 100 ms polling/native 22000 ms bound, selected DID `170c`/`1727` result mappings, explicit finalization |
| DCM21 ID and DCM19 software readout | `6d6d0..6d87f`, `67690`, `67bc0`: selected classic controller, output clearing, request `1a85` or `2126`, size/offset slicing and native copy-on-error behavior |
| DCM30/40 settings; DCM32/41 enable; DCM39 routine; DCM37/44 command | `908e0..90aef`, `c1f50..c1ffd`, `b1690..b1720`, `93640..936e7`, `c2620..c26bd`: exact setting write/readback, differing restore-status precedence, routine `1103`, mapped native error field `10b0` distinguishes status 105 |
| DCM38/45 clear | `c26c0..c27a0`, `99440/99480`: normal-first extended session, exact write `2e206100` response, DID `2061` result, status 2005 for nonzero readback, restore/finalize |
| AC08 refrigerant filling / AC09 pressure history clear | `63f00..640df`, `641b0..6448b`: source-selected command length, exact zero padding and two-byte echo checks |
| AC21 servo / AC25 battery low count clear / AC26–27 resets | `8bb20..8bc88`, `8c140..8c323`, `97390..97543`: native 50 ms session/command gaps, routines `1101/1105/1106/1107`, AC25 native 30 second polling, native action guards and distinct restore/error precedence |

The exact native12 and GTSPlus builds also have private implementation
candidates for these four MM09/10 operations. Their selected algorithms use the
native12 `b940` or Plus `142f0` pending setter, preserve MM10's seven groups and
partial output order, and retain the exact source guards. The eight wrapper
pairs remain pending root packet integration and review; they do not change the
170/514 public coverage count yet.

FCM start/stop, APP03 and MM41 worker bodies accept `args=()`.
When the original exported wrapper forwards an unused pointer, these bodies
also accept and ignore its one opaque argument; wrapper arity remains exact.
The Plus subset includes APP03 four phases, MM41 pairing and AC26/27 resets. FCM checks take one mutable
`bytearray` with at least four bytes: the native cancellation DWORD in little
endian. Start success deliberately leaves the native session active for the
corresponding subsequent operation. PCS cancellation preserves the session for
its explicit stop operation; Navi cancellation restores and finalizes it.

PLG03 takes a native context of at least 28 bytes; action is DWORD 0, cancel
is DWORD 4, variant DWORD 8, selected index byte 12, support DWORD outputs 16/24.
Action 1 additionally requires the selected table byte at `36 + index * 8`.
Its native unbounded polling has the same explicit host 180 second/900 poll cap.

PLG01 classic lid/status takes 16 selected metadata bytes (lid index/size DWORDs
at 0/4, diagnosis status index/size at 8/12); the command-only classic diagnosis
takes no arguments. PLG01 UDS support/diagnosis takes one `bytearray` of at least 24 bytes; native support
DWORDs are at offsets 16 and 20. DCM ID takes one output buffer of at least 4132
bytes. DCM software takes a 43 byte context, with input source offset DWORD at 0
and size DWORD at 8 (bounded to 21 output bytes and a 4128 byte native reply).
DCM38/45 take one mutable result byte. AC26/27 take one four byte native action
DWORD; a nonzero action retains the native no-command behavior. AC21/25 take no arguments.

BDY51 takes at least 40 bytes except `ExitCommunication` (no arguments).
Selected response index/length are DWORDs 0/4, reply bank starts at 12; count/state
DWORDs are at 20/24/28/32 and cancellation at 36. The supplied buffer must contain
the selected indexed bytes and the complete reply. SupportCheck produces selected index/length/count metadata through the actual A8 support bank.

SMRT35 get/reget takes six output bytes; check takes 16 bytes (selected value at
byte 6, native stop DWORDs at 8/12). SMRT33 start/status and SMRT35 terminate take
no arguments. MM09 history takes 131 bytes: selected support header/mask at 0,
payload length DWORD at 64, 63 output bytes at 68. MM10 disc takes 4132 bytes,
with selected exact reply length DWORD at 4128.

CSN05 takes 8266 bytes: native read/write lengths DWORDs 0/4, selected write mask
at 8, reply/value bank at 4136, read selector byte at 8264 and write selector at
8265. CSN10 takes an action DWORD. FCM13 takes 16 output bytes. DCM30/40 takes
two mutable setting/readback bytes; DCM32/41/39/37/44 take no arguments. DCM37/44
requires concrete `read_field('native_10b0')` when exchange returns status 7; the
field is the controller's mapped native error, not the raw negative reply byte.
AC08/09 takes one selected command-size DWORD, bounded by the native frame buffer.

The injected context provides `module_sha256`, `module_bytes`, cancellation,
clock/sleep and `comm('native:1011d4f0')`. Communication executes individual
initialize/configure/session/frame/finalize primitives; no provider declares a
whole business operation successful. The communication scheduler owns wire
retry/pending behavior. The selected native fields are `1080=0`, `1084=180000`
and `1064=0`.

Native FCM result loops have no deadline. The host adds an explicit 180 second
or 900 poll ceiling and exception cleanup; exceeding it raises `TimeoutError`,
never reports a successful native result. This is host policy, not a recovered
native timeout status.

Synthetic tests cover phase transitions, pending/completion, response lengths
and echoes, transport/session errors, differing cancel/stop cleanup, source
mismatch and deadline bounds. They prove native algorithm reconstruction over
injected primitives; vehicle behavior remains `PHYSICAL_UNCONFIRMED`.

SMRT62 uses a native 4140 byte context: selector DWORD at 0, cancellation DWORD
at 4, payload at 8 and payload length DWORD at 4136. The start write replaces
the second payload byte with the selector mask and copies the remaining native
bytes. Native ASM preserves success on a valid `2e203d` echo; the supplied
18 decompilation misleadingly prints an unconditional status 3.

MS2SMRT05 uses 16 bytes: action at 0, alternative support output at 4, selected
DID at 8 and NRC output at 12. MS2SMRT07 uses an action DWORD. MS2SMRT08
uses 4248 bytes: support bitmap 0..111, raw 4128 byte reply at 112, NRC DWORD
at 4240 and action DWORD at 4244. MS2SMRT09 uses action/NRC/result DWORDs at
0/4/8. Four native attempts retry status 2/7 with `Sleep(0)`; only final status
7 publishes native global NRC `1012ae38` (18) or `10153554` (Plus).
MS2SMRT05 preserves its native wrapped absolute deadline comparison. The host
adds a 60001 iteration tight-poll ceiling which raises `TimeoutError` if the
injected clock makes no progress; this is host policy, not native success.

Coverage remains **OPEN**: 128 exact native18 bodies, 36 Plus bindings and six
classic12 SMRT33/35 bindings are callable (170/514; 344 OPEN).
All other body exports and all DS4 bindings fail closed pending independent
branch review.
The actual native18 manager108/132 path now passes selected consumer checks
through real 83/97 wrappers and an authored raw J2534 SDK: retained lifecycle,
negative replies, transport exceptions, native cancellation, bounded host
cancellation cleanup and classic A8 metadata into BDY51/52/53. No Comm provider
is replaced in that check. This remains a subset of the source union. Plus ordinary fixed manager now passes SMRT62 positive/negative/fault,
BDY21 native-cancel/stop and AC28 retained lifecycle through the real SDK facade.
The receipt covers 40 scenarios total; other Plus lower branches retain their
individual source gates.
The reviewed four-build union snapshot contains 212 distinct export names and
514 source/export bindings. The private evidence coverage ledger records the union source hash and
every binding/status (170 callable bindings, 344 open bindings). An inventory entry
is not an implementation claim. OEM disassembly and bulk text remain private
BYOD evidence.

Run `python -m unittest discover -s tests -p test_utility_ex_ty_body.py -v`.

Classic12 SMRT33/35 uses identity
`e85b2456b26d3966ca243c03fa775cf81ad58bf05689bdb87b616eda4c8b6f5f`,
mode 3 and exact pending setter `native_rva:b940`. Native direct delays call
`native_sleep` when available, preserving the scheduler yield from `Sleep(0)`.

AC28 (18 `b13e0..b16bf`, Plus `b7410..b770d`) takes an eight byte
cancellation/action context. Action DWORD 4 zero starts routine `1108` through
raw six-byte-minimum normal/extended session replies and returns 1005 while
retaining the controller. A later nonzero action polls result byte 0/1 as
pending, 2 as complete and other values as 1007. Cancellation byte 0 equal to
1 exits polling; the routine restores normal session and finalizes. Its native
unbounded polling has an explicit host 180 second / 3600 poll exception ceiling.
The 18 C decompilation loses result branches; the ASM is the source of those
branches. Independent full-source review remains OPEN; native18 retained lifecycle is included in the actual SDK consumer receipt.


BDY21/22 support both native18 and Plus. KeyNumGet produces count bytes;
start retains routine `1106`, poll preserves native cancellation codes 1001/1003,
and Stop/Timeover/End perform stop plus normal-session cleanup. Host cancellation
uses the manager bounded cleanup primitives while retaining the global cancel
flag. Native18 BDY23 implements target switching, key-search one-hot masks,
seven state bytes and the native result/cancellation fields; the differing Plus
mode22 branch remains OPEN.

BDY52/53 SupportCheck produces native selected metadata from A8 support banks.
BDY52 takes 16 bytes (metadata DWORDs 0/4/8, count/state bytes 12..15), while
BDY53 takes 15. The command, 500 ms sampled field transitions, DTC checks and
clear order are preserved. BDY52 clears only selected fault codes; BDY53 always
clears and prioritizes `9402` over `9401/9405`. Unsafe support offsets that would
read beyond the native 4128-byte bank fail closed, rather than reproducing an
out-of-bounds stack read.

DCM36/43 native18 take 4092 bytes: action DWORD 0, count byte 4, up to 255
16-byte records at 5, cancellation DWORD 4088. Actions 0/3 distinguish native
state mappings; action1 sends exactly `2e20010100` and retains the controller;
action2 samples DID `2001` until native completion/cancel and restores normal
session. DID `f181` clears all 4080 output bytes before transport and copies
records from the zero-padded native reply. The 180 second polling exception
ceiling is host policy. ASM jump tables recover branches absent in the supplied
C decompilation.

Private reproducible checks live under `runtime/no-car-103`: `wrapper_packet`
binds newly reviewed exports to wrapper/body hashes and source arity/modes;
`pin_sources` verifies their instructions against exact supplied PE bytes;
`concrete_consumer` executes actual selected wrappers and manager lifecycle over
raw SDK calls. None executes the OEM PE. G2 and G3 remain OPEN until the full
owned source union and independent consumer review pass.


All native18 DCM exports in the current OWN103 union now have business bodies;
cross-version bindings remain independently gated. DCM12 produces command34
length on target750/C7. DCM15 produces PID35 count/PID38 length, maps selected
read state1 to9100 and exact `7f3b22` to9101. DCM20 preserves the optional PID99
support failure, mandatory9A/9B capabilities, selector-specific zero-padded
commands and 500ms status/cancel sampling. DCM19 FOTA produces20 software and2
status-byte metadata, exact33 writes and1000ms status polling with native cancel
DWORD44. Remote DCM settings retain target/pending initialization order, native
C2-only negative-response acceptance, C4-only read operation, conditional dual
write/readback and output bytes28/29. Polling host ceilings raise exceptions.
Selected source11DB0 calls use `select_target`; fixed manager19D40 calls use
`configure_target`, preserving their different native globals and fallback rules.


All native18 MM names in the current union now have bodies. MM09 support
produces the sparse63-byte mask, payload count64 and optional PID41 flag132;
MM10 support packs seven source-reachable pair/groups at4132 and count4128,
flag4216. Existing MM09/10 bodies consume the same mutable buffer. MM08 recovers
kind1/kind2 A8 metadata, literal30540001, zero first-read delay,500ms sampled
status and native15second timeout output. MM11/13 copies ten PID52 bytes and
conditionally three PID53 bytes. MM17 validates thirty PID64 capabilities and
copies five six-byte rows. MM20 validates PID55 support and cancels valet mode;
MM21 accepts exactly a one-byte diagnostic response, matching ASM rather than
its misleading C. MM31 preserves its first ten DID1014 bytes on a later
DID1015 failure. MM30/39/40 retain successful starts and preserve their distinct
stop, cancellation, result-code, session-restore and finalization behavior.
Their native unbounded loops use explicit host exception ceilings. The source
wrapper packet includes the older MM09/10 consumer wrappers so their new
metadata producers can execute through actual83 admission.
