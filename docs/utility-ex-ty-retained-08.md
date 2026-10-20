# Retained TY leaf 127 checkpoint

All 49 assigned exact source/export pairs have authored bodies: FSR21,
HNCSN14, BCM6, AVS4, and SBW4. This is not a G2/G3 closure claim. Concrete
lower composition and independent native branch review remain open.

The selected TY provider advertises the exact source-specific sets, including
all three source versions for FSR/BCM and the distinct TY18/TYPlus HNCSN sets.
No other source identity or existing97 core operation is aliased.

The public seam is `supported_exports(source_sha256)` and
`run_body(export, args, TYContext)`. It mutates the caller's bytearray directly.
The shared UtilityEx engine owns exported-wrapper mode selection, scheduling,
worker completion, and native result publication. Native status codes are
integers; source identity failure, host driver errors and host cancellation
remain exceptions. `NativeTYMemoryFault` identifies a supplied UI/native stack
allocation overrun instead of inventing a native business result.

FSR12 actively polls with 500ms sleeps and an unsigned elapsed bound strictly
greater than 5000ms. TY18/Plus start returns 1206/3406 while retaining its selected
controller; continuation consumes the caller's action/cancel fields, sends stop,
and finalizes. The FSR03/04 result writes two bytes in native reversed order.
Support snapshots reuse the existing reviewed support-record predicates.

BCM02's TY18 `10081620` and TY12 `10066960` entrypoints were mislabeled as C
strings in cached Ghidra output. The wrapper's exact ASM PUSH and original PE
objdump recover the real business workers. BCM01 uses all 60 literal DID table
entries; BCM02 uses BA..CD. Both collect into their 7/6-byte UI rows, switch from
target 726 to 720, write the tail DWORD, then apply the original actionable-row
predicate. Every initialized path reaches native finalization.

AVS01 retains on start and polls until status 2/cancel/error on continuation.
AVS02 uses two requests, a 5000ms native sleep, and a masked result byte. The Plus
mode22 alternate wrapper callback uses manager `1013e7d0`, requests `3101030207`
and `3101030107`, reads `22120b`, and reverses result bits 0/2 on incomplete
results. Native helpers compare echoed parameters without adding a response-SID
predicate that the source does not contain. Native `Sleep` calls use
`TYContext.native_sleep` without host slicing.

SBW retains the initialized controller and sets its caller UI flag, distinguishes
native cancellation status 1002 from host cancellation, polls pending 0/1 states,
and only cleans up on the native completion/error branches. HNCSN calibration/support, sensor initialization, front/rear angle writing,
neutral position and bumper readback retain their distinct native UI offsets,
wire prefixes, polling states and completion predicates. Normal
transition expands the manager's seven temporary setters and restores them, while
ignoring the native normal-session result exactly as the source does.

Evidence:

- `analysis/evidence/no-car-127/source-pair-packet.json`: all 49 assigned wrapper
  identities, callback PUSH candidates and cached source/helper hashes; this is
  a closure inventory, not a claim of execution completeness.
- `analysis/evidence/no-car-127/pe-byte-proof.json`: every wrapper instruction byte
  checked against the exact original source; all three 60-byte BCM DID tables
  match the authored public projection.
- `analysis/evidence/no-car-127/bcm02-*-recovered.asm`: private static disassembly
  for the missing-C callbacks and nearby helpers.
- `analysis/evidence/no-car-127/wrapper-import-packet.json`: 49 ported wrapper rows;
  TYPlus AVS02 includes its mode22 alternate callback.
- `analysis/evidence/no-car-127/checkpoint.json`: current implementation hashes and remaining gate boundaries.

Angle arithmetic requires explicit caller floating-point state:
`host:x87_control_word` for TY18 and `host:mxcsr` for TYPlus. TY18 reuses the
reviewed retained07 binary-rounding primitive for PC24/53/64 and all four RC
settings; TYPlus uses SSE precision/rounding. NaN/overflow conversions preserve
masked integer-indefinite low bytes, while unmasked invalid operations raise
`NativeTYArithmeticFault`. No Windows default control word is invented.

The TY18 first support helper's error path publishes the literal constructed
lock object's vtable `100da9bc` to both UI DWORDs, then returns the real native
status. Independent review is still resolving the other support helpers' native
stack-local error outputs. Their current undefined-state exceptions are a
reconstruction boundary, not proof that the original application crashes.

Verification: 46 authored branch tests pass, including all 49 actual83 exported
wrapper mode/thread/status joins through the actual97 provider and original
module identities. Those joins use an authored communication boundary and do
not establish concrete108 lower execution. Independent source branch review and
concrete lower joins remain open. No OEM PE was executed or changed; no device,
vehicle, Wine, network, JVM, or Git operation was used.
