# Retained TY STB, RCAM and PSA SRS

`scripts.utility_ex_ty_retained_05` implements the 37 assigned exact source/export
pairs: nine STB03/STB04 exports in TY12, TY18 and TYPlus; three RCAM exports in
TY18 and TYPlus; and PSA SRS GetStatus/SetStatus in TY12 and TY18. It advertises no
DS4 or cross-source aliases. Common UtilityEx wrappers own mode checks, worker
startup, 10000 ms scheduler timeouts and result polling.

Arguments are borrowed native little-endian mutable bytearrays. STB03 contains
five DWORDs with target at offsets 12/16; STB04 contains four DWORDs with target at
8/12; ExitActiveStabi ignores its pointer and accepts an empty buffer. Support checks update the original buffer. PSA SRS GetStatus requires five bytes and SetStatus requires four;
GetStatus writes only byte 4, preserving bytes 5..7. RCAM01/03 validate their accessed fields by action (4..13 bytes);
RCAM02 requires 0x102c bytes (length at zero, data at four, selection byte at
0x1024 and read/write DWORD at 0x1028). Buffer validation is a host boundary;
native pointers are never dereferenced by Python. RCAM read/write frames are bounded
to their native 0x1020-byte allocations; write payloads require 2..0x101d bytes.
Oversized host input/replies raise ValueError before any payload mutation.

STB executes native support-record lookup/counting, DTC filtering, calibration
preparation/start/result, target selection and branch-specific resets. Each helper
opens and closes its selected controller. The executing check always sends both
normal-session cleanup requests; their status does not replace the primary result.
RCAM uses the exact source fixed manager and preserves its connection/session on
native retained branches. It implements capability bit translation, staged
routine requests, caller-mutated cancellation flags, data read/write, the ordered
six-byte security transform and result-to-2000 mapping. PSA performs identity
classification, chooses D0 or CA, extracts the low nibble and sends DF/E0 writes.

Native C drops important argument and length branches in RCAM helpers. The
implementation follows ASM: response length/echo validation, actual payload
copies, second-payload-byte bit mutation and seven-byte routine parameters. The
six-byte key transform reads the original seed for shift/index selection and the
already-mutated key for addition.

`analysis/evidence/no-car-124/wrapper-packet.json` preserves all wrapper C/ASM
hashes and callback PUSH cross-checks. `source-closure.json` and its private source
copies preserve the transitive cached business closure. Those original artifacts
stay private; public tests contain authored diagnostic vectors only.

Validation: `python -m unittest discover -s tests -p
test_utility_ex_ty_retained_05.py -v`, changed-file Ruff and Pyright. Synthetic
public tests replace only the image digest comparison; they do not establish
original-image or physical behavior. HOST identity rejection is tested without
that replacement. All 37 actual public wrapper calls have also passed worker startup, timeout,
mode rejection and published status composition through engines 83 and 97 with
original image identities and authored communication primitives. Concrete selected
lower joins and independent source review remain required before G2/G3 can close.
