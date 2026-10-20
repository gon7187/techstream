# FCHV tank and value workers

`scripts.utility_ex_fchv` implements 36 source/export pairs for the exact supplied
Techstream18 TY (`79fc495c…`) and GTSPlus TY (`821bbfd9…`) images. The exported
`supported_exports(sha)` list is the executable boundary. The four-variant PE
union has no FCHV export in Techstream12 or TY_DS4; those are not aliases.

The TY core dispatches to `run_body` lazily and verifies the supplied image bytes.
All wrappers in this module take one argument, require mode20/21, schedule the
native worker with10000ms timeout and return its uint32 status unchanged. The
root scheduler remains responsible for thread publication, joins and cancellation.

Implemented operations:

- FCHV02: AutoPowerOFFCancel; SupportCheck; ReadTankShutValveStart/Open/Close/Retrun;
  ReadTemperature; TankShutValveDrive/Stop; ReadPressure.
- Plus FCHV26: SupportCheck; ReadTankShutValveStart/Open/Close/Retrun;
  ReadTemperature; TankShutValveDrive/Stop; ReadPressure; ReadData.
- FCHV07 ReadValues and FCHV08 ReadValues/WriteValues in both images.

Previously implemented FCHV02 ReadData and EndExtendedSession, Plus26
EndExtendedSession, FCHV04 protocol/timer,05/06/09/10/13/14/16 and07/08 support
and overwrite stay with the TY core. This module does not replace those bodies.

Tank calls take one mutable bytearray with native byte offsets. FCHV02 has five
56-byte row descriptors, minimum316 bytes. FCHV26 has three rows, minimum196
bytes. Each row contains DID bytes0/1, uint32 payload offset4, uint32 payload
length12, availability DWORD44 and output bytes48 onward. The DID helper
produces two bytes for low DID9A/9B and four otherwise; reads beyond these
produced bytes are rejected before I/O instead of exposing original stack data.
Stop/ready/selection fields keep the native offsets. Successful start/poll/read
calls retain the initialized controller. Error paths stop the valve when the
source does, restore normal session and finalize; Close/Return success statuses
1012/1011 also retain it. Support02 publishes all five availability flags
before the caller validation pass can return1001. Temperature26 uses signed big-endian16 comparison
`<= -3277`, established from the signed ASM branch rather than decompiler text.
The shared timer preserves the native one-tick adjustment across DWORD wrap.

Value calls take one `FCHVValues(data=bytearray(...), selected=(a,b,c))` replacing
the native pointer/length pair and selection DWORDs. ReadValues07 publishes
concatenated DID/BE16-length/payload records only after every selected read
succeeds, clearing the previous pointer contents on helper entry. Selection DWORDs
are reread before every diagnostic call and again during aggregate copy; a newly
selected past slot contributes zero bytes, without inventing an extra request. ReadValues08
compares exactly bytes5:7 and does not replace the input. WriteValues08 selects
the first record per DID, writes2005/2010/2011 in that order, forces the first
2005 payload byte to1 and maps write failure to1000. Its record/selection
extraction occurs after initialization/session and finishes before the first write.
Malformed record payloads are rejected at that helper boundary before writing. Native unchecked successful AutoPower replies
shorter than five bytes and temperature comparison lengths beyond its two-byte
threshold fail explicitly rather than reproducing an out-of-bounds native read.

AutoPower saves the concrete broker target pair, configures750/E9 and protocol11,
conditionally sends tester-present, reads/modifies2001 bit40, then finalizes,
sets protocol0 and restores the target pair. It preserves native fixed result1009
and the tester-present status DWORD at offset280 (minimum284-byte block). These are actual communication
primitives, not a whole-operation callback. The concrete lower I/O join is owned
by the shared communication layer and remains independently gated.

Checks: `python -m unittest tests.test_utility_ex_fchv`; Ruff/Pyright for product,
tests and `runtime/no-car-111/wrapper_packet.py`. The latter regenerates exact
wrapper/body C and ASM SHA256 evidence. All packets are authored offline controls;
no OEM library was executed and no device/network session was opened.
`runtime/no-car-111/exact_body_replay.py` additionally reaches all36 implemented
source/export pairs through the actual TY aggregator using original module bytes.

Parent C116 remains OPEN across the declared PLAN41 partition: leaf115 owns
FCHV01; leaf116 owns03/04/11/12/17; leaf117 ownsPlus24/25/27/28. These workers
are not aliases to this module. Independent body review and complete concrete
lower communication integration are also pending. Physical behavior is
`PHYSICAL_UNCONFIRMED`.

HOST fault/cancellation safety is explicit reconstruction policy: attempt a raw
valve-stop request for a possibly active operation, then normal session and
finalization. Every release is attempted; cleanup failures attach notes to the
original exception instead of replacing it. Release uses the concrete bounded
`cleanup_exchange` and `cleanup_session` scope while retaining global cancellation.
`actual_cleanup_replay.py` proves the real public FCHV18 Start worker through108,
132 and typed SDK callbacks: activation sets cancel, stop and normal requests
still reach the SDK, then both filters/channel are released and the original
foreign InterruptedError survives. This is an authored SDK boundary, not device
execution. Other source/lower branches, including guarded Plus, remain open. Direct native Sleep sites use `context.native_sleep`,
preserving the shared host pre/post cancellation boundary without NK chunking.

Each tank, AutoPower and values operation captures its entry exception identity
and traceback in a thread-local ContextVar. An unrelated exception handled by
the caller is not treated as this operation's primary: a new cleanup fault still
propagates, and ordinary normal-session calls retain their native helper choice.
