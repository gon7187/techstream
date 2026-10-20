# Native JLR adapter firmware software

`scripts.jlr_firmware` implements the host-side `PassThruFirmwareUpdate` image
selection and transfer path recovered from `monpj432.dll`, SHA-256
`2710726fdd174f32b5e703e310cfce047a663451edbb3e35ca0c8eeff6929413`.
This is adapter firmware, separate from Toyota ECU calibration programming.
Physical status: **PHYSICAL_UNCONFIRMED**. Verification uses synthetic framed I/O;
no USB discovery, physical open, flash, or vendor PE execution was performed.

## Explicit inputs and API

- `parse_image(bytes)` / `load_image(path)` read an intact native resource image.
- `images_from_pe(bytes)` / `load_library(path)` statically extract integer
  RT_RCDATA resources 5006 (bootloader) and 5005 (application). PE bytes are never
  loaded as code. Duplicate language variants fail rather than choosing silently.
- `plan(board_reply, images)` compares eight supplied board records with image
  fingerprints. Records retain native bitmask slots, board kind and image bytes.
- `FirmwareUpdater(JLRClient(injected_transport), reopen=..., cancelled=...)`
  is inert until `run(images)`. The caller explicitly transfers connection
  ownership. An existing channel owner prevents execution and is left alone.
  Supply both image roles to reproduce the complete native embedded catalogue.
  `reopen` must return a new, unowned `JLRClient`; it supplies the platform-specific
  re-enumeration result for the same explicitly selected logical device after a
  master mode transition; the provider owns physical identity correlation.
  Constructors do not open
  devices. This module does not construct any USB transport.

Every file entry point uses `local_files.read_regular`: bounded regular-file
reads reject devices/FIFOs before running their open operation. Firmware, keys,
original executable bytes and decompiled C are not distributed. Tests construct
independent synthetic images and PE resource trees.

## Container and wire contract

The intact resource starts with a 108-byte envelope. DWORDs at 0, 4 and 8 hold
header size, kind (`0x50001` bootloader / `0x50002` application), and version.
The DWORD at 76 is the comparison fingerprint used by the host. Other envelope
bytes and all bytes after the envelope remain opaque and are preserved exactly.
The host does not decrypt, decompress, rewrite or recompute image authentication.
A fingerprint match is not a cryptographic authenticity assertion.

All commands target native board manager 1 and use `JLRClient.transact` for SLP
framing, sequence correlation, status validation, cancellation and deadlines.

| Native helper | Executable disposition |
| --- | --- |
| `0x100615e0` | `FirmwareUpdater.run`: one-shot device ownership and bounded record flow |
| `0x1004b700`, `0x100607c0` | Windows device enumeration/selection replaced by explicitly injected client/reopen provider; no implicit enumeration |
| `0x1000a1d0` | `images_from_pe`: RT_RCDATA 5005/5006 selection, static reads only |
| `0x1003ec30`, `0x1003ee40`, `0x10043f70` | `plan`: board kinds 1..11, presence/fingerprint selection, bootloader/application record ordering; supplied images replace embedded resources |
| `0x10040ac0` | Total image lengths and `acknowledged` byte accounting |
| `0x10040b40` | Mode preparation, begin/chunk loop, master reopen and post-transfer board confirmation |
| `0x1003f160` | Opcode `0x109`: eight 20-byte board records |
| `0x1003e910` | Application-mode opcode `0x102`, then explicit reconnect |
| `0x1003e820` | Boot-mode opcode `0x103`; native accepted statuses 0 and 7 |
| `0x1003f270` | Bootloader unlock opcode `0x10c`, ordinal plus `0x5a81c30e`, `0x5a000000` |
| `0x1003f480` | Opcode `0x10a`, operation 1, slot ordinal, total image length, first 108 bytes, four zero tail bytes |
| `0x1003f770` | Opcode `0x10a`, operation 2, slot ordinal, chunk length, `0x5a000000`, next unchanged image bytes |
| `0x1006e180`, `0x1006d9b0` | Existing JLRClient framing and bounded correlated response handling |
| `0x10044110` and device destructors | Owned injected transport close and ownership release on all paths |
| MFC strings, progress callbacks, containers, CRT | Python dataclasses/tuple/history, byte counters, ordinary exceptions; no original UI code or C++ runtime needed |

The begin helper's four extra tail bytes are unwritten stack bytes in the native
implementation (`0x1003f593`..`0x1003f5bc`). They are deterministically zero here.
They do not belong to the firmware image and do not advance the image offset.
The next-chunk request size comes from reply byte 20. Zero terminates the transfer
only when every image byte was acknowledged. Oversized chunks, early completion,
truncated/status-error replies and mismatching post-transfer identities fail.
The host caps chunks at 8192 bytes and images at 16 MiB as explicit resource bounds.
The whole operation has a 300-second default deadline (explicit maximum 600 seconds);
each individual transaction receives at most 10 seconds of the remaining budget.
This deadline is cooperative: injected transport/reopen/close implementations must
bound their own calls; Python cannot preempt an arbitrary blocking provider.
Board information is refreshed after every mode transition, as in the native path.
The export's outer inventory loop performs at most two passes, taking a fresh
board report and replanning before the second pass. A master already in mode 1
ends the outer loop after its current pass. A present master application matching
the explicitly supplied application image first receives `0x103` and a refreshed
`0x109`, even when the ensuing image plan is empty. With only a bootloader image
supplied, an absent application comparison input is never guessed.

The original Windows registry suppression flag and minimum-version policy used by
other connection paths are not silently imported. This API follows the explicit
firmware-update export's fingerprint selection; `force=True` is an explicit local
request to include matching records on the first pass; the second pass uses
fingerprint selection. User-supplied images are validated against
supported role envelopes, not an unverified file extension.

## Lifecycle and uncertainty

The updater has terminal states `verified`, `cancelled` (before any command), and
`uncertain` (any failed attempted transaction or cleanup). It cannot be rerun or
resumed. A status-only acknowledgement never becomes success without final board
presence/fingerprint confirmation. Failure closes owned I/O; cleanup exceptions
are attached to an existing primary error rather than hiding it. A rejected,
pre-owned client is not closed. Device reconnection, electrical timing and actual
firmware acceptance remain physical acceptance work; synthetic verification does
not establish them.

Run `python -m unittest discover -s tests -p test_jlr_firmware.py -v`.
