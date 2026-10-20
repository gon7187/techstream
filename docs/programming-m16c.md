# M16C and SecurityVFOREST programming engines

`scripts.programming_m16c` implements the raw M16C bootloader, its SecurityM16C
variant and the SecurityVFOREST writer. It consumes explicit `VendorCAN`
read/write callbacks and calibration inputs. It never opens a transport, runs a
vendor DLL or derives vehicle identity. These families do not use the P5
`NativeProgrammingChannel` or alias `CommonWrite`.

## Selected native inputs and lifecycle

`parent_cpu(cpu_types, parent_types, current)` selects the first exact configured
parent CPU match, excluding the current CPU. No match fails before transport I/O.
The caller binds the resulting parent's request/response identifiers to the
supplied `VendorCAN` and its filter callbacks. It separately binds the native
finish identifier to `finish_channel`; finish does not assume the request ID.

`m16c_segments(image, starts, sizes_kib)` pairs native `StartAddress` entries
with `GetBlockInfo` sizes, converts KiB to bytes, and slices concatenated image
data in native order. Missing/trailing bytes, count mismatches and unsafe address
ranges fail explicitly. `M16CSegment(address, data)` also exposes aligned,
complete 256-byte regions for direct injected operation tests.

`M16CControls(get_timeout, set_timeout, start_filter, stop_filter)` supplies the
original transport lifecycle. Callbacks act on the explicitly bound native
identifiers, return an integer timeout/filter handle where applicable, and must
return promptly. Filters are stopped on success and error. M16C saves/restores
the original receive timeout even if another cleanup fails. Cleanup errors stay
visible in the returned report. SecurityVFOREST does not invent a save/restore
operation absent from its native writer.

```python
from scripts.programming_m16c import M16COptions, m16c_segments, m16c_write

segments = m16c_segments(image, (0x12000,), (1,))
options = M16COptions(
    location_id=location_id,
    parent_password=parent_password,
    password=child_password,
    id_address=password_check_id_address,       # exactly three bytes
    password_suffix=password_check_password,  # exactly three bytes
    receive_timeout_ms=receive_timeout,
)
report = m16c_write(
    raw_channel, controls, segments, options,
    finish_channel=finish_channel,
    progress=lambda count, percent: update_progress(count, percent),
)
```

`last_cpu=False` sends the original change-CPU command `65` and waits for its
ACK instead of finishing. The last CPU sends `80` to the supplied finish channel
without awaiting an ACK, matching the native null response-address argument.
Its remaining deadline is clipped to the parent operation's deadline. Supplied
channels must not be used concurrently.

## M16C operation contract

`M16CWriter(channel)` exposes `password_check`, `status`, `verify_status`, `erase`,
`page` and `prepare_retry`. Its commands have no common `3c` ACK step:

| Operation | Native payload and completion |
| --- | --- |
| Password | `a0` + ID-address3 + `07`, followed by password32 big-endian + suffix3; `a4` response byte1 must contain mask `0c` |
| Clear | `a6` before erase and write |
| Erase | `a1` + address bits8–23, low byte first + `d0`; `a4` byte0 bit7 means ready, mask `30` means failure |
| Write | `a2` + address bits8–23, low byte first; separate raw 256-byte page; same readiness mask, plus response byte1 mask `02` means failure |
| Verify | `a3` + address bits8–23, low byte first; separate raw 256-byte page; `a8` response `ff` means busy and `00` success |

Native failure codes are password7, erase12, write13, verify15 and retry-prepare20.
`M16CError` retains its operation, code and received status bytes. Explicit
`M16CReadError(9)` / `(16)` denote the native recoverable unavailable-read
outcomes; unrelated read errors propagate. Malformed/truncated buffers fail host
validation instead of reproducing native out-of-bounds reads.

The full `m16c_write` sequence is conditional parent CheckID, optional watch-CPU
memory information for plain M16C, configured flash timeout, conditional M16C
password check, then erase each supplied region and alternate write/verify for
every 256-byte page. Plain M16C also honours `WaitTimeAfterFlashWrite`.
Recovery skips CheckID/password only when `IGOffRetriableFlag` is false.
`M16COptions` names expose the other native waits and timeout settings explicitly.

`M16COptions(security=True, nonce=nonce16, key=key16, ...)` selects SecurityM16C.
It always sends the recovered six combined nonce/key frames, with inter-frame
waits and a single ACK after the last frame. It does not add watch-CPU memory
retrieval or the plain writer's final wait.

`m16c_prepare_retry` implements the plain M16C `PrepareRetry` export with filter
cleanup: try `a4`; on native read9/16 try `a8`; if both fail send exactly 256 zero
bytes and wait. There are at most four `a4` probes and three dummy transmissions.
Any available status completes preparation regardless of its busy/error bits,
matching the original reachability probe. It does not erase or replay a writer.

## SecurityVFOREST

`security_vforest_write` performs its own native order: CheckID, combined
nonce/key, memory information, firmware-descriptor/CPUID compatibility gate,
write all groups, verify all groups, falsification check, then change CPU or
finish. `VForestPolicy` supplies CPUID, configured shrink mode and status waits.
An explicit `alternate_policy` callback can load the selected alternate native
parameters; they must pass the same compatibility check before any image bytes
are sent. No alternate CPU name or resource selection is guessed.

The recovered write/verify body is byte-identical to P4 VFOREST, so it reuses
`vforest_groups` / `vforest_transfer`: group-count-minus-one headers `42`/`17`,
raw chunks up to 1024 bytes, ACKs and status busy40/write or busy20/verify.
It has no invented erase command. Errors map to native write29/verify30;
combined authentication maps to72 and falsification check to73. CPU mismatch
maps to10. Common CheckID, memory, change-CPU and finish behavior is shared only
where the originals call those same helpers.

`new_password(image, address, byte_order, explicit=...)` implements the actual
`CalibrationFile::GetNewPassword` getter: use an explicitly cached value when
present; otherwise read four bytes at native `PasswordAddress`. `ByteOrder`'s
low16 bits select little endian when zero and big endian otherwise. Inputs are
supplied image bytes, never device memory. When `previous_retry_password=True`,
the SecurityVFOREST runner requires this resolved `replacement_password`.
`retry_password` implements native failure selection: a force flag selects the
replacement, error7 toggles the previous choice, other errors clear it. It does
not automatically repeat an uncertain programming operation.

## Versions, progress and bounds

Plain M16C supports explicit `M16COptions(version="12" | "18")`, default18.
SecurityM16C and SecurityVFOREST are CUW18 families; version12 is rejected.
The M16C wire operations match between recovered versions. The native exception
cleanup differs: CUW12 clears progress silently, whereas CUW18's
`WritingErrorDispose` clears count, notifies, clears percentage, then notifies.
The optional progress observer retains that order. Normal progress similarly
publishes count then percentage, after the data write and before status/ACK
completion; it measures attempted work, not a confirmed ECU write.

Host limits are 64 MiB total image data, 255 selected CPU/region entries,
24-bit M16C addresses, complete 256-byte pages and 4096 status polls per M16C
operation. `VendorCAN` additionally bounds I/O count, retained response bytes
and absolute monotonic deadlines. Waits use an explicit injected provider.
Cancellation and expired deadlines take precedence over simultaneous I/O errors.
Native raw-status requests may be retried only according to their recovered
idempotent getter behavior; application data is never automatically resent.

Reports preserve uncertainty: `writer_completed` means the selected injected
flow finished, while `programming_completed` remains false and physical status
is `PHYSICAL_UNCONFIRMED`. Run the authored regressions with
`python -m unittest discover -s tests -p test_programming_m16c.py -v`.

Static anchors: M16C StartFlashWrite1160/PrepareRetry1f00/password2430/status27f0/
erase2980/write2b60/verify2e30/verify-status30e0; SecurityM16C main1200/password1f60/
status2320/erase2490/write2670/verify2940/verify-status2bf0; SecurityVFOREST main1200/
groups1ba0/write1cf0/verify1ff0/chunk22e0. Addresses are RVAs in their respective
CUW18 DLLs. CalibrationFile new-password3090/archive-password2ef0 and
CommonFlashWriter progress-disposal1480 are separate helpers. Original binaries,
decompiled material and real authorization inputs are not redistributed.

## Imported CUW arguments

`bind_m16c_context(container, node, observed_cids, selection, identity, ...)`
constructs immutable `M16CInputs` from a parsed CUW, its selected native catalog
row and an exact registered module hash/build. It performs no transport I/O.
The three supported module names are `TCUWCanM16CFlashWriter.dll` (CUW12/18),
`TCUWCanSecurityM16CFlashWriter.dll` and
`TCUWCanSecurityVFORESTFlashWriter.dll` (CUW18). A filename or a claimed build
alone cannot select a writer.

CPU images pass through the shared native S-record/VBF materializer. The current
CPU's catalog row supplies block sizes, start addresses, waits, flags and password
check bytes. Each of the three password-check parameter strings contributes its
first decoded `CBytes` byte; bounded multi-byte hexadecimal strings retain that
native behavior. M16C selects the first other CPU matching `ParentCPUTypeList` for
CheckID and communication. Its old password and LocationID belong to that parent;
the A0 password belongs to the current child. Both passwords require explicit
observed CIDs matching imported target records. Plain and security M16C do not
evaluate unused new-password metadata. SecurityVFOREST resolves its replacement
password only when the observed retry branch requires it. Its alternate CPU
catalog row is loaded only after the current memory descriptor fails the CPU gate.

`target_metadata[0]` is the raw physical target. On the last CPU write,
`target_metadata[1]` is the native functional finish target. M16C copies the first
two address bytes, including when a catalog selector returns a third protocol
addressing byte. The third byte is not a 29-bit CAN identifier. Missing required
addresses fail before I/O. The resulting `segments/options` feed `m16c_write`;
SecurityVFOREST instead supplies `image/vforest_options` for
`security_vforest_write`. Callers supply channels, lifecycle controls, progress
observers and the functional finish channel explicitly.

Runtime observations accept only `cpu_index`, `stage`, `recovery`,
`previous_retry_password`, `force_retry_password` and `previous_addresses`.
Authorization attachments accept exactly16-byte `nonce` and `authorized_key`;
when corresponding CPU metadata exists, the bytes must agree. Geometry,
passwords, CPU types and image substitutions are not observation fields.
`stage="prepare_retry"` is available only for the plain M16C export. Its bound
`wait_after_dummy_ms` comes from `WaitTimeAfterSendDummyData` and feeds
`m16c_prepare_retry`; binding recovery does not schedule a subsequent write.

Authored integration checks parse actual CUW envelopes and catalog tables before
exercising the raw writer bytes for every supported module/build, both parent
orders, the retry preparation and the VFOREST authentication/group path. They
prove software wiring with supplied observations, not vehicle compatibility or
physical programming.
