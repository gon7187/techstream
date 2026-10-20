# Original CUW12/18 recovery persistence

`scripts/cuw_legacy_recovery.py` implements the original executable's recovery
state and file representation. It does not execute an OEM image, contact a
vehicle, open an imported pathname, or attest a recoverable ECU checkpoint.

The source map and static assembly slices are in
`analysis/evidence/no-car-112/`. CUW12 uses initializer `416738`, begin-writing
`416ea8`, full Save `418200`, and encoder `418fe4/419070`. CUW18 independently
uses initializer `4296c4`, begin-writing `429ff4`, full Save `42eedc`, and encoder
`430a8c/430b18`. Live string slots are initialized from PE literal strings; their
zero-filled on-disk storage is not interpreted as an absent key.

Both versions serialize, in native order: source, selected device, CID count and
CID vector, VIN, CID-node count and byte vector, repro-check byte, central-GW
BOOL, CPU index, Writing, password choice, end-block BOOL, and PassThru error
byte. CUW18 then writes assembly-number and update-availability BOOL vectors.
CUW12 has neither latter vector in its native schema. Unknown imported keys and
sections remain preserved instead of being silently deleted.

`LegacyRecoveryStore.from_context(context, source_path, selected_device,
original_data=None)` requires an actual source-bound executable context. Its
`state` is the identical `context.state` object. Imported source/device labels
must exactly match the supplied labels; CPU selection must belong to the actual
imported context. Importing Writing=true leaves the persistence latch inactive.
Plaintext imports remain plaintext; native encoded imports retain nibble-text
encoding. Unchanged canonical encoded buffers retain their original noise bits;
changed buffers use a valid zero-noise nibble encoding. No CUW2026 recovery codec
is used.

`set_field(io, key, value)` supports the recovered CPU-index, Writing, password,
end-block, and PassThru-error setters. They mutate shared RAM first and then
perform complete Save only when persistence is active. `RetryMode` changes the
recovery object's +5b field and `RetryInput` changes +5c without Save. Both are
separate from the executable manager's `retry_mode` flag. Writing, password
choice, and end-block are three independent BOOLs.

`begin_writing(io)` first prepares the native path when +5b and +6c are false,
then sets Writing=true, performs full Save, and only then sets +6c=true. A Save
exception or host cancellation retains Writing=true and an inactive latch.
Already active setter failures retain both the RAM mutation and active latch.
The native path is `dirname(executable_path) + "\\Save"`, optionally followed by
`"\\" + firstName + "_" + lastName`; the original calibration is copied there
and its copied label is serialized as SavedCalibrationFilePath.

Path inputs are explicit `context.observations`: `recovery_executable_path`,
`recovery_user_enabled` and, when enabled, `recovery_user_name` containing the
actual original profile getter's result. A missing path/profile branch fails
before setting Writing. The store makes these bounded primitive calls:

- `recovery_path_exists(path=...) -> bool`
- `create_recovery_directory(path=...) -> None`
- `copy_recovery_source(source_path=..., destination_path=..., fail_if_exists=False) -> None`
- `write_recovery_bytes(data=complete_buffer) -> None`

The write provider supplies storage only, never a recovered Save result or ECU
success decision. `write_recovery_file(explicit_linux_path, data)` is the atomic
Linux byte adapter: a sibling temporary file, flush/fsync, and atomic replacement,
matching the existing workbench writer pattern. The caller explicitly binds the
Linux destination; Windows source labels are never automatically opened.

Validation: `python -m unittest discover -s tests -p test_cuw_legacy_recovery.py -v`,
`ruff check scripts/cuw_legacy_recovery.py tests/test_cuw_legacy_recovery.py`, and
`pyright scripts/cuw_legacy_recovery.py tests/test_cuw_legacy_recovery.py`.
Source-derived file/lifecycle tests are offline. Hardware remains
`PHYSICAL_UNCONFIRMED`.

## Terminal cursor and native finish

A contiguous CPU table of size N admits WriteCpuIndex=N as a terminal RAM/save
cursor. Importing N as a selected/resumable CPU remains rejected: no CPU occupies
that position. The manager's typed state admits terminal128 independently of
selected-CPU access checks.

`finish(io)` follows original18 `42de54 → 42ff24` and original12
`417ddc → 418e8c`. It calls `delete_recovery_file(path=..., owned_output=...)
-> bool` first for SavedCalibrationFilePath, then for RecoveryInfoPath (+70),
then resets recovery RAM. Native false deletion returns are ignored. A thrown
exception or host cancellation stops immediately; previous deletion remains
observable, subsequent deletion/reset do not occur.

The reset empties source/device/VIN, CID/node vectors, repro/GW/CPU values,
Writing/password/end-block, recovery retry/input and the active latch; it restores
PassThruErrorCode=99. Original18 also clears the assembly-number and availability
vectors. It preserves the original source label (+60) and RecoveryInfoPath (+70),
and does not reset unrelated manager flags. It performs no Save. Normal caller
terminal setters can subsequently leave Writing=false and WriteCpuIndex=N in RAM
without restarting persistence.

`owned_output` is metadata only. The store never opens/unlinks a Windows label.
A Linux provider must independently map its own output registry, verify the
current output inode and directory, and protect supplied original paths and
inode aliases. The flag alone never grants an unlink. An original source label
that aliases the copied native destination is explicitly not marked owned. This
module supplies no direct Linux deletion adapter; authored injected providers
exercise the complete native call chronology without deleting arbitrary files.
