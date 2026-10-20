# Legacy executable programming controllers

Original CUW12 and CUW18 contain executable-local programming controllers in
addition to the independently selected DLL engines. A matching family name does
not establish equivalent phase ordering, communication, or recovery behavior.

The executable controller work remains incomplete. The shared module binds an
imported calibration to the standard controller class, retains normalized CPU
types, admits original executable bytes by SHA-256, and supplies recovered
password, recovery, message and typed exception helpers. `execute` dispatches the
five SIL families, EPB/EPC/Chassis/OldECB/Sonar/FC/Body/DSS1 and CAN EMPS/DCM/DH/FHI through their concrete controllers;
other families still fail explicitly. It does not yet dispatch the calibration
through all 21 concrete controller families. It must not be used
as a successful programming backend.

`bind_context` requires an actual parsed CUW, its selected catalog row, observed
identities and explicit original executable bytes. The source PE is admitted
before binding; original executable mode preserves raw LocationID text and omits
DLL catalog address evaluation. Executable preparation addresses use their own
reconstructed producer. `executable_cpu_type` preserves parser-produced CPU
ordering and historical type conversion. A class selection is not an executed
programming result.

Ordinary compaction now derives remaining rows from imported `NewCID` values and
the native exclusion vector. It keeps source CPU and image indices separately,
then reindexes the runtime CPU rows, CPU types, RAM overrides and write index.
Original18 format9 preserves its distinct first-matching file-group chronology.
The original12 parser admits metadata1–7/101/102;8/9 are rejected before binding.
Original18 admits1–9/101/103–107/206. Original12 metadata102 uses the restored
CPU-schema parser; its complete node-target/compaction flow remains unsupported.
The native factory bypasses this compaction for ordinary VBF images or its
separate `native_flag_6e4` mode. Native file-format03/04 conversion remains an
explicit unsupported producer. The complete UI/error-latch producer is still
incomplete, so this primitive is not a complete normal programming controller.

String matching requires an explicit original ACP, effective user locale and
`CaseSensitive` flag. The current port admits only bounded ASCII calibration IDs
under ACP1252/932 and locales0409/0411. Other native collation contexts fail
explicitly; Unicode case folding is not used as a replacement for Windows
`CompareStringA`.

Detected CPU types update separate native RAM state. Parameter access then
selects the corresponding supplied catalog row; it does not keep password
parameters from the previous CPU type. Controller constructors also retain their
actual channel read/send timeout snapshots separately from subsequent changes.
The manager's `retry_mode` flag remains separate from RecoveryInfo's `+5b`
`recovery_retry` and `+5c` `retry_input` flags.
The manager bytes `native_flag_ed5`, `native_flag_ed6`, `native_flag_ed7` and
`native_flag_ed8` retain original12 positions `+145`, `+146`, `+147` and `+148`. Direct writes through
these controller pointers do not write RecoveryInfo's `Writing` or
`WritingEndBlock` fields.

`target_indices` retains the native fixed four-DWORD array, initially all
`0xffffffff`. The selected password/calibration accessors read only its actual
bound target rows. `initialize_executable_targets` uses actual observed CIDs and
the imported target-row order to populate indices and the native NewCID exclusion
vector. Its return BOOL retains the opaque WORK `native_flag_2c` (18+2c/12+28);
no discovery-success meaning is inferred. Ordinary18 SCC/blank flags come from
the imported `KindOfCal` section. The VBF branch compares the first CPU's imported
ASCII `TargetHardware` rows exactly against the actual native manager string.
The host entrypoint currently admits up to99 `NN` rows; this is a supported-input
boundary, not a claimed native count limit. It reads
`observations['native_hardware_98']` (12+60). Its missing hardware producer fails
explicitly. This branch may select only target0 and bypass compaction/fallback;
paired-address selection and the hardware getter's publication remain open.

After compaction, `complete_executable_targets` appends the image-derived
NewCID/password to each unresolved CPU's native RAM table. Both original
constructors allocate 32 rows. At capacity the native append does nothing and
the caller still selects the existing final row. Appended RAM DWORDs remain
distinct from the version8/9 import rule that initializes target passwords to
zero. Restored targets are never regenerated or compacted.

A concrete `LegacyRecoveryStore` may be attached only when build, calibration
digest and shared state identity match. Password/error helpers then use its full
native Save and active latch. The old `persist` argument applies to unbound
primitive checks; a bound store controls persistence through its native latch.
`begin_writing` belongs only at a source-proven native begin call, not every
controller pointer assignment that happens to set a BOOL.

Raw message primitives preserve every `PASSTHRU_MSG` field, including `RxStatus`.
Native J2534 errors retain both the signed exception category and the original
driver status. GUI callbacks copy the recovered fields or invoke the selected
completion/error handler; they cannot supply programming success.

`legacy_recovery_password_state(writing_end_block, native_mode_78, previous)` implements
CUW12 VA `0x444ecc` / CUW18 VA `0x46cab0` (RVA `0x44ecc` / `0x6cab0`). The argument
is the actual caller-supplied BOOL: EPC passes manager `native_flag_ed6`, which is
separate from saved `WritingEndBlock`. A true argument sets the state true. A false
argument toggles the previous state only when native field `+0x78` equals seven;
otherwise it clears the state. `+0x78` is the DWORD holding the native error
category copied by the recovered typed exception handlers. This state is not a
block cursor.

The native method writes through controller pointer `+0x8c`, then persists the
result using the native recovery setting writer. The target BOOL is `UseNewSoftwarePassword`, subsequently saved by
CUW18 `0x42ed0c` to recovery field `+0x59` (distinct from
`WritingEndBlock` at `+0x5a`). The pure reducer returns the password
state for its caller; it performs no file access, device access, or authorization.
The saved recovery parser and original source/device association live in
`scripts.programming.bind_native_saved_recovery`.

Source identities (SHA-256):

- CUW12 executable: `9a5d508691edb697b7d5fd42dc4495b4ad9e4ffc64eccf518da2e5ff2c47476d`.
- CUW18 executable: `97f7b9302a6090e2715ca6c9713aecc73404d6c0f75aede2dd52f09bd201074b`.

Static PE class tables independently establish 23 matching controller classes in
each executable: 21 concrete `Execute` implementations and two abstract bases.
This is an inventory, not an implementation-completeness claim. The common
recovery virtual slot is `+8`; `CTechVimFlashWriter` inherits a different base and
does not have that slot. Neither an RTTI name nor a DLL profile is accepted as a
substitute for reconstructing each concrete controller.

Run the current state-control checks with:

```sh
python -m unittest discover -s tests -p test_cuw_legacy_engine.py -v
```

No vendor executable has been run. Physical behavior is `PHYSICAL_UNCONFIRMED`.

The Airbag route requires the original typed CGW startup/recovery producer for
accepted transfer retry. The modern CGW online-key sender remains separate.

`require_executable_standard_getter(context, "CSilCIDGetter")` reads the actual
`FlagToUseCIDGetterAndFlashWriterDLL` catalog value before the independent local
getter factory. Missing/empty values retain the source false initialization.
The host accepts complete bounded decimal LONG spelling; unsupported native
`strtol` spellings fail explicitly. Specific SIL getters remain separate.
`publish_executable_sil_cids` requires the issued result and retained channel,
fresh target RAM and the zero-status, nonterminated normal branch. It publishes
the actual CID list and retains its native status result without writer callbacks.
The outer manager error/termination latch remains unsupported.

`discover_executable_mmc_cids` requires the actual original MMC getter module,
catalog DLL switch/name, and caller-owned `VendorP5Channel` with its source
timeout profile. `publish_executable_mmc_cids` publishes the actual `f111`
hardware identifier and `f188` software CIDs into fresh target RAM. The query
helper preserves host exception identity; both original-build controls cover
that boundary and retain the native hardware prefix on a second-query fault.
Full caller lifecycle acceptance remains open.

`select_executable_cpu(context, index)` reconstructs one factory selection from
the retained WORK and runtime index (12: `44e0ec`; 18: `479b20`). It preserves
compacted source/image mappings, first WORK, target/password RAM and the shared
saved recovery cursor, while capturing the live channel read/send timeouts.
It does not advance the saved cursor or execute a manager CPU loop.
The first native factory captures CPU0's type into the retained manager string
before its compaction call (12: `44bff4`, manager `+150`; 18: `47623c`, `+ee0`).
`executable_original_cpu_type` reads that string after factory admission; later
CPU mutations, compaction and indexed selection preserve it.

`connect_executable_context(context, io)` ports manager12 `44bc58` /18 `475db4`
for admitted standard contact types. It calls the actual channel Connect and
sets the shared read timeout to 1000. Its CJ2534 handler retains signed category
and raw driver status in manager RAM (`native_value_e60/e64`, 12 `+d0/d4`) and
rethrows the same exception; host errors propagate unchanged. The GUI branch
choosing when to call this method remains open. Constructor selection must
follow connection to capture the current channel timeouts.

Selected `TargetData` uses the original INI hexadecimal decoder: zero to eight
hexadecimal digits, with empty or missing values producing zero. Signs,
prefixes and nonhexadecimal input are rejected. Appended RAM passwords still
take precedence; metadata8/9 keep their separate zero-initialized import branch.

The original executable LocationID accessor reads raw imported text through the
source zero-padded native byte-array decoder, including short and empty values.
It does not consume the strict DLL catalog field. CCan/P5 dispatch is candidate
integration plumbing; true runtime Recovery entry remains explicitly unsupported
until the actual UI transition and restored manager state are joined. Portable
regressions do not close the full manager or independent source-review gates.
