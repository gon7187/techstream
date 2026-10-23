# CUW2026 public file services

`scripts.cuw_file_services.read_reprogramming_data_file_2026` composes the actual
2026 `1005ccf0` output structures with the calibration parser and the engine.
The public region argument is one based; parser metadata receives `region - 1`.
Modes other than 1 (normal) and 2 (temporary recovery inspection) return 1001
with unchanged immutable output buffers and cleared archive flags.

Normal plain-CUW, JSON-list and archive input bind the engine through an issued
source set, then read `CalibrationType` from the actual
profile and `EngineTypeFlag` / `FlagToOutputAllAttachedInformation` from the
bound General source. Recovery mode creates separate metadata and leaves the
loaded engine source intact. Recovery sets both header flags to one, clears the
compliance/family fields, and preserves each CPU row's trailing calibration-type
DWORD. Immutable header/CPU results preserve caller padding and extra rows.
CPU string offset zero is **NewCID**, not the image filename.

Valid dates require an explicit captured native OS formatting primitive. It
receives the exact parsed `(year, month, day)` and its result is issued through
`native2026_date_presentation`, bound to that parser object and raw date. No
Windows locale format is guessed. Empty/invalid dates use the parser's native
empty result. No OS formatter is invoked for those dates.

`admit_file_sources_2026` reconstructs these input-producing operations from
captured file bytes, without writing extracted OEM content to disk:

- `46de0` / `4c650`: comma-delimited `.json` file list, first/last bracket
  removal and quote removal. The native algorithm does not trim whitespace or
  interpret JSON escapes. Missing paths fail; supplied file bytes are parsed.
- `47390`: `.cuwc` attached INI requires a positive calibration count and
  nonempty `CPUxx.NewCID`. Extracted `.cuw` filenames match NewCID prefixes;
  collisions and unmatched filenames fail. Missing entries are skipped, as in
  native output-vector construction.
- `46010`: `.scuw` extraction reads `Setting.ini` with
  `[DeltaReproCalFile] FileNum / FileName1..N` and
  `[WholeReproCalFile] FileName`. The issued object preserves actual delta FILE
  metadata, the whole source, and each group span for later output collapsing.
- Actual multi-file metadata versions 10/12 are rejected (`0x318c`). Mixed
  Ethernet/unsupported contacts fail (`0x31a2`). File capacity is 16.

For a cold raw admission, the same walk also issues a private immutable wait
timing trajectory on its `FileSourceSet2026`. It records source bytes, parsed
metadata identities and literal operation order only; it does not carry
precomputed wait values. Issuance requires the engine's exact frontend catalog
and its General table to be bound already. JSON keeps each encountered SCUW
`46010`/whole `32130` before the flattened `43cd0` files and ends with
`32ff0(0, TRUE)`. Direct SCUW keeps `46010`, PARTS `43cd0`, whole `32130`, and
the separate final whole `41940`. Direct CUWC keeps extracted-member `43cd0`
and ends with `32ff0(0, FALSE)`. Ordinary direct CUW is a current-only route
and receives no timing capability. Derived file sets retain the same one-use
capability; `bind_file_sources` consumes it under the engine lock after host
validation, immediately before the first source mutation. Native writes
already reached remain visible if a later step fails.

Known native admission rejection branches issue error 6 with the original
`CPassThruCtrlr.cpp` location from authenticated PE RVA `7c810` and their native
line value. The public wrapper returns 1001 and logs `1(6)` while preserving
the untouched caller outputs. Host bounds, malformed binary guards and
cancellation retain their own exceptions.
The 260-byte Win32 profile string buffers retain at most 259 Latin1 bytes for
SCUW delta/whole paths and CUWC NewCID keys. Empty numeric counts produce zero.
General Win32 profile quoting and nondecimal integer conversion are still open;
the host admits bounded decimal count strings and rejects other conversions
explicitly. This boundary is not claimed as complete Win32 INI parity.

A registry prevents callers from constructing or copying an accepted source-set
object. Its fields and archive status come from parsed input, not caller flags.
ZIP extraction uses the existing bounded primitive and rejects unsafe names,
symlinks, duplicate names, encrypted members and oversized expanded content.
Large plain input can use `LargeSource2026`; no whole 300 MiB read is required.
Normal success transfers the large container's lifetime to the engine; recovery
inspection leaves ownership with the supplying capture.

`compliance_2026` implements `4a6f0`: for P5-Unified, only the first gateway DiagID per node
is compared with `0751`; other contacts test **format version** 10 or 12.
`calibration_family_2026` implements `4ad60`'s single-file format/family check
against **Vehicle.CANIDTx_Phys_USDT** (`0790` / `0791` / `0792`).
Neither ECU kind nor a CPU calibration target substitutes for these source
conditions.

`file_logger_2026` issues the actual `SetLogFunction` adapter from the exact
engine PE and constructor log-ID table. Its explicit captured ACP converter
feeds a notification-only sink; no OS encoding is guessed. The installed engine
logger receives context 300 and source order: ContactType 1003, KindOfECU 1002,
each first output FILE CPUType 1001, then persistent native delta-active 2016.
Native error handling emits 3002/severity 2 with `1(error)` for PassThru and `3`
for generic/int lookup failure. Host sink failures propagate unchanged. Native
NULL disables callbacks; it does not create a fabricated successful event.

## Remaining source closure

This work is not a claim of complete `ReadReprogrammingDataFile` equivalence.
The public wrapper now consumes actual admitted multi-file and delta sources,
binds their real engine context, flattens whole/group CPU output and reads actual
General/profile tables. Recovery SCUW uses `native2026_recovery_header` over the
original header prefix, with format 500 and the actual configured CPU capacity.
Native integer lookup faults retain partial output writes and status 1001;
PassThru faults 9999/1021 map to 2001/1002, as recovered from catch ASM.

`FileSourceSet2026.after_group_reset(..., worker=actual_worker)` produces native
mode2 `4b900` FILE replacement views. Private lineage proves the exact old
source and worker that issued each reset; arbitrary admitted sets and dataclass
copies are not accepted as reset results. The separate mode1 mapped factory
requires the worker's authenticated judge origin. Its direct zero-map sibling
requires the canonical current A48 view and the worker's direct origin receipt,
then issues a new no-table version retaining that runtime A48 metadata and the
original output/recovery descriptors. Neither mode1 factory is a public source
selector or a replacement for the engine's single authenticated publisher.
A mapped JSON group replaces its member span with the same whole pointer; the
source pointer-map entries remain distinct from the current FILE indices.
Initial `32ff0(0,true)` selects the whole pointer whenever table slot zero is
mapped. `execution_files` describes the initial execution lease, **not** a
replacement for `3ec30`/`48e80` traversal over the actual FILE table and captured
per-FILE identifier vectors.
`table_files` and `table_file_names` expose the actual D55C/D59C vectors.
An ordinary CUW or typed large/USB source retains one admitted current lease in
`files`, while its native table remains empty. Lists, archives and initial node
splits retain their real FILE slots.

Phase6 ordinary FILE pairs with identical first-node DiagID and LogicalAddress
use the actual `4a850` / `19c00` / `19910` producer. The resulting FILE retains
an issued `NativeCompositeSource2026` proof and both original archive owners;
it is not exported as an invented binary CUW. Native merge collisions follow
the generic exception path and preserve the caller's untouched output buffers.
The native persistent delta flag controls whether this merge branch runs.
Mapped Phase6 files also follow `67a60` / `67c60` ordering: the first-node
DiagID (fallback LogicalAddress) determines the key bucket, unmapped Phase6
files insert before that bucket's original anchor, and mapped delta members
retain their actual pointer-map identities. `68190` checks same-address runs
using their whole-file pointers through the pure `19c00` precheck. Public tests
cover reordered FILE indices, whole-file output and native collision failure.

A first ordinary `Ethernet & P5-Unified` load projects its actual 2–16 nodes
through `32130` / `19300` / `13040` / `173d0`. Each FILE retains a registered
`NativeNodeSource2026` and the original parent owner. The repeated source names
remain exact, per-node ContactType selects each real profile, and DB08 suppresses
the public multiple-files flag. The issued set also retains `admission_source`
and its digest separately from selected or derived metadata, including the
original `.scuw` archive whose selected current FILE is its whole calibration.

Still active: repeated composite context capture/restore (`49c70` / `4a0b0`),
prior runtime CID/address capture consumed by `20f20`, complete delta reset
joins, recovery replay through distinct `62f80`, and the complete lifecycle of
the D2A1 producer used by native pre-read cleanup. Full cleanup diagnostic `41eb0` also needs its
actual owned global-state producer.
Unimplemented admission branches fail explicitly.
Recovery source rows are captured before FILE transforms: JSON keeps its
original `local134` names and bytes, including SCUW archives; CUWC uses extracted
file rows; direct SCUW keeps the original archive with multi-count zero.
The issued `recovery_sources()` and `recovery_index_for_metadata()` expose these
rows and original FILE+50 ECIndex proof. Phase6 retains the left FILE index;
initial composite nodes retain constructor index zero while their repeated
original filenames produce the native multi-count.
After `4b900`, the worker's narrow retained-clone provider supplies any actual
`34e10` cached selection. The A48 view remains original until actual `36800`
performs the source-gated rebuild: the first CPU image name must lack literal
`.vbf` and the indexed-image vector must be empty. The service does not initiate
that rebuild. It validates issued runtime metadata through
`native2026_validate_runtime_metadata` and requires the same whole FILE container
and digest; selected, A48, table, collection
and output views then share that exact metadata object. The worker separately
restores the authored target/CID/companion/count vectors through `47e60`.
G2/G3 stay open.

The public wrapper also accepts an issued `NativeUSBSource2026`, including a
pinned regular file from `native2026_usb_file_source`. Its prefix is parsed
without materializing the full USB file; the bounded trailer span retains its
actual full-file digest, CRC and free-space requirement. Mode 2 retains the
caller lease. Successful mode 1 issues a typed single-file source descriptor and
transfers ownership through `bind_file_sources`; failed binding retains the
caller lease. Ordinary replacement and engine close
invalidate transferred spans. Public checks cover these lifetime transitions.
The same source descriptor joins fresh recovery binding for actual large and
USB originals after `38880` reset. Its recovery rows retain the exact pinned
view. Public tests trigger the real notification writer and verify the saved
full-file identity, including a streamed 300 MiB large original and original SCUW
archive bytes distinct from the current whole-calibration digest.

`FileSourceSet2026` also issues immutable `NativeFileView2026` and
`NativeFileGroupView2026` values for the current table version. Descriptor
identity is cached on that exact source set: plain and part views name real
table slots, while a whole view names its group's current start. A current-only
source has an admission view of kind `none` with no table index; its metadata
still describes the actual current FILE. Validation rejects copied, stale and
cross-version descriptors. The authenticated mode1 judge-reset seam is
separate from the existing mode2 retry producer and requires the worker's
exact native judge-origin receipt; the positive mode1 source producer is owned
by the later getter/judge stage. Mapped table views follow the identity pointer
map after group compaction; original group ranges are consulted only for direct
zero-map archives. The mode1 source transform clears the FILE table for that
same zero-map branch while selecting the source-issued whole FILE.

Cold C44 timing admission captures the raw 43cd0 table and initial JSON/CUWC
32ff0 source before the Phase6 transform. The same one-shot admission carries
an immutable Phase6 transform: successful merge edges preserve original raw
slot ordinals, exact input metadata/source identities, and each returned
composite lineage. The post-4a850 table is separate from the optional mapped
post-67c60 table. Only the source-issued mapped branch runs 68190 and a second
32ff0 selection; plain Phase6 keeps the initial selection and timing vectors.
The admission also owns the exact registered FILE-table derivatives for the
initial pointer, post-4a850 table, optional post-67c60 table, and final pointer.
The engine publishes each derivative only at its native source point, so a
failure after a reached pointer or table store leaves that precise table
visible while the admission remains sealed from retry and downstream consumers.
Historical pointers are admitted only through their identity in that same
one-shot table-stage payload.
The raw consumer tests fault the initial JSON selector, direct SCUW WHOLE
selector, and mapped second selector at their actual source points. They also
fault the host persistence bind after a completed no-map Phase6 transform;
each case checks the retained canonical stage, sealed retries, and close
cleanup. A wrong-stage publication and replayed consumed stage are rejected
without changing the published tuple.
The helper does not replay the merge producer or claim parity for native late
allocation, payload-transfer, rebuild, destruction, or partial-compaction
faults.

Run the authored producer/consumer checks:

```sh
flock -x runtime/no-car-next-20261022/unittest.lock \
  python -m unittest discover -s tests -p test_cuw_file_services.py -v
```

Tests use authored binary containers and archives, with a static authenticated
CUW image only for engine identity. No OEM PE execution, device access, car
communication, Wine or network service is involved.
