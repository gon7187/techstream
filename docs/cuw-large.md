# CUW2026 large-file source descriptors

`scripts.cuw_large.native_large_cuw_2026(path, cancelled=...)` validates a regular
`.cuw` file of 0x12c00000 through 0xffffffff bytes. The extension is case
insensitive. The native container version must be 12. Attached metadata must be
107, 209, or 500 with the first literal `Protocol=` value equal to `02`.

The parser checks signature, exact declared file size, original SHA256, the CRC32
of original bytes18..EOF, record framing and every payload CRC. Original files
are never rewritten. Native16030 retains the original record payload length in
archive GetLength even when GetData is the144-byte descriptor; these values are
deliberately separate. Memory usage for source reads is bounded by 0x500000 bytes;
metadata is limited to1MiB as an explicit strict host parser policy. This is not
an arbitrary image-size limit. Large binary images stay backed by source spans.

The frozen `NativeLargeContainer2026` contains the ordinary attached
`CalibrationRecord`, original digest, declared byte count and `LargeRecord2026`
records. Each large record exposes the original record offset/header/CRC, a
`span=(source_offset,length)`, and the native0x144 descriptor. Descriptor bytes0..3
hold the metadata version, bytes4..0x107 hold the NUL-terminated original absolute
pathname; DWORDs at0x108/0x10c are inclusive original payload start/end.

`materialize_large_record_2026(container,record,addresses=(a,b,c,d),binary=...)`
reconstructs native2b460 descriptor fields from actual backing bytes. Binary
materialization retains the exact original starting offset. S-record scanning
validates count/checksum/termination-width/S5 count and records the first source
position meeting each enabled address threshold. Third/fourth groups belong to
metadata500. DWORD pairs110/114,11c/120,128/12c,130/134 retain address/source
position;118/124 retain the preceding-S1 flags;138 is the binary flag. No inferred
contiguous geometry or artificial address-gap allocation is introduced.

`validate_large_container_2026`, `validate_large_record_2026` and
`validate_large_materialization_2026` require exact producer-issued identities;
constructing or replacing a frozen dataclass does not authenticate it. The source
inode is pinned with O_PATH before opening for bytes, so FIFO/device paths are
rejected without opening their device operations. Every read verifies original
fd and pathname identity, size, nanosecond modification/change timestamps and
short reads. Containers own their descriptor and must be closed or used as a
context manager. Replaced, modified, truncated or closed sources fail explicitly.

`LargeSource2026(container)` is an absolute original-file bounded slice view for
native P6 streaming windows. `record.read(offset,length)` is relative to its
payload, and `record.iter_chunks(cancelled=...)` streams original bytes. The
materializer's generic `iter_payload()` provides binary chunks or S-record
(address,data) rows; P6 uses its own native block/counter/zero-tail algorithm over
the original source view rather than this convenience iterator.

Evidence comes from static CUW.dll2026 recovered functions29a70,29cc0,2a050,
2a2e0,2a480,2a7b0,2aa90,2aad0,296a0,2b460,2bc70,32130,36f30. The published tests
create synthetic sparse300MiB files with real framing and checksums, never OEM
payloads. The module executes no vendor PE, network or hardware operation.

Validation: `python -m unittest discover -s tests -p test_cuw_large.py -v`.
Native metadata/archive/P6/engine consumer integration is owned by leaves47/32/36;
this document alone does not establish their completion or physical equivalence.
