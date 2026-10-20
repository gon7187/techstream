# Legacy TSE conversion

`scripts.tse_conversion.decode_legacy` reads the original `.AD` type-3 and
`.DC` type-6 input streams used by ConverterTSE_DT 3.0.10.0. It returns immutable
bytes and native collections, retaining the entire source, metadata, time bytes,
unused fields and trailing data. It does not modify the source file.

```python
from scripts.tse_conversion import decode_legacy

legacy = decode_legacy(source_bytes, extension=".AD")
assert legacy.source == source_bytes
```

`convert_legacy` converts those real streams into complete native TSE files:

```python
from scripts.tse_conversion import convert_legacy

output = convert_legacy(
    source_bytes,
    extension=".AD",
    codepage="cp1251",
    caller_time=captured_four_dwords,  # exactly 16 bytes, in original order
    decimal_point=b".",
)
```

The caller supplies its Windows thread ACP and the original four DWORD date
arguments. The converter does not substitute the date stored in the input.
The decimal-point default is an authored C-locale policy; another original
process's formatting requires its actual first `localeconv` decimal-point byte.

The converter selects the first native function `1` or `0x10`, converts DTCs,
ordinary freeze frames, multi freeze frames and detailed freeze frames, and
builds the native ECU groups and final index. AD records retain their original
input ordinal in `Data N` even when preceding ECUs are skipped. DC produces
`Data 1`. Header file type is `8`, version `0x1013`, language `3`, mask `0x25`,
with features `0x2711`, `0x2713`, `0x2716`. IniCarInfo, ConfCarInfo, ECUInfo and
DTCMon have independent versions `0x1000`, `0x100f`, `0x1003`, `0x1007`.

Separate source-preserving readers and conversion primitives are available:
`decode_legacy_object`, `convert_legacy_signal`, `convert_legacy_ecu_dtcs`,
`convert_legacy_dc_dtcs`, `convert_legacy_ecu_freezes`, and
`convert_legacy_dc_freezes`. `LegacyNode.member` uses the original object's
member offset, not a wire offset.

The original writer duplicates a prefix containing metadata and the first
buffer, then stores a compression flag, a length, and the complete logical
stream. The reader follows the native raw and compressed branches. In the raw
branch, the stored length is retained but does not constrain the logical stream,
matching the original reader. The compressed branch uses the native 4096-byte
LZSS dictionary and bytewise-OR checksum. A final incomplete token can terminate
safely without producing output. The declared decoded prefix and the actual
allocation are distinct: additional decoded bytes are allowed only within the
original allocation and remain outside the logical prefix.

Native writes beyond the allocation, reads from an uninitialized dictionary,
and checksum reads from uninitialized output raise `TSEConversionError`.
Host limits are 32 MiB per source/allocation and 100,000 aggregate collection
records; these are host resource limits, not original device limits. Cancellation
is checked during field reads, record collection, decompression and checksum
work. No original executable or DLL is loaded or executed.

The original converter dynamically requests `_ConvertData@20` from
`CommandAPI.dll`. Version 12.2.0.9 supplies it. Version 18.0.0.3 supplies
`_ConvertData@28` instead, and the converter's missing-symbol branch returns
`0xc0070102`. Substituting the different export is not supported by the source
proof. Successful conversion must bind an explicit compatible scalar provider
and an explicit source Windows thread codepage. Business helpers at RVA `d940`
and `16ae0` call `WideCharToMultiByte` with literal codepage `3`
(`CP_THREAD_ACP`), flags `0`, and NUL-terminated input. The output header's
language word is not a codepage binding.

The complete converter binds the independently recovered original-12 scalar
provider in `scripts.legacy_scalar`. Wide input strings are converted through
their first UTF-16LE NUL. Text outside the supplied codec's exact repertoire
fails explicitly: Windows best-fit substitution is not guessed. An unterminated
wide string fails instead of reading past its stored allocation.

Constructor joins determine receive-object layouts: shared `Read50cd0` is a
list reader for these classes, not a CCmdBuffer reader. Saved replies contain
lists of DTC, Func, Detail or Freeze objects according to their original
constructor vtables. Shared signal conversion drops the second legacy string
and leaves the output display-choice list empty, matching the original writer;
normalized choices are used by the scalar evaluator. Raw DWORDs and value flags
are retained alongside their formatted byte strings.

DTC ordering preserves the original selection-sort swaps, including its
nonstable treatment of equal IDs. A position heap avoids quadratic host runtime.
Duplicate IDs retain the first resulting code/name, combine status words with OR
and concatenate detail records. AD detail matching uses the first matching
DetailList. A later missing match retains the native previous frame ID while
clearing the signal list. DC checks a full DWORD for summary selection, but its
five fixed slots test the low flag byte; its temporary flag storage is twenty
bytes. Inputs that would overwrite that storage fail. Native detail slots remain
numbered `1..5`, independent of stored raw IDs.

Full conversion has an additional 4,096-ECU index budget inherited from the host
native-header builder. Final index offsets are computed from actual serialized
fragments. Independent static review confirms that the original `e7c0` calculator
uses `0x30` per ECU while its index writer emits thirteen DWORDs (`0x34`). The
host deliberately corrects those offsets; byte-for-byte parity with that OEM
index defect is not claimed.
Unrecovered DTC list selectors outside `1`, `2`, `4` raise an error rather than
reusing a previous row's native temporary state.

Source pins and native locations:

- ConverterTSE_DT: SHA-256
  `77c477bc6ab72f58e599147e306ac297e3836600b49ab726c59b8dfa4662765e`;
  entry RVA `de50`, AD reader `17970`, DC reader `17ea0`, DC groups
  `184e0`/`185b0`/`18610`, metadata `1a190`, outer reader `198f0`, writer `19a30`.
- CommandDataLibLegacy: SHA-256
  `53e7fe2352e3002e4758cef49ea8155d63e6536bd2eeecae23ea3f468835d15b`.
  This differs from the main CommandDataLib deployment lane.
- DataCompress_DT: original-12 SHA-256
  `95a2948e7b3a02280e63fe5df075ae28ba3a678a091c4b22b359c2075c83f879`,
  original-18 SHA-256
  `469d28871f46c291e8772576965c902ee2996246e9765e0c409e042bcda4eed1`.
  Algorithm bytes at RVA `1000..1f70` are identical; decoding core `1bd0`,
  checksum wrapper `1e50`, export `1f20`.

Full AD/DC controls include nonempty detail summaries and detailed signal values
through the actual saved-TSE report consumer. Independent source review and
additional all-family consumer controls are recorded in
`analysis/evidence/no-car-110/review.md`.

Run the authored literal, collection, termination, truncation, mutation,
allocation and cancellation controls with:

```sh
python -m unittest discover -s tests -p test_tse_conversion.py -v
```
