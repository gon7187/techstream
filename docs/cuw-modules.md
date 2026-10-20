# Static CUW split-module recovery

`scripts.cuw_modules` reads an original 2026 CUW DLL and its adjacent `<name>.dll._` companion. It reconstructs a PE **for static inspection** using Python's standard library. It does not load a PE, execute an entrypoint, resolve a host import, contact a service, or interact with an adapter.

```python
from scripts.cuw_modules import ModuleProvider, recover_module

provider = ModuleProvider("/path/to/your/original/CUWDLL")
metadata = provider.inspect("CUW.dll")
recovered = provider.recover("CUW.dll", cancel=lambda: False)
# Equivalent: recovered = recover_module("/path/to/your/original/CUWDLL/CUW.dll")
```

`RecoveredModule` contains `image` (inspection PE bytes), `source_sha256`, `companion_sha256`, `original_entry_rva`, `imports` (DLL name and symbol names/ordinals), and `restored_regions` (RVA/size pairs). The caller owns any decision to save these private bytes. Neither originals nor recovered vendor material belongs in a source distribution.

The inspection PE uses RVA as file offset, preserves the mapped section grouping, restores the original entrypoint/import and relocation directories, and decodes original import names. Import addresses remain unbound. Protector metadata and helper sections remain present. Its digest identifies this deterministic reconstruction, not the original pre-protection file or an executable native Linux implementation. The export directory is retained, including C++ data exports that can legitimately contain zeros.

The supported profile has input-seeded KONN records, feedback word decoding, ROL11/ROL13 regions, byte rotations, inverse expanded AES schedules, zero-IV AES CBC with unchanged partial-block tails, a custom Huffman/LZ table, and finite AL arithmetic programs. All schedules, tables, seeds and program bytes come from the user's own files. Only immediate byte arithmetic is interpreted; memory instructions, branches, calls and arbitrary native execution are rejected. Equal input/output-size regions skip decompression, matching the native wrapper.

Inputs and mapped images are limited to 64 MiB. PE sections, descriptors, tables, import strings, thunk counts, per-region scratch lengths, Huffman tokens and output lengths are bounded. Import entries/names have aggregate budgets; zero regions must be disjoint and fit a total mapped-image budget. Local reads use `scripts.local_files.read_regular`, rejecting FIFOs/devices before reading. Cancellation raises `InterruptedError`; malformed or unsupported profiles raise `ValueError` (missing inputs retain the filesystem exception). The provider accepts explicit basenames only. File format support does not imply permission or capability to execute Windows modules.

The supplied corpus contains 136 DLLs: all 132 DLL/companion pairs reconstructed successfully. Four unpaired libraries (`CalculationHmacAPI.dll`, `Newtonsoft.Json.dll`, `msvcp140.dll`, `vcruntime140.dll`) are ordinary separate dependencies and do not use this split format. Independent structural inspection found 1,019 nonempty export slots and 77,903 valid HIGHLOW relocation entries across the reconstructed pairs. Private evidence binds every result to both original hashes; no decoded keys or vendor bytes are included here.

The independent 18 comparison finds 73 shared module basenames and 59 additional names (including support/caller libraries). Thirteen of the 73 shared names have changed named-export sets. No strict normalized `.text` equality was found; retained protector grouping and loader extras mean this result establishes no semantic equivalence or incompatibility by itself.

Version compatibility must join the canonical outer filename, exact original and companion hashes, reconstructed bytes, and recovered exports/imports. A packed-stub digest cannot identify the inner engine's behavior. Shared export names with 12/18 establish an interface comparison only; changed code or additional engine families require their own native semantic review. This recovery removes the software-format barrier to that review and does not claim complete 2026 workflow equivalence.

Run the distributable authored vectors without any original artifacts:

```sh
python -m unittest discover -s tests -p test_cuw_modules.py -v
ruff check scripts/cuw_modules.py tests/test_cuw_modules.py
ruff format --check scripts/cuw_modules.py tests/test_cuw_modules.py
pyright scripts/cuw_modules.py tests/test_cuw_modules.py
```

The tests include independent FIPS AES vectors for 128/192/256-bit keys, CBC chaining, partial tails, authored format vectors, malformed/truncated input, bounded Huffman failure, arithmetic rejection, import-name decoding, cancellation, path rejection and FIFO rejection. Full original-corpus reproduction is private and requires the user's supplied originals.
