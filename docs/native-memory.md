# Bounded native pointer storage

`scripts.native_memory.NativeMemoryArena(source_sha256, owner, limit=16 MiB,
cancelled=None)` stores virtual uint32 pointers in Python. No process pointer,
DLL, `ctypes` dereference, transport, device or licensed service is used.

- `alloc(size)` returns a distinct, zero-filled positive allocation.
- `read(address, size)` / `write(address, bytes)` permit interior addresses only
  when the entire span fits one live allocation. They never combine neighbors.
- `realloc(base, size)` moves and preserves the prefix, zeroes growth and
  invalidates the old address. Allocation failure retains the original block.
  `realloc(base, 0)` frees it and returns zero; `free(0)` is a no-op. `alloc(0)`
  is rejected rather than inventing a platform-specific zero allocation.
- `borrow(base)` leases the actual mutable bytearray, without copying. A Python
  memoryview prevents resizing; pins prevent free/reallocation/arena close.
  Interior bytearray leases are rejected because slicing would copy storage.
- `assert_owner(source_sha256, owner)` checks exact source identity and object
  identity. Source, owner and budget are read-only public properties.
- `free(base)` invalidates and zeroes storage; `close()` releases all unpinned
  blocks. Both remain available after cancellation. Other operations check the
  injected cancellation flag and raise `InterruptedError` before mutating state.

The live budget is at most 16 MiB and 4096 allocations per arena. Reallocation
can temporarily retain old and new backing, bounded by twice the byte budget.
Pointers are reserved process-wide, with gaps, and never reused, so stale or
cross-arena numbers cannot accidentally resolve to another allocation. The
lifetime address reservation is bounded by the uint32 address space: exhaustion
raises `MemoryError`. Bytearray references must not be used after their lease;
escaped Python views see zeroes after free and cannot resurrect a logical pointer.
These are explicit host memory policies, not claims about OEM allocator behavior.

## Exact receiver producers and consumers

`scripts.script_libraries.NativeProcedureLibraries` checks original caller and
engine image identities through `UtilityImportBinding`. Its
`borrow_receiver(arena, base)` returns a `NativeReceiverProjection` only when the
arena is the selected engine's `native_memory`, its source matches that engine,
and its owner is the context's `native_memory_owner` (the context itself).
The projection exposes the same live `buffer` and source-reviewed `call_method`.
Closing a projection while the engine worker runs raises `BufferError` and
retains its pin. Finish or explicitly cancel the worker, then retry `close()`;
no business cancellation is manufactured by receiver destruction.

Three source-fixed producers use the actual original18 large TY caller
`IT3UtilityTY.dll`, SHA256
`d9fc5bb2f9d7bd583a9fbe317c3d45a2ed4eb60b210ea9623a8230f3baec1e8d`,
and engine `UtilityEx2TY.dll`, SHA256
`79fc495c68eb099a7ebc0d1eefe0eafd80101ac0bc09a58d3f603ed556c84762`:

| Producer | Native source and stored fields |
| --- | --- |
| `create_awd04_receiver()` | Initializer RVA `0x99710` zeros 12 DWORDs at receiver `+0xe8`; the resulting buffer has 48 bytes. Destructor `0x99670` frees its nested pointer at buffer `+0x24`. |
| `create_tpw03_receiver()` | Initializer `0x57bf0` creates seven inline descriptors at buffer `+0x24`, stride `0x14`, and a write descriptor at `+0xb0`. Eight masks receive separate arena allocations. Descriptor IDs, indexes, masks, lengths and zero selection fields follow the native literals. Destructor `0x57b40` frees all eight mask pointers. |
| `create_4wd05_receiver(file_bytes)` | Loader `0x9a530` reads a LE-u32 decoded length and native nibble-coded payload. Its first 32 decoded bytes populate two 16-byte metadata fields at `+8/+0x1c`, with lengths at `+0x18/+0x2c`; remaining history is allocated and stored through pointer `+0x50` and WORD length `+0x54`. Destructor `0x9a390` frees that pointer. |

The 4WD file encoding is **not ASCII hexadecimal**. Decoder helpers
`0x156ac0/0x156b10` use signed division and byte shifts, including native alias
characters; those calculations are preserved. Host bounds reject incomplete,
overflowing or mismatched file lengths before allocation. An empty history uses
NULL; zero initialization of unspecified padding/header fields is host policy.
Partial producer allocation failures release all newly allocated blocks.

Four source-reviewed methods pass stable receiver `+0xe8` storage through exact
IAT slots: TPW03 `0x57ec0 → 0x226fa0`, AWD04 `0x99700 → 0x227654`,
4WD05 send `0x9a450 → 0x22764c`, and history write `0x9a470 → 0x227644`.
The chassis engine reads nested pointers through this same source/owner-bound
arena; pointers are not substituted with inline data or successful callbacks.

## Validation and limits

Run `python -m unittest discover -s tests -p test_native_memory.py -v`.
Authored tests cover allocation bounds, overflow, overlapping spans, stale and
cross-arena pointers, realloc failure, cancellation, live pinning, escaped views,
source ownership, receiver cleanup and all three concrete source producers.

When the supplied private images exist, additional checks verify exact native
caller/initializer instruction bytes and execute the actual native history-file
producer through receiver method, guarded IAT, UtilityEx/chassis body and native
communication lifecycle to typed raw SDK fakes. Literal requests are
`1001, 1003, 2e20026162, 2e2003, 1001`; filters/disconnection and malformed nested
spans, cancellation between records and raw SDK faults are asserted. Additional literal-wire checks cover TPW03's A8 support snapshots, nested mask
reads, PID reads and `3b36` write; AWD04's 27 history queries and actual
malloc/realloc accumulation; and the 4WD05 replay branch consuming the same
loaded history pointer. All four pointer-consuming exports execute through the
real engine and native communication code. No whole communication/session/business
completion provider is injected. These tests skip
in a public checkout without the private source images.

Private source evidence is under `analysis/evidence/no-car-142/`, including
`IT3UtilityTY18.asm`, `native-pointer-caller-bindings.json` and
`receiver-producers.json`. This covers memory and these receiver producers; it
does not claim complete outer UI/controller selection, every native procedure,
or physical vehicle effects.
