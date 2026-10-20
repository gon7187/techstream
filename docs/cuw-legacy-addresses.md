# Original CUW executable address factories

`scripts.cuw_legacy_addresses` ports original12 `40f4f0` and original18
`41ac7c`. The caller supplies `ExecutableContext` with the actual matching
original executable in `attachments['legacy_executable']`. `ExecutableImage`
checks the complete original SHA256 before any static virtual-address read.
No executable is run, imported as a library, or contacted over a device transport.

`select_legacy_addresses(context, kind_of_ecu, config=None, *, reprog_mode=False,
factory_state=AddressFactoryState())` returns immutable `CAddress` records.
`kind_of_ecu` is the literal native KindOfECU string. The optional `AddressConfig`
contains actual observed CID strings from the native object's count/getter interface; an empty object
and an absent object select different branches. Configuration strings and the
native process latch must come from their actual producers.

The CID predicates retain native prefix-length `strncmp` comparisons.
The implementation preserves all native KindOfECU branches, repeated entries,
reverse selector traversal, first matching row, and empty output on an unknown
kind or missing selector. It copies eight-byte rows from the private executable's
65-row table (12: `5861a0`, 18: `5d621c`). No OEM address bytes are embedded in the
public module or authored tests. A DLL catalog or LocationID is never substituted.

`CAddress.raw` retains every byte. `request_header` and `response_header` expose
the native two-byte address left-padded to four bytes. `diagnostic_request_header`
and `diagnostic_response_header` additionally preserve the record's respective
extension byte when its extension flag is set. Consumers must use the width of
their actual native helper rather than blindly reusing a diagnostic header for
ordinary raw writes.

`AddressFactoryState` holds snapshots of the native process-global default
selector vector and FC named rows. Empty vectors model their post-constructor
state. Default selectors are separate from the optional configuration strings.
For KindOfECU 1/10/16 with configuration present, native code copies the first
byte from the global default vector; an empty vector would dereference NULL.
The port raises `NativeAddressFault` rather than inventing an address or crashing.

`select_fuel_cell_address(context, key, state, previous)` ports original12
`410830` and original18 `424d1c`: it takes the first exact named FC row, prefixes
its seven bytes with native identifier 65, and otherwise preserves the supplied
previous record. The key is selected CPU calibration metadata, not KindOfECU.
`legacy_kind_override(context)` reads the actual native pointer used by the
Body/DSS secondary preparation mode. Mutable vectors are never read as though
heap pointers in a static PE were live state.

The static selector helpers perform bounded immutable computation. The concrete
CID getter uses the shared host runtime for neutral communication primitives,
resource ownership, deadlines and cancellation. Invalid types, embedded NULs, oversized vectors, changed executable
identity and malformed table spans fail before any communication.

Run authored checks with:

```sh
python -m unittest discover -s tests -p test_cuw_legacy_addresses.py -v
```

The authored suite covers every literal selector branch in both builds, nullable
configuration, native string predicates, process defaults, ordering, duplicates,
FC first-match/preservation, record widths and negative source admission. A
separate private static check admits both original executable hashes and selects
all 65 IDs over 402 calls per build; it records source/table hashes without OEM
address bytes. No car/adapter execution has occurred.

Full factory completion requires the actual imported metadata/recovery/UI vector
producers and all family consumers to be composed by the original executable
engine. Passing this module's tests alone does not close that integration gate.

`legacy_address_inputs(context)` binds these producers. The manager's `+4`
TStringList becomes controller `+108`; saved recovery restores it from
`CIDNum`/`CIDN`. The default selector vector restores independently from
`CIDNodeNum`/`CIDNodeN` (RecoveryInfo vector base `+30`, data pointer `+40`).
Normal discovery supplies `AddressDiscovery` in the context observation
`legacy_address_discovery`, carrying exact build/container hash, ordered CIDs,
corresponding source-derived address records, one completed candidate per
`queried_addresses` entry, and the software mode latch. The query vector is
independent of CID count: one query may append multiple CIDs or none.
The binder rejects mismatched hashes, builds, CID order, foreign ordinary table
rows, missing discovery state and conflicting latch snapshots. FC discovery
records use native ID65 and produce the CID-keyed seven-byte rows. This typed
capture represents actual getter output; constructing it alone does not replace
running the source-derived getter over injected communication primitives.

`select_p5_addresses(context, kind_of_ecu, config=None)` independently ports
original12 `41da48` /18 `43876c`. It returns `P5Address` with seven-byte records
from the separate three-row tables (`58b088` / `5dc97c`). It keeps the distinct
P5 CID prefix predicates, nullable configuration, reverse ordering and first-ID
scan. Request/response headers use row offsets1/4, two bytes each padded to four;
bytes3/6 remain uninterpreted. It never drops a flag from an eight-byte record.
`AddressDiscovery` retains the actual typed seven-byte P5 getter rows and admits
them against this separate table.

Original12 constructor and recovery vector peers are independently checked in
raw ASM (`43bfb0`, `44bff4`, `417ed8`, `417f94`, `41094c`). Original12 initializer `416738` binds `CIDNum`/`CID%d` and
`CIDNodeNum`/`CIDNode%d` to the globals used by loader `416f68`; missing
counts default to zero. Host input admission rejects values outside byte range
instead of native AL truncation. Full factory consumer integration and
independent source review keep G2/G3 open.


`discover_legacy_can_addresses(context, io, *, read_identifier, reprog_mode,
terminated)` implements original12 `436a4c` and original18 `457e98` CAN getters. It reconnects protocol6,
sets read timeout1000, selects KindOfECU candidates with NULL configuration
(Kind3 uses Kind1), probes PID0900, reads PID0904, associates newly parsed CIDs
with each candidate and publishes one selector per query. Unsupported candidates
1/3/10/20 are skipped; others raise native code1. Successful query IDs3/10/20
terminate the candidate loop. Four-byte discovery headers deliberately ignore
extended diagnostic header fields.

`parse_can_cids` enforces the native count/16-byte length contract, omits records
whose first byte is NUL, terminates each ANSI string at its first NUL, and
preserves whitespace and opaque bytes through Latin1. Optional request1A89,
expected5A/error92, updates a thirteen-byte output buffer; leading NUL bytes
become `I`, invalid or all-zero values preserve the previous buffer. Returned
identifier buffers and native publication flags retain query order.

The actual normal manager sets `read_identifier` from `manager+f10 != 2`
(`475d34..475d4a`, constructor `457da8` into inherited `46a15c` field+94).
The single `terminated` predicate represents actual thread byte+d. Native
callback VMT5f182c method46aab0 subtracts40 from interface `this` and jumps to
459d00, which reads that same byte. The getter samples it before GetCID and
passes it to the shared diagnostic helper for every read. Filter/disconnect
cleanup on fault and early cancellation is explicit host policy.

Original12 CAN getter436a4c/probe437568/GetCID437210/parser437448 are
separately ported from exact raw ASM. Its smaller instance has no original18
optional identifier slots: `read_identifier=True` is rejected and auxiliary
output is empty. Its actual selector publication4377dc copies getter+88
through41094c/417f70; per-CID address associations in the typed output are a
host sidecar derived from the concrete query, rather than a claimed original12
instance field. Independent source review remains open.
P5, FC and SIL CID getter dispatch remain separate work; a recorded typed capture
is accepted by the binder but does not close those concrete getter paths.
