# Native operation reconciliation

The native-operation manifest is a source-bound ledger, not a certification of
vehicle support. `python -m scripts.native_inventory inspect` validates its
structure and reports open targets. `python -m scripts.native_inventory validate`
rejects any open export, module audit, or required business contract. It never
loads a vendor library or opens a vehicle transport.

The canonical universe is independently frozen from original artifact inventories
and static PE headers/export directories. It retains all exported slots, including
ordinal-only exports, aliases, data symbols and forwarders. Executable-section
flags distinguish code from data; a filename does not establish implementation,
reachability or equivalence. Reconstructed engines retain their protected source
and companion identities. Each PE also has a module audit target, including
managed images and executables without native exports. A module audit must account
for business operations reached through internal code, managed methods and dynamic
selection; closing a thin exported primitive does not close that audit.

The source universe digest and counts are pinned in `scripts/native_inventory.py`,
independently of the manifest's mutable ownership and completion claims. Removing
or inventing an artifact/export, changing an alias, replacing an original identity,
or changing a native address fails even if the manifest recomputes its own digest.
Original code, resources, authentication material and decompiled instruction bytes
are absent from the public manifest. Its source names, hashes and addresses are
metadata only.

The frozen scope contains 2,454 unique PE identities with 3,407 provenance
aliases and 146,011 live exported slots: 132,513 in executable sections and 13,498
data exports. Every earlier original/provenance alias was re-read from its actual
file before expansion. Recursive supplied application scopes contribute 525 PE
files for version12, 610 for version18 and 1,435 for GTSPlus2026, including managed
images, installers and runtime dependencies. Byte-identical identities share an
artifact while retaining every distinct source/provenance alias. The previous
1,300-identity scope was incomplete for the supplied applications.

The independently reproducible universe digest is
`9baf36c9aa71df6f24b504b82d5a3e004b07f83059882dd6018fa82ef25b09c6`.
The compact metadata manifest is approximately 37.5 MB. Reading is bounded by
64 MiB, 4,096 identities and 200,000 export slots; regression checks load the actual
expanded manifest and retain those fixed bounds. A source inventory is an honest
accounting boundary, not a requirement to reimplement the entire Windows or .NET
platform. A concrete host replacement can close a reviewed platform operation;
merely recognizing a dependency filename cannot.

The supplied version12 and version18 `USB_Driver_XP_x86/wdreg16.exe` paths share
one 16-bit NE identity. The separate mandatory OPEN contract
`native12:wdreg16_installer` retains that obligation without inventing PE addresses.
Managed GTSPlusCommon/MsgDatComm images with named zero EAT slots have no live
export target for those holes: the collector does not reinterpret the null name
RVA as a DOS-header export name. Their module audits remain OPEN, including their
managed and dynamic business behavior. No platform role or malformed metadata
implicitly closes an audit. Any newly identified dependency outside these pinned
scopes requires independent expansion and re-pinning.

## Completion claims

`universe` contains canonical artifact metadata. `operations` has exactly one row
for every native export ordinal and module audit, with a leaf owner or `null`.
`OPEN` rows have no claim. Ownership is routing and never proves completion.
`contracts` lists required semantic operation IDs, including internal business
families. `claims` binds resolved targets to those contracts. The integration gate
must additionally pass its independently maintained known-contract set as
`required_contracts`; omitting a known family then fails rather than shrinking the
contract to match the implementation.

A reviewed claim uses this structure (the hashes/addresses below are illustrative,
not a claim about an original artifact):

```json
{
  "id": "family.operation",
  "owner": 31,
  "status": "implemented",
  "targets": ["<original-sha256>:export:1"],
  "implementation": [{"path": "scripts/module.py", "symbol": "Controller.run", "sha256": "<reviewed-source-sha256>"}],
  "tests": [{"name": "test_module.Tests.test_native_success_and_failure", "sha256": "<reviewed-test-source-sha256>"}],
  "native_evidence": [{
    "source_sha256": "<original-sha256>",
    "rvas": [4096],
    "document": {"path": "docs/module.md", "sha256": "<document-sha256>", "anchor": "Exact native contract"}
  }],
  "review": {"path": "docs/module.md", "sha256": "<document-sha256>", "anchor": "Independent review disposition"},
  "reason": "Concrete recovered behavior, including the native failure branches."
}
```

Every target must have exactly one matching owner/disposition/claim. Its original
SHA-256 and entry RVA must appear in native evidence, and evidence/review documents
must exist at guarded repository paths with matching hashes and literal anchors.
Implementation and regression bindings use a reviewed file SHA-256 by default.
An explicit `hash_kind` of `module-ast` or `symbol-ast` instead binds the exact
Python AST without line offsets, comments or formatting. Module AST bindings pin
fixture/global/helper changes; symbol AST bindings require the reviewed claim to
list its actual dependency closure. Semantic changes require focused re-review,
never blind digest refresh. Implementation and test references resolve through Python AST without importing
the claimed code. Missing symbols, obvious placeholders, constant-only results,
constant/assertion-free tests and `NotImplemented` branches cannot close targets.
The validator returns exact test names for the integration runner; structural
validation alone does not execute or certify their behavior.

`platform` and `unreachable` require the same concrete implementation, regression,
source evidence and review bindings as `implemented`. They are not automatic
exemptions for CRT, C++ constructors, data exports or Windows interfaces. Native
reachability and the actual host replacement must be established by review.
Aliases of one original source identity do not imply equivalence across builds.

Incomplete owner implementations stay `OPEN`. The ledger must not manufacture
thousands of empty ABI methods, invent successful provider responses, or rename a
partial primitive as a complete wrapper. Physical observations remain
`PHYSICAL_UNCONFIRMED` regardless of a source-only gate result.

## Reviewed selected-database host replacement

The selected-database claim group covers the recovered MultiPID, CommPid,
CommRid, CommDid, ProtInfo and ActTestCommMode index/getter operations of
`KgpDataCtrl.dll`, source SHA-256
`e5235bc0c241c6a450fe461031eed0915675032b1db994bd54d98818fac88aa9`.
The manifest carries the exact independently collected SHA-256 and RVAs; the
source identity shown here must match that metadata before claims are attached.

These original C++ record/index interfaces are replaced by selected immutable
Python rows, explicit field layouts, tuple-key ordering and ordered exception
overlays. They do not export a Windows ABI or preserve process pointers. Native
query keys, row order, first-row selection, missing-resource distinctions and
versioned layouts are retained through `VehicleProfile` and `correspondence_rows`.
This is a concrete data-model replacement, not an exemption for every other
export in that DLL. Its module audit remains open.

Independent selected-database review disposition: the communication descriptor
schemas and group queries were independently checked against both original
builds; the ProtInfo/PSA consumers were separately checked against the full bus
comparison and selected ActTest caller; MultiPID was checked against the actual
monitor consumer. Source-bound authored overlay, wrong-key, missing-resource and
original regional-corpus checks passed. These dispositions cover the six named
metadata groups; they do not certify transport wrappers or unreviewed tables.

Regression bindings pin the reviewed test source file as well as the exact method.
The validator checks source and proof identity; its returned test names feed the
parent executable regression gate. Static validation alone does not run tests.
The six selected-database claims remain OPEN while their shared source is extended;
restoring them requires independent review of the final source and test changes.
