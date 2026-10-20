# Selected native monitor support producers

`scripts.monitor_support` performs no device access at import. The cache receives
an explicit selected `VehicleProfile`, ECU identity and primitive providers.
`SupportQuery` carries the exact request, selected communication/settings records,
and the full selected ECU/resource/category/exception/vehicle identity. `source_build=12|18`
selects application algorithms independently of the DDB format. Cache instances belong
to one selected context and should be reused by its consumers.

`valid_id_entries()`, `enabled_pid_entries()`, `pcs_operation_pid_entries()` and
`support_bit_entries()` are native ordered producers: they retain repeated
identifiers, repeated bitmap chunks and distinct per-occurrence lengths. Output
list counts are DWORD-sized, independently of SHORT-sized database record counts.
Dictionary methods are first-match lookup projections; callers that iterate a
native list or use its count consume the corresponding entry tuple.

`MonitorSupportCache.valid_ids()` implements the PID-extension DB203 bitmap / DB206
fallback and DB237 additional request bytes. It preserves source order and first
matching PID definitions. ValidIdExt omits DB203 mode0 entries after validating
the selected DB203 record count; an entirely inactive list uses the DB206 fallback.
Normal enabled PID lists retain mode0 entries. `enabled_pids()` selects normal, extended, P4 and A8
producer paths. Normal/Ext/A8 zero-length PID definitions trigger a PID query;
its length is `(reply_length-request_length)&255` in both source builds. P4 uses
the selected PID/DID raw support payload count instead. ValidIdExt subtracts its
supplied receive offset; these are distinct source contracts.

The `no_frame_number` family implements the separate native NoFrmNo helper.
It still patches the selected request's frame number and PID. For a three-byte
freeze request, the reply header is the BYTE-wrapped reply length minus the
selected base PID's returned data length, and must be two or three bytes. A zero
base length triggers the native cached PID-length query; missing/zero lengths or
other header sizes fail with `A0040202`. Four-byte requests retain the native
`reply[header_length-2:-2]` slicing, including non-freeze kinds.

`support_bits()` executes the native raw support stream (function13 PID,14 DID,82
RID,A9 WID). `SupportStream.send(SupportSend)` returns a native status;
`receive(SupportReceive)` returns `(status, payload)`. Requests preserve the selected
send timer, observed connection bus ID and native flags0/1. Receives preserve
capacity255, selected timeout, flags0 and100ms wait. Native version12 uses the
selected receive timer directly; version18 can replace it with the first selected
CAN record's timeout. After the first valid page, retries receive without resending.
A terminal timeout succeeds only after at least one valid page. Failures remain
native failures in the cache; absent streams/connection identities fail explicitly.

`pcs_operation_pids()` implements the distinct PCS operation FFD producer:
kind1 selects function0F and kind3 selects0E, then the support bitmap produces
candidates. Each candidate requires a nonempty ALL-row DB256 query and an actual
raw support payload; its length comes from that payload, without DB206 lengths
or filtering by DB256 PID bytes. Mode2 dependencies, forced Ever invalidation
and three/four-byte request/reply layouts follow the native helper.

`data_ids()` implements C8 root/group discovery, explicit designation, explicit bus,
Mazda selected CA candidate enumeration, Subaru cached CA enumeration, and the
separate native NoCache class with its excluded group list. Candidate sources use
selected DataIdForDm/DataIdForAct and selected custom-sign/custom-item records.
Only successful CA replies produce lengths. Native suppressed page errors remain
visible in `DataIdSupport.suppressed_errors`; cancellation and budgets propagate.
NoCache's default NULL response-cache pointer creates a fresh local TEMP scope.
An explicit `response_cache=cache.new_temporary_cache()` binds a retained native
cache instance and validates its selected source identity before any cache lookup.
This supplied-cache branch matches the saved DDR caller's owner-held cache;
neither branch reuses an unrelated operation-wide TEMP response implicitly.
Normal, explicit-bus and NoCache automatic Mazda selection preserve the native
outer caller's ignored helper status: they return and cache identifiers produced
before a metadata failure. A newly built length list is committed only after the
helper completes. Direct `family="mazda"` still propagates helper metadata errors;
host cancellation and budgets propagate in every branch.
The last executed custom-item probe status is returned by the direct Mazda
helper after its length-list commit. Automatic dispatch ignores it and retains
partial identifiers and committed lengths.
`subaru_did_support()` follows the native 32-bit continuation pages, remembers
attempted pages, and shares the resulting enabled DID list with the normal cache.
Designation returns the complete mutated native list, preserving seed groups
before appending expanded identifiers. Bitmap additions retain duplicates;
designation, excluded, Subaru and enabled-DID input counts use native DWORD bounds.

`check_support_pid()` executes P5 CA length/mode checks and selected DataIdBitForDm
conditions. Native mode1 reads its bit from the DID echo byte at `(end>>3)+2`.
Build12 uses its static selector; build18 supports recursive value conditions and
cached dynamic re-evaluation. The raw support cache precedes the optional record
mode override. Dependency cycles stop at the host bound instead of recursing forever.
For value comparisons, failed communication and header-only replies produce a
failed equality predicate, distinct from a received numeric zero; native mode2
then inverts that predicate. Static bit conditions return false for unavailable data.
The first matching support-value signal ID0 is a native lookup failure. Reverse
bit ranges retain native `C0000001`; payload overflow or a dynamic lookup's
one-byte variable raises host `SessionError` instead of attempting an unsafe read.

`transaction()` and `multi_receive()` validate the selected frame against the
current profile before any cache lookup or I/O. The shared identity includes ECU,
management/diagnostic hashes, category record, exceptions and vehicle-name key. Validation regenerates native
selection and compares all records and decoded wire data; a matching provenance
string alone is insufficient. Literal request overrides retain original metadata.
Selected frame groups accept the native positive signed-SHORT count through32767;
FIRST-frame consumers preserve larger groups, while support templates that require
exactly one frame still reject multiple records.
Selected query result counts above32767 fail with native `A0030110`, matching
the original database record setter. ValidIdExt and normal PID length queries
follow their bitmap exchange; a later metadata failure preserves that chronology.
Active support candidates query `profile.pid_records(pid)` in native order:
only the first contiguous BYTE2 group is SHORT-sized. Already reached immutable
metadata groups are reused within that call; future candidates are not queried
early. The no-support fallback queries all selected DB206 rows.

`transaction()` distinguishes shared Ever cache (`cached=True`), instance TEMP
cache (`cached=False, temporary=True`), and direct communication (`cached=False`).
The Ext provider uses the native default4096-byte receive area; request length
remains USHORT. Only success and native91010009/90020323 enter response caches; cached empty replies
produce91010009. `begin_operation()` resets the host deadline/exchange budget and
TEMP cache while retaining source-bound shared cache state. Designation creates
its own native TEMP scope; each CA enumeration probe constructs a fresh scope.

`multi_receive()` implements native61720/build12:40e20. It preserves full ordered
responses, retries an initial failure, stops with success on timeout after a valid
reply, and never sends again after an accepted reply. Its result retains both the
native status and any partial replies. Host cancellation/budget failures propagate.

`mode35()` issues selected CB templates, advances the native24-bit page counter,
uses a fresh local TEMP cache, handles FF LID escapes across pages and truncates each identifier list at its first
unsupported Freeze descriptor. `mode35_frame_map()` derives ordered bit positions
and widths from selected Freeze rows, including native mixed signed/unsigned offset
comparison and WORD wrap. The pure builder rejects malformed/missing definitions;
it does not fabricate uninitialized native array contents.

`send_support_comm()` implements the native13030 dispatcher over raw support
streams, C8/CA/6B/75/E0 queries and the distinct104 DataId status producer.
`get_comm_support_bit(reference)` consumes selected DB130 rows in native AND/OR
order, preserving predicates1/2/5/6, first uncached timeout initialization, and
fatal metadata errors. Connection rows require concrete `NativeCommunication`
instances, selected by explicit `(target_category, bus)` bindings. Targets share
application build, management source, exceptions and vehicle-name key with the
parent; their ECU database and category may differ. Target channels use `target_operation()` to inherit the parent deadline, cancellation and remaining
primitive allowance. The concrete lower layer receives the combined parent
cancellation predicate; independent synthetic integration checks stop before
additional native I/O when cancellation arrives during connection.
`temporary_scope()` preserves native local cache lifetimes and restores an outer
TEMP scope after nested calls or exceptions. GetCommSupportBit creates one native
local TEMP owner for its entire call; same-category contexts on different buses
share its category/request lookup while retaining selected-source guards.
`share_ever_cache()` binds fresh contexts to their selected DataCtrl's Ever owner;
replacing an already populated independent buffer is rejected.

`PacketFrameCache.get_packet_frame()` executes A2/04 collection, accepts sequence11
first, preserves contiguous E2 sequence bytes and payload lengths, then sends A3
under interrupt mode and drains to91010009. Lookup preserves native first ECU
match. Send/receive timers, retry limit and source identity are explicit. Cancellation,
deadline and primitive budgets guard the native potentially unbounded receive loops;
interrupt mode is restored on host cancellation/error and incomplete results are not
cached.

`PacketFrameCache.from_profile()` selects the first DB11D ComSet record at key1,
preserving its DWORD send/receive timers and BYTE14 retry count. A native query
failure or empty group uses the original defaults1000ms/200ms/two retries. This
factory accepts primitive packet operations; concrete lower-adapter composition
belongs to the selected transport consumer.
The factory retains its selected profile and checks its current identity before
every lookup and primitive operation, including cache hits with an old identity.
An A3 send failure can notify the selected shared monitor session through
`disable_packet_ecu`, before draining replies. A callback failure still restores
interrupt mode and prevents insertion of an incomplete packet-cache result.

`check_freeze_pid()` preserves the separate native normal and freeze PID lists:
the freeze list supplies the initial Freeze range check, while PidBit selector2
tests identifier membership in the normal list. Selected DB208 queries resolve
every variable in the first reference group before using its first definition.
Selector4 uses two identifier bytes, native out-of-range `GetAt` node0 writes,
and a four-byte reply header. Selector3 reaches a NULL DID list in the native
Freeze caller and is rejected explicitly instead of fabricating support.

`temporary_observations()` snapshots the active native TEMP buffer in insertion
order as immutable request/reply byte pairs, including cached empty failures.
It validates the selected source and follows the active `temporary_scope()`;
the caller captures it before leaving a per-Execute scope.

Static source anchors are in the private `analysis/evidence/no-car-52` inventory.
Authored regression cases are public in `tests/test_monitor_support.py`.

`monitor_source_identity()` accepts the management-only `ProtocolProfile` and
records its explicit `ecu_database_sha256=None`. Management transactions and
packet initialization need no fabricated ECU database. ECU table producers,
including support discovery and Mode35, reject this context before I/O.

`share_discovery_cache(owner)` binds contexts on the same native DataCtrl to
support ShareData slots10/11/19/1a and Mode35 slot21. Entries remain separated by
selected category and support kind; display names and bus aliases do not split
native discovery state. Source/build/exception/vehicle guards precede cache hits.
Mode35 retains the native error from the final Freeze metadata filtering stage,
so repeated and sibling calls return that status without another query. Early
assembly errors and host failures are not inserted as discovery results.

## Verification boundary

This module is under integration, and leaf52 G2 remains open. Passing checks cover
literal support wire, actual selected resource queries, P4 consumer integration,
P5 conditions/cache scopes, Mode35 and packet/multi-receive chronology. They are
static-source and synthetic-I/O evidence. No vendor PE was executed and no adapter
or vehicle was used. GetCommSupportBit/SendSupportComm and concrete no-buffer
connections are implemented; cross-target caller integration and source-hash-bound
independent review remain open before full family
equivalence is claimed. The pure
Mode35 builder explicitly rejects native uninitialized partial array contents.
