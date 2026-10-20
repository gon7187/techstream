# UtilityEx communication reconstruction — incomplete

`UtilityExComm(context, selector)` validates the complete supplied module SHA
against the eight exact12/18/DS4/GTSPlus TY/NK identities. Its selected manager,
target metadata and supported fixed objects come from each image's own source.
**All eight exact images join all twelve selected classes: P3, F1/strict/slow
variants, legacy P4/ISO9141, plain/extended classic CAN/P5 and three SIL objects.
These use concrete raw SDK primitives. Plain fixed CAN is joined
for NK18 object1014f5e0 and TY18 objects1011d4f0/1011c400/1011a220/1011b310.
DS4 fixed objects101b6758/1006cf88 and Plus fixed objects101c18a0/101392d0
are joined, including distinct PlusTY secondary objects10135c58/1013d6a8/10136e10.
Version12 fixed objects100e9850/100aed50 are also joined using their older
native lower layout. All eight primary managers have actual SDK traces for
standard, extended-address and OEM branches.
All eight ordinary functional broadcast paths use a separate lower class. TY18 SIS1011e618
uses its separate v0500 DRIVER, field layout and lifecycle after the explicit
`_Ex2InitializeDoIP@0` controller initialization. Plus SIS10134b78 has its own
JSON primitives and three-argument controller ABI; its facade has actual SDK
traces, while the public Plus controller export join remains pending83.
Other source/class lifecycle paths remain unavailable. G2/G3 stay OPEN until all
eight source implementations and independent domain traces are complete.**

Implemented components in `scripts/utility_ex_comm.py`:

- TY18 selected P3 uses its exact11fc0/12010/11700 pending wrapper globals.
  Eleven P3 native roles and five direct DRIVER methods match independently
  identified NK18 instruction control flow. Actual TY18 original-image context
  tests cover positive/wrong-service exchanges, A8 aggregation,13/80 DTC framing
  and selected-pointer/disconnect cleanup. TY18 plain/P5 CAN actual original-image
  context traces also cover exchange, A8 aggregation and disconnect; the complete
  seven-object TY18 CAN/SIL identity map is joined through owner132.
- Selected admission now covers96 actual original-context traces:12 roles in
  each of eight images. Forty P3/F1/strict/legacy/slow traces verify distinct
  configuration tables, F1 versus F0 tester address, FAST/FIVE_BAUD handling,
  checksummed literal packets and disconnect. Fifty-six CAN/P5/SIL/extended
  traces verify native selector identity, constructorD/1000c handling, startup,
  business and exit handshakes. No whole initialization or exchange callback is
  substituted. Source-specific pointer, abort, pending count and worker handoff
  globals are mapped explicitly rather than computed from layout offsets.
- Explicit `cleanup_exchange` and `cleanup_session` borrow owner132's bounded
  five-second per-thread lower release scope. Actual NK18/TY18 original-image
  context traces prove canceled release packets reach individual SDK primitives,
  normal session state updates, worker stop and filter/disconnect cleanup while
  the global cancellation flag stays set. Native ordinary session behavior is
  retained outside the release scope.
- `exchange_plain` constructs the source base CComTestMode pending wrapper and
  preserves lower interrupt errors. Default selected `exchange` uses the derived
  wrapper's short-circuit behavior. Both paths have actual raw SDK positive
  traces across all96 source/class routes; their interrupt distinction has
  separate primitive branch tests.
- Selected NK18 C0B0 and TY18 19FC0 use owner132's distinct ISO9141 lower, including native
  five-baud/FAST_INIT branches and686af0 checksum packets. It is not a P3 alias.
  Selected extended CAN C168/C288 and SIL AEA0/AF30/AF80 retain separate lower
  objects and constructor parameters. Literal NK override/profile global setter
  RVAs are available independently for all four NK images.
- TY18 fixed1a890 and PlusTY1e280 forward to the lower child send-timeout field;
  TY18 raw SDK traces verify the changed timeout. This is the ordinary fixed
  class; the separate Plus P6 schema remains guarded.
- TY18 selected121b0 writes native lower+10. Only ordinary classic CAN18/DS4/Plus
  uses that field for its send/receive timeout;12 ordinary, SIL, extended, P5 and
  P4 preserve their own literals. The actual TY18 mode4 SDK fixture verifies200
  after the setter, while its P5 fixture remains1020.
- `select_diagnostic_mode` delegates to the concrete fixed lifecycle: native byte
  mask, same-mode early success, retained lower child status13 and normal1/2
  selection are explicit. All eight ordinary mode3 paths use a separate broadcast child with
  functional transmit address, physical receive address and two literal filters.
  Actual original-context traces verify7df transmission and7e8 reception across
  all eight HS/MS paths. Plus MS filters preserve literal+8 while HS uses+16 in
  mode74; source12 packers preserve literal1020.
- Plus P6 managers101c6da0/1013e7d0 use separate fields, shifted DRIVER
  bindings, one shared four-slot pool across independent6/8012 factories, a
  CAN29/CANFD lower and owner132's separate outer/worker lifecycle. Actual
  original-context traces verify normal/extended sessions, DID, cancel-safe
  normal release and one-filter/disconnect cleanup on both Plus images and
  both physical protocols. Native-error, foreign SDK exception and post-connect
  cancellation component controls retain/close acquired ownership.
  Native10a4 is the busy limit,10ac is inter-request delay,10b0 is pending count
  and10b4 is NRC state. Physical factory selection is retained after connection;
  request flags follow the current module protocol independently. Controller
  initialization uses the8012 factory and preserves its output handle even on
  a native error status. Its public controller export join remains separate.
- P6 broadcast has its own source-bound lower and component SDK traces:
  functional transmit/flow header, physical reversed18DA response header and a
  single flow filter. Owner132's selector remains explicitly unavailable until
  its post-review integration; ordinary broadcast is never substituted.
- TY18 SIS1011e618 has distinct1074/1078 receive fields,1060 retries and10a4
  native error. It rejects the ordinary manager10b0 getter. Its lower38 target
  setter changes the DoIP wire destination without changing physical DRIVER
  ownership. An actual original-image context test runs the exported controller
  initializer, measured physical/logical connection, normal/extended sessions,
  DID/NRC exchanges and cancel-safe normal cleanup through individual v0500 SDK
  primitives, then closes all three logical handles and the physical handle.
- Selected `initialize_at(address, mode=1)` supplies the explicit native16f20
  target argument without changing module target globals; actual NK18/TY18 P3
  traces verify a different wire target and preserved global target.
- Modern DS4/Plus admission has32 independently named pool roles and72 lower
  vtable-role instruction comparisons between the NK and TY images. Bounded
  original-PE disassembly includes indirect-switch arms omitted by the cached
  function-body ranges. Actual source contexts cover normal/extended sessions,
  NRC33, worker operation, canceled normal cleanup and filter/disconnect release.
  Plus mode74 uses response address+16, verified separately in both images.
  DS4 OEM target fallback reads live EbGetPara71, outside the broker snapshot.
- Version12 NK/TY lower vtables have36 paired native-role instruction matches.
  Relative to18, native lower storage fields shift by8 bytes; configuration
  control flow remains identical after those explicit field relocations. Its
  logical duplicate key compares address without the extension. Version12 only
  accepts native modes14/15; later34/74 remain rejected. Sixteen actual source
  contexts additionally verify extended byte29/flags80 and OEM8005 four-argument
  Connect across all eight images. The separate12 controller initialization ABI
  remains guarded in owner83.
- Direct native Sleep sites use the explicit host `native_sleep` primitive;
  cancellation-aware outer polling retains its own checks.

- All eight selected-object tables and actual native protocol getters, independently
  recovered from constructor vtables.12 rejects mode34. Modern sources use distinct
  objects for mode4/P12 and mode14/P12. The actual protocol is never inferred from
  broker70. The96 getter proofs are in `selected-protocol-map.json`.
- Source-local global target setters/getters, fixed target configuration with native
  zero fallbacks, pre-connect lower-class selection, and fixed timeout/retry fields.
  NK fixed managers additionally retain immutable SCONFIG pairs. PlusTY10135c58 has
  the same source constructor as101392d0 and its own mutable fields. Other fixed
  classes, including Plus mode22 managers, remain unclassified and unavailable.
- Direct pending/busy/no-response setters by exact source RVA. Modern NK swaps
  the positions of the busy time budget and the inter-request delay. These are
  explicitly mapped rather than inferred from function order. NK18 cancellation
  getters17340..17380 read the same module fields as the actual classic scheduler;
 83 consumes them for canceled27→28/29 and canceled2→30 normalization.
- TY18 128d0/NK18 22a80 fixed UDS retry, busy21, receive-pending78, NRC state,
  suppressed-positive checks and session exchanges with keepalive disabled.
  Extended session validates both replies before publishing session3.
- NK18 17110/17160/173b0 selected pending wrapper: count versus elapsed-time
  limits, continue-pending, exact force-abort flag, interrupt error propagation,
  pending getter state and worker handoff globals. Native force abort is distinct
  from the outer wrapper cancellation flag.
- NK18 18ef0 classic selected-manager retry and retained counters, plus TY18
  11ac0/NK18 19650 A8 multi-frame support aggregation. A8 keeps256 offsets with
  1020 sentinel, handles duplicate records and zero-filled backing, retries only
  before the first accepted frame, and preserves native offset-zero status
  suppression. Independently audited NK12/DS4/Plus A8 implementations share that
  algorithm with source-specific globals.
- Shared NK12/18/DS4/Plus support profile cache:16 profiles keyed by source-local
  target pair, actual native protocol and kind; native80 before wire when full,
  allocation81, and preservation of an old profile on failed refresh. Native
  refresh functions are16af0/20100/3db70/3eb80. All domain consumers use this cache.
- TY18 11870 selected DTC collector: request13[mode], response53/count prefix,
  two-byte records across multiple frames, per-frame length/echo validation and
  pre-first-frame retries. Later receive errors preserve the partial bytes and
  never resend. The native caller's default mode80/capacity1000 is explicit.
- NK12/18/DS4/Plus fixed short-cleanup setters10fb0/18840/32b90/33aa0: seven
  concrete native fields switch between one-attempt cleanup and normal defaults.
- NK18 four-thread, protocol-aware driver arbitration21fc0/22090/22100/22190;
  raw lock retry, queued receive deadline and disconnect-after-lock-failure.
- Concrete `UtilityDriverBinding` raw SDK adapter using positional mutable native
  outputs. Export results carry only status; channel/filter IDs and received
  messages come from output buffers. No opaque business success callback is used.
- NK18 lower pool213f0/216b0/219c0/21b30: four logical slots, shared physical
  handles, duplicate rejection, bounded eight-message queues, OEM Connect mode15
  versus nonzero legacy wrapper mode1000c, demultiplexing and final-owner close.
- NK18 complete P3 lower163d0/16710/16870/168d0/16960 over the direct
  protocol4 singleton21370/21660/21840/21960/21ac0. Its direct SDK path is
  distinct from the logical CAN slot pool. Exact4/15-entry native configuration
  tables, FAST_INIT retries, KWP checksum framing, pending/busy decoding and82
  interrupt with GET/SET_CONFIG10 restoration are covered by raw primitive tests.
- NK18/TY18 plain fixed facade joins `UtilityExFixedLifecycle` from owner132 to the real
  pool/lower and shared fields. Normal/extended sessions start/stop the actual
  worker, NRC state reaches native10b0, and finalization releases both filters
  and the physical handle. TY18 admission is backed by39 lower-method and14
  pool-method instruction comparisons against separately identified native roles.
  `configure_keepalive` preserves explicit request,
  interval, response size and recovery flags. Native stop's second argument1
  closes the lower; the ordinary stop default is0.
- NK18 selected classic CAN objects1014ae60/1014ad90 join owner132's direct
  protocol6 lower with source-specific configuration, filters and timeouts.
  Actual A8 aggregation feeds the shared support cache through this facade.
- NK12/18/DS4/Plus native support append17580/20b90/3d4c0/3e4d0 deliberately
  appends duplicate profiles without the refresh16-limit and returns99 after
  success (81 on allocation failure). Lookup preserves the first matching entry.
- NK18 concrete CAN lower24140/24590/24eb0: connect, native configuration,
  routing, both filters, standard/extended packing, receive/NRC decoding,
  different pending timeouts and resource cleanup on failures. This lower is
  joined to the concrete fixed manager and worker for the listed NK18/TY18 objects.

The pool uses only individual raw primitives through `J2534Device2026._call`'s
host guard. It does not borrow2026 connect/configuration business algorithms.
Resource acquisition is recorded before post-call cancellation checks; failed
cleanup retains ownership for a later finalization attempt. Tests execute Python
and supplied synthetic raw primitives only: no OEM image, Wine, device, network
or vehicle execution.

Remaining work:

1. Join the source-bound P6 broadcast lower to owner132's separate selector after
   its review window; complete public controller export composition with83.
2. Complete the remaining stack P5 lifecycle and source-specific native setter
   contracts, without treating that stack class as the plain selected facade.
3. Complete DTC source contracts beyond the joined TY18 collector and verify
   remaining direct native-global consumers.
4. Independently review full source-bound domain integration, fault behavior,
   worker budgets and observable native Sleep scheduling. G2/G3 remain OPEN.

Verification: `python -m unittest discover -s tests -p test_utility_ex_comm.py -v`,
Ruff check/format and Pyright on the two owned Python files. BYOD checks validate
actual supplied module identities and native object metadata; unported facade
initialization explicitly fails closed.

Current owned verification:91 unittest checks pass; Ruff and Pyright pass.
