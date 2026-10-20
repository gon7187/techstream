# Retained MS2 diagnostic operations

`scripts.utility_ex_ms2` provides 38 exact exports for each of the supplied TY18
and TYPlus identities: 76 source/export pairs. The TY aggregator joins this
provider; the common UtilityEx engine owns mode52 admission, native worker
scheduling, timeouts and status publication. The pressure predicate remains a
direct export. ABS05 and EFI02 have no native arguments. Original12 and DS4 do
not gain exports by name. MS2MM/MS2BSRL remain with the TY core provider and
MS2SMRT with the TY body provider. EYES01–07 delegate to the separately owned
`scripts.utility_ex_ms2_eyes` source-specific provider.

The supplied module is data only. No Windows module is loaded or executed.
Authentication keys are projected from caller-supplied, hash-authenticated PE
bytes using source operand or data RVAs. Authored code and fixtures contain no
original keys. Native mutable messages retain their identity across the outer
worker and provider joins.

| Family | Recovered behavior |
| --- | --- |
| ABS01–05 and pressure predicate | Support maps, signed pressure/calibration conversion, routines0202/0203/0204/0207, fixed UI delays, authenticated session40 and native retention/status branches |
| AT01–02 | Authenticated FF00 polling; selected sensor support, timed stability, two-manager speed threshold, live UI pressure-control flags and native NRC mappings |
| BDY01 | 47 selected DIDs, support masks, writes and refresh; failed field reads publish55 |
| DCM01–02 | Support/selection masks, IO control, live monitor values, return-control polling, setting writes and refresh |
| EFI01–06 | Four receive slots, routines8010/8011, compact DID records, authenticated writes, VIN/broadcast operations and native timeout changes |
| EMPS01–02 | Selected communication, source-specific identification patterns, DTC allow/deny sets, calibration/session commands and raw error-byte mappings |
| EYES01–07 | Source-specific selected records, authentication, routines, write/readback and native capture-file/timestamp behavior in the EYES provider |
| GWY01 | DID103b/routine020c; worker start precedes six-byte reply validation; retained manager on2000 |
| IG01 | Typed selected record, authenticated IO control, live stop flag and exact source stack-copy layouts |
| MET01–02 | A000 and selected support maps, compact native records, legacy mode2 authentication, writes and retained session flag |
| PWD01–02 | FF00 with distinct0000/0002 payloads and native pending/result status mappings |
| RAB01–02 | Paired status/value records, five-DID multi-read and selected-record block copies with native zero padding |
| SAS01–03 | Three-manager VIN transfer, AES security and DTC guards; signed measurement conversion with source-specific x87/SSE rounding inputs |
| TPW01 | Selected2106 read or3b0e32-byte payload with five identifiers and native spacing |

Fixed managers use their exact source identities. The security helper receives
two distinct communication roles: native argument8 handles preliminary access
and failure cleanup; argument7 handles the selected second access. A shared raw
NRC global in `context.state` differs from the manager's mapped `native_10b0`.
`select_diagnostic_mode` represents native12f40/Plus12cf0; it must not be replaced
with the lower protocol/class selector. SAS01 periodic configuration changes an
existing worker's pause/configuration/resume state, with exact response length1;
it does not create or destroy a worker.

`MS2RAB02Message` and `MS2IG01Message` replace native pointer-bearing metadata
with source-tagged uint32 record fields. Plain bytearrays remain accepted for
branches that do not dereference those records. IG01's Plus stack copy includes
four uninitialized native bytes; callers must supply the observed bytes under
`native_stack:100b0fc0:uninitialized_1c`. An out-of-range AT02 selector requires
an explicit uint16 `native_stack:MS2AT02:selector_did` value. The implementation
does not invent native stack contents. SAS03 requires an explicit
`host:x87_control_word` or `host:mxcsr` floating-point environment.

Native normal-path cleanup and retained-session branches follow the recovered
bodies. Host cancellation and exceptions have explicit bounded cleanup and
propagate typed failures. Individual exchanges and source sleep points observe
cancellation; the common worker supplies the outer deadline.

The source-free literal suite covers branch/wire/output behavior, malformed
responses, native errors, cancellation, host faults and retention. The public
worker replay exercises every advertised pair through the actual common engine,
TY aggregator and provider; synthetic module authentication and communication
are explicit test boundaries. This is separate from private authenticated-source
projection checks and concrete lower integration evidence.

Run `python -m unittest discover -s tests -p test_utility_ex_ms2.py -v`.

G2 and G3 remain open until concrete lower paths and independent source review
are complete. In particular, Plus selected DTC/lifecycle remain explicit lower-layer
boundaries. Private TY18 checks exercise ABS04 AES encryption, SAS01 AES
decryption with three managers, and EFI06 functional7df send/physical7e8 receive. Physical communication is
PHYSICAL_UNCONFIRMED.
