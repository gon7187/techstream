# UtilityEx source-bound engine

`scripts.utility_ex` supplies persistent per-image state, broker parameters,
native cancellation, source-specific domain selection, and an owned worker.
`NativeUtilityExNK2` and `UtilityEx2TY` are host replacement classes. Their names
do not assert that an identically named OEM class was recovered.

An original immutable image is mandatory. Eight distinct NK/TY images have
independent SHA-256 identities; a filename or matching ordinal does not enable
another build. Domain providers additionally check their own exact source guard.
`run_body` invokes an internal reviewed worker body. `start_export` additionally
models an explicitly reviewed native wrapper's mode check, timeout, running15
and busy16 returns. Unreviewed wrappers raise rather than inheriting another
export's scheduling contract.

The engine binds exact NK wrapper contracts to concrete domain bodies, including
direct signed returns, native void returns, conditional start/stop workers,
argument arity and pointer identity. The initial 94 TY18/TY12/TYPlus wrappers match
complete source templates with mode20/21, literal timeout and direct native
thread entry. Their private C/ASM hash evidence is
`analysis/evidence/no-car-83/ty-template-wrappers.json`. TY18/TYPlus character and
hex conversion exports also preserve their direct ABI. An available wrapper
never enables a missing domain body. Source-reviewed owner packets add native
ABS families, FCHV, mode4 ignition, mode19 PSA, mode52 MS2 and source-specific
mode22 contracts. MS2 ABS05 and EFI02 retain their native zero-argument ABI.
MS2 pressure validation runs directly in every mode. STR GetRegKeyNumAfter
preserves its native pointer-global writes before mode rejection.

`Ex2SMRT_32_EndEraseMode` preserves its actual no-argument NKDS4/NKPlus ABI and
its older one-argument NK12/NK18 ABI. Source-specific provider admission excludes
ABS36/37/38 from NK12. Private wrapper and body evidence lives in the imported
owner packets under `analysis/evidence/no-car-83`.

Canceled NK18 body statuses 2/27 use the communication facade's actual shared
classic counters to produce native 28/29/30 results. Unsupported source counter
bindings raise; they cannot silently normalize using another image's globals.

`UtilityExContext` reads the actual `Ex2SetParaFromBroker` sequence through
individual host `get_parameter` primitives. The sequence is recovered separately
for every image. `broker` reads that native snapshot. A host write does not
silently update the snapshot; the source's explicit refresh does. Driver, native
communication and UI operations remain separate typed primitives. Persistent
state belongs to one context rather than module globals.
Refresh also overwrites the source's actual `native_global:<VA>` aliases, even
when raw broker values did not change. Plus mode22 applies its native extended
identifier conversions after the ordered reads.
Direct `EbGetPara` sites use `native_parameter` to read the current host value
without changing that snapshot. Literal `Sleep` sites use `native_sleep` for one
host call; `sleep` retains the source's cancellable 100ms wait slices.

`UtilityImportBinding(caller_bytes, engine).invoke_iat(iat_rva, args)` executes
80 proven original18 IT3 imported thunks through the concrete engine. Immutable
caller and target SHA-256 identities must match the proven image pair; unknown
IAT slots and unavailable native operations raise. The original caller binary
is never executed. This supplies imported-thunk dispatch; interpreting native
procedure control flow and selecting it from the normal UI remain open.

`UtilityDriverBinding` recovers the nullable standard DRIVER function table
independently from all eight images. It binds fifteen literal SDK names to their
native offsets, preserves the all-required readiness flag, and computes the OEM
protocol as uint32 `protocol + 0x100`. Supplied functions implement individual
SDK exports. The original DLL is never executed. This resolver is distinct from
selecting an Ex2 business name from a procedure; that outer native bridge remains
a source proof obligation.
`slot_offset` resolves a literal SDK name to its reviewed native field offset.
Separate Plus alternate factories remain excluded; their layouts cannot replace
the standard singleton. Legacy12 controller initialization remains unavailable
until its forwarded SDK argument ABI is established.

NK18 battery and programming-voltage exports run their recovered algorithms
through individual typed SDK primitives: Connect, Ioctl, Disconnect and
SetProgrammingVoltage. Output DWORDs remain caller-owned mutable buffers.
Battery boundaries, native ignored SDK statuses, retained programming handles
and broker-controlled voltage conversion are covered by supplied-image tests.
Host cleanup failures retain ownership and preserve the original exception.
NK18 ordinary-mode Ex2Initialize/Ex2Finalize preserve the raw controller SDK
status. Modes 20, 21 and 52 reject before acquisition because their native
keepalive lifecycle remains incomplete. CCU CAN/SIL/ReproConnect also remain
unavailable pending the concrete classic-manager lower path.

Workers retain their original host exceptions until joined. A stop timeout
retains ownership and cancellation; Python does not safely implement native
`TerminateThread`. No timeout manufactures a completed business status. Timed
native waits observe uint32 clock wrap and cancellation between 100ms slices.

Communication algorithms and lower acquisition are owned by
`scripts.utility_ex_comm` and `scripts.utility_ex_lifecycle`. Exact-source lower
admission is enforced by those components; unsupported classes remain closed.
Remaining business bodies, native common exports and complete procedure/UI
coverage remain open. This module does not claim complete UtilityEx coverage
or physical verification.

Run authored mechanism checks and optional supplied-image composition checks:

```sh
python -m unittest discover -s tests -p test_utility_ex.py -v
```

Optional supplied TY18 checks execute authored FCHV broker/timer algorithms
against the actual hash-guarded source context without native binary execution.
They do not certify communication or device behavior.

The worker belongs to its context and publishes the image-specific native result
global at start and normal completion. Source bodies retain responsibility for
earlier stores, such as publication before cleanup. `running` reports callback
liveness under the worker lock so a native receiver arena lease remains pinned
until the asynchronous callback completes.

`native_memory` carries the optional bounded `NativeMemoryArena` supplied by the
receiver owner; `native_memory_owner` is the context identity. Pointer-consuming
providers authenticate both the image and owner before reading or allocating.
No pointer is manufactured from a flat byte buffer. `read_module_data` reads
bounded original PE32 initialized bytes and section zero-fill; mutable globals
remain in context state.

TY18 SIS uses a separate `UtilitySISDriverBinding` with seventeen v0500 SDK slots,
independent readiness and controller ownership. It cannot alias the standard
DRIVER layout. The typed `GetPrivateProfileIntA` and `GetPrivateProfileStringA`
primitives accept captured ANSI filename/section/key/default arguments and
bounded mutable output. They require explicit individual injected exports and
preserve native raw integer return values; they provide no authentication or
setup-success callback and never infer credential values.

Reviewed wrapper snapshots are reproducibly imported with
`PYTHONPATH=. python runtime/no-car-83/bind_wrapper_packets.py`. The importer
checks source anchors, native modes, arity, callback/timeouts and ordered
pre-mode argument-global stores, including reference permutations and literal
zero stores. Admission covers wrapper mechanics; concrete lower composition
and independent complete business review remain separate open gates.

The complete four-image NK export ownership ledger is generated with
`PYTHONPATH=. python runtime/no-car-83/nk_export_ownership.py`. It preserves all
4465 nonzero source/export pairs: 654 ECD/STR, 1065 ABS/SMRT, 147 common/CCU and
2599 explicitly unassigned business exports. These are assignment counts, not
implemented-operation counts.

The NK139f0 and13970 CMN writer families use separate retained native structs.
Both publish their fields before the busy-worker check. The controlled13970
family preserves its cleanup DWORD and stop-on-error flag; no shared buffer is
aliased across the two families. Their concrete worker belongs to lifecycle132.

TY18 generic P5 exports bind the concrete selected P5 worker. Native Finalize in
modes20/21/52 stops P5 and the five source-fixed workers in native order before
finalizing the standard SDK controller. Inactive fixed shutdown never acquires
a DRIVER or pool solely to stop it.

TY18 `_Ex2ComSecurityAccessCGW@0` runs the concrete10150 worker through the shared
10000ms scheduler. It performs the source-selected target/session sequence,
seed/key exchanges, AES128ECB using key bytes read privately from the supplied
module, bounded native retries and source-ordered cleanup. No credential literal
is copied into authored code or evidence. Its declared public return is void;
`invoke_machine` preserves the proven scheduler EAX visible to the native caller
at11670. Source-bound IAT dispatch uses this machine result without polling the
worker to infer it. `ty18-cgw-source-packet.json` verifies18 source functions and
3786 instruction bytes against the original image. Full caller composition and
independent semantic review remain separate gates.

`Ex2PLG_01_FinalCom` preserves its reviewed unconditional mode predicate and void
wrapper return while publishing the worker's native result. Reviewed95 mode
predicates support exact equality, finite membership and explicit any-mode cases.

Plus SIS source `821bbfd99576…` has a separate standard base table at `0x20..0x58`
and v0500 table at `0x109c..0x10dc`. Its binding reports base and extended
readiness independently and retains the native three-argument controller-init
shape as metadata; TY18 keeps its two-argument shape. `json_d_get_data` and
`json_s_get_data` expose only explicitly registered individual JSON primitives.

Plus P6 is a separate `UtilityP6DriverBinding` for exact TYPlus/NKPlus images.
It preserves the `0x24..0x5c` table, readiness offset `0x20` and controller
handle offset `0x1c`; protocols `6` and `0x8012` have separate context bindings.
`invoke_raw` forwards positional buffers and returns only a typed
`PrimitiveResult.status`. This layer does not run controller initialization,
OEM discovery, connect or pool algorithms. Those compositions and full source
coverage remain open.

Source-reviewed STR52 metadata is admitted for its exact16 NK18/NK12/NKDS4/NKPlus
rows, including each image's pre-guard shared-argument store order. SMRT55 metadata
is admitted for exact NK18/NKDS4/NKPlus only; its CHK wrapper has an any-mode guard,
and TermKeyDiag2 keeps consumed arity0 while the formal/header ABI remains unknown.
The reviewed SMRT55 body uses B-before-A capture for both setters. ABS52
Read/WriteBrakePadResidualThickness metadata is admitted for the exact TYPlus image
only. These source-bound admissions permit dispatcher/consumer testing; complete
UtilityEx coverage and physical equivalence remain open.
