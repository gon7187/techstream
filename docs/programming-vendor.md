# CUW vendor CAN programming

`scripts.programming_vendor` implements statically recovered CUW18 vendor packet
codecs and CPU operation sequences against explicit replay/fake providers. It
opens no adapter, executes no vendor DLL, and calculates no authorization keys.
Successful results remain `PHYSICAL_UNCONFIRMED` and never set
`programming_completed=True`.

## Transport contracts

`VendorCAN(write, read, timeout=30, cancelled=..., clock=..., wait=...)` carries
raw payload bytes after the caller-selected CAN identifier. `write(payload,
remaining_seconds)` must return the actual accepted message count, exactly one.
`read(remaining_seconds)` returns one identifier-filtered payload. Providers must
return within the supplied deadline. Unproven writes, late responses and
cancellation after an attempted operation require reconciliation; they are not
replayed automatically.

Raw common-CAN ACK is the standalone byte `3c`. Status is `50`, ACK, a one-byte
status, ACK. The reader ignores unrelated payloads while finding ACK, bounded by
its deadline and receive count. Busy status polling is bounded to4096 attempts.
The common status query permits the original retry count; image bytes are never
retried after an unproven write.

`VendorDiagnosticChannel` implements the **old** CAN diagnostic utility:
NRC21 repeats the original request only after an actual matching negative reply;
NRC78 receives without repeating it. Default native counters are255 busy repeats
and149 pending responses. On pending overflow, an explicit `send_cleanup(ecu,
b'\x3e')` provider must confirm the cleanup message. Other negatives raise
`NativeDiagnosticError`, retaining their response bytes. A `NativeTransportError`
retains the actual provider error code for the narrowly permitted HINO-VCS retry
branches. Neither class discovers transport or chooses an ECU.

MMC, SBR and standard HINO use `scripts.programming.NativeProgrammingChannel`,
the distinct P5 diagnostic utility. PSA, HINO-DSS/VCS and common P4 diagnostic
operations use `VendorDiagnosticChannel`.

The calling transport session owns connection, identifier/filter binding,
timeout restoration and filter teardown. The module's periodic/configuration
callbacks describe concrete native operations and must raise if they fail;
packet exchange and raw message writes cannot succeed by returning `None`.

## Recovered module coverage

| Native modules | Python operations | Native behavior |
| --- | --- | --- |
| CommonFlashWriter | `VendorCAN`, `common_block_request`, `common_auth_frames` | Blank35/36, erase25/26, write41/address/count/data and45 continuation, verify15/16 with256-byte chunks, verify2 opcode18 with128-byte chunks, inverify47/48, CPU65, finish80, falsification47/status50 |
| CommonPrepareWriter | `common_prepare_requests`, `common_diagnostic_mask` | Session1002/1060, positive50; three720/a027 broadcasts with native delay |
| FlashWriterUtils | `common_memory_info`, `common_cpu_matches`; shared legacy block helpers | Start/end inclusive, default block sizeKiB, descriptor; exact CPU/shrink comparison |
| PSAFlashWriter/PSAUtils | `psa_write`, `psa_download_request`, `psa_identification_request` | Erase3181, poll318101; data34 with selector/address24/length8/data/CRC16LE; check3182; metadata3483 and nested CRC; communication82 or1081 finish |
| PSAPrepareWriter | `psa_prepare` |81 or10c0 start;2781 four-byte seed; explicit periodic3e during supplied-key provider;2782 four-byte key |
| PSACIDGetter | `psa_get_cid`, `PSAQuery`, `psa_identification_field` | Configured SID21 field offsets/packed decimal, software suffix, target/current metadata merge and date |
| MMCFlashWriter | `mmc_write`, `mmc_download_request`, `VendorSegment` | Loader34/44, counter36,37 with supplied CRC;31010301 loader activation;3101ff00 area erase; image transfer;31010304 check |
| MMCPrepareWriter | `mmc_prepare` | Explicit native preparation-state callback,1082 entry burst,2000ms/100ms periodic,1002 timing parameters,2741 eight-byte seed/2742 supplied key |
| MMCCIDGetter | `vendor_get_cid(..., 'MMC')` |22f111 and22f188,24-byte identifiers, explicit optional secondary NRC31 |
| SBRFlashWriter | `sbr_write`, `SBRFile` |3101ff00 erase;3404/ALFID;36 counter/address32/data;37 exit;3101ff01 sum check, native2500ms periodic and tester-present sequencing |
| SBRPrepareWriter/SBRUtils | `sbr_prepare` | Functional session/mask/communication control; gateway2733/2734 supplied256-byte key;31010200/0201; master/slave ordering; actual SSM ID and seed; supplied ECU key |
| SBRSoftwareIDGetter | `vendor_get_cid(..., 'SBR')`, `sbr_identifiers` |0904 ASCII16 records or22f182 binary5 ROM records, short binary left padding and uppercase hexadecimal |
| HINOFlashWriter | `hino_write(..., 'HINO')` |340044 address/size, negotiated block count, counter36,37, routines10ff/10fd/10fe/10fc,1101 and native communication restoration |
| HINOFlashWriterForDSS | `hino_write(..., 'HINO-DSS')` | Distinct34 address24/zero bytes, unnumbered36 chunks, A2/A0/A3 routines and11 reset; actual7f3411 skips only loader |
| HINOFlashWriterForVCS | `hino_write(..., 'HINO-VCS')` |34 selector/address32/size32, unnumbered36,05/01/02/03 routines, bounded native reset retries |
| HINOPrepareWriter and DSS/VCS variants | `hino_prepare` | Concrete variant-specific broadcasts/session/seed widths and supplied keys, timing/block-size configuration; VCS narrowly permitted retries |
| HINOCIDGetter and DSS/VCS variants | `vendor_get_cid` | Standard P5:22f188/12bytes; P4:1a81/13bytes removing spaces; DSS:1a8801/16bytes; VCS:1a/13bytes |
| CanCIDGetter | `vendor_get_cid(..., 'Common')`, `common_cid_response` |0900 probe and0904/count16 records, explicit optional address extension |
| PowerTrainFlashWriter and ForSolar | `powertrain_write`, `PowerTrainProfile` | Supplied CheckID; actual memory/CPU gate with alternate supplied profiles; native block layout; blank/erase/write/inverify/verify; CPU transition/finish; Solar external address width and skip-verify behavior |

M16C, SecurityM16C and SecurityVFOREST belong to the separate
`programming_m16c` module. P4/P5 family writers belong to `programming_legacy`.
Shared modern ReproStd/Unified/Ethernet operations belong to `programming`.

## Bounds and supplied data

All image data is immutable and bounded. MMC CRC response bytes, PSA target
identification, any padded SBR transfer bytes, location IDs, passwords, nonce,
keys and signatures must come from explicit caller data/providers. A supplied
provider is an authorization boundary, not proof that a vehicle accepted it.
SBR accepts a zero seed only when it was actually received from that ECU.

Native common memory fields are **start address**, **inclusive end address**,
**default block sizeKiB**, and **firmware descriptor**. Treating the end address
as a byte count or the block-size byte as the CPU descriptor is incorrect.

The HINO-DSS writer constructs its size object but leaves three transmitted size
bytes zero in the recovered native1110 routine. That observed packet layout is
preserved; the module does not replace those bytes with an assumed size.

Native code sometimes assumes aligned buffers. The implementation validates
complete128/256/512/1024-byte chunks instead of reading beyond an image. Host
count, receive-byte and deadline bounds make native polling loops finite.

CUW12 shared DLLs have different hashes. CUW18 behavior is not evidence that
CUW12 has identical contracts; cross-version compatibility is audited separately.

## Checks

Run `python -m unittest discover -s tests -p test_programming_vendor.py -v`.
Vectors use authored bytes and explicit fakes. They do not load native binaries
or access hardware. Private native captures and per-module source hashes remain
under ignored `analysis/evidence/no-car-17/` and `runtime/no-car-17/`.

`psa_records` retains the native S0 selector, skips the first S1 identification
record, and preserves every subsequent transfer record in order. `mmc_segments`
parses the native concatenation of addressBE32, sizeBE32, data and supplied CRC2;
it rejects incomplete declarations before I/O.

`powertrain_prepare_retry` implements the separate native retry export, including
05/ACK, the previous-write/verify-error gate, supplied transport error9/16,
1024/256 zero-byte resynchronization and the third failed dummy-read limit.
`common_is_finished` runs the native filter/3e/read/stop-filter probe. Its
`finished` flag means that this probe replied; it does not certify programming.

`powertrain_write(native_build=12|18)` preserves the audited version difference:
For regular PowerTrain CUW12 sends finish without ACK; CUW18 uses the resolved
`finish_ack` setting. Solar acknowledges finish in both versions.
Optional `progress(count, percent)` receives native pre-ACK data progress.
On failure regular CUW18 and both Solar versions clear count, publish it, then
clear percent and publish it; regular CUW12 clears both silently. A separate finish stream shares the active
operation deadline.

SBR retry with `send_all_on_prepare_retry=False` selects the distinct shortened
ExtendedSession/gateway-authorization/routine0/optional routine1 sequence. The
220ms delay is conditional on the actual functional-request wait flag. SBR ECU
keys must contain exactly four or sixteen supplied bytes for the selected
non-AES/AES mode. `sumcheck_timeout_seconds` sets the diagnostic utility's pending
response elapsed-time allowance only during the sum-check operation; it does
not increase the transport's blocking read timeout. The prior allowance is
restored even when periodic startup fails.

Old diagnostic transports can supply paired `get_timeout()` and
`set_timeout(milliseconds)` controls. The saved value below5000 triggers the
native pending timeout (`pending_timeout_ms`, default5000), and the saved value
is restored before a busy retransmission and on exit. NRC78 resets the native
consecutive NRC21 counter. Native CUW12 uses the constant5000; CUW18's additional
argument is explicit. Platform timeout changes for P5 remain caller-owned.

`hino_dss_prepare_retry` executes the DSS retry export, which delegates to the
same native DSS preparation routine as normal prepare. Bind its native filter
through `vendor_stage`; it needs no standard-HINO timing configuration callback.
HINO communication restoration retains the native P4 `a02801`/`a08501` and P5
`288001`/`8581` payloads, distinct from the preparation mask/stop payloads.

The retained getter scope also includes `TCUWCanDHSoftwareIDGetter` and
`TCUWCanSoftwareInfoIDGetter`. `dh_get_cid` sends `1a81` and prepends the supplied
`ComplementCID` to the five-byte native field. `software_info_get_cid` probes
`1a8800`, rejects NUL selectors, then sends `1a88<selector>` for each returned
selector. Its sixteen-byte parser preserves the original truncation and
full-buffer trailing-space behavior, including spaces preceding a NUL.

`vendor_get_cid(..., 'MMC')` retains native transport/diagnostic failures as a
failed result, including `identifier_f111` after a successful first read. Host
I/O errors, deadlines, cancellation and `KeyboardInterrupt` propagate unchanged
from either read; they are not native ECU failures.

SoftwareInfo requires explicit `start_filter()`/`stop_filter(handle)` providers
for its separate discovery and selector filter phases. Its outer session owns
connect6, the resolved receive timeout and disconnect. Address extension or
`kind_of_ecu='38'` requires `set_bs(enabled, remaining_seconds)`, which performs
J2534 ioctl2/SET_CONFIG with one parameter0x1e and value0/1; reset executes after
failure too. CUW18 adds the non-query-kind2 assembly read; CUW12 omits it.
Supplying the actual two/three-byte `request_id` retains CUW18's bounded request
address metadata. No identifier is inferred from a DLL name or the host channel
label.

`VendorInitialCommandError.code == 7` represents the native CheckID initial ACK
failure. Only actual native ACK read errors9/16 enter that branch. Partial or
failed writes, unknown transport errors and host cancellation remain distinct.

For payloads retaining the optional address byte,
`VendorDiagnosticChannel(address_extension=...)` uses the actual SID after that
byte for pending/busy matching and includes the byte in cleanup traffic. The
getter context and channel setting must agree. Providers that remove this byte
at the transport boundary use the unextended contract consistently.
DH's original second-byte-5a offset test is preserved, including its ambiguous
leading-Z case. SoftwareInfo retains previously parsed IDs if a later read
fails; the overall result still reports the failure.

`vendor_write_inputs(container, cpu_index, family, parameter, observed=...)`
binds the imported `CalibrationContainer` through the recovered native CPU/file
schema. Pass the selected catalog row's `value` method as `parameter`; it reads
actual header/area settings, DataFormatID selectors, file fields, parameter-row
geometry and waits. Ordinary CPU/flash-code S-records use the shared native
materializer, including FF-filled gaps, the S0 header and the distinct FlashSize.
Non-S-record ordinary CPU images retain bytes only through the native `.vbf`
filename branch. Format9 SBR file records use their separate native file path.

PSA retains its original S-record sequence, including a first S1 identification
record before S2/S3 transfer records. The builder requires the actual software
reply and an explicit `(day, month, year)` in `observed`. PowerTrain requires an
explicit authorized `password`; optional SBR padded file bytes are supplied by
native file index in `observed['padded_files']`. Nothing derives an authorization
key or guesses device memory geometry. `psa_getter_inputs(parameter)` reads the
native configured SID21 field lists for the preceding identification operation.

HINO's declared download size comes from the selected SBL/DATA parameter pair
and can differ from the archive length. `hino_write(loader_size=...,
image_size=...)` preserves these separate native values. Common CID auxiliary
assembly reading is enabled only for CUW18; CUW12 omits that newer path.


`vendor_module_profile()` returns the source-derived utility policy, address
scope, filter ownership and timeout settings after the caller authenticates the
native module identity. Common/DH/SoftwareInfo/SBR getters visit all native
address records; MMC/HINO/PSA getters use the first. SoftwareInfo owns two inner
filters, so its outer `vendor_stage()` uses `manage_filter=False`.

`VendorP5Channel` adds explicit transport timeout providers to the shared P5
response engine: initial reads retain the saved timeout; max(saved, native minimum) bounds
receive-only driver9/16 retries after NRC78. Pending reads use1000ms and the
last native fractional adjustment; every exit restores the saved timeout. MMC/HINO preparation
updates the native minimum from the actual negotiated session timing; the
provider must apply `configure('pending_timeout_ms', value)` to
`minimum_response_timeout_ms`. Getter minima and SBR's fixed5000ms are carried
by the module profile. The elapsed pending-response limits remain distinct:
MMC10seconds (erase90), HINO180, SBR30 or its configured sumcheck duration.

Common status retries apply only to the native ACK failure represented by
`VendorStatusAckError.code == 4`. A failed status write or data read remains an
uncertain transport failure and is never replayed automatically. Nonfinal
verify chunks preserve the native status-ACK exception branch without
retransmitting the data chunk.

For PowerTrain, pass `resolve_parameter(alternate_cpu_type)` to the imported
builder whenever the selected row declares `AlternateCPUType`. It returns the
actual catalog row getter. The builder retains both profile geometry and
selected-row timing; `bh32` performs its preliminary memory read before the
selected flash timeout, while ordinary writers set that timeout first.
Observed recovery state, CPU type22, reset-after-CheckID and next-CPU decisions
remain separate native branches. The module profile exposes CPU22's2000ms wait
before the filter when called with the actual `cpu_type`.

CUW18 regular PowerTrain finish acknowledgement resolves
`FlagToReceiveRespForFinish` across every calibration CPU through
`vendor_finish_ack()`. Pass those flags as `observed['finish_ack_flags']`.
CUW12 regular PowerTrain always omits that acknowledgement; Solar uses it in
both builds. These codecs and profiles identify CUW12/18 behavior only.


SBR preparation takes the native `error_kind` (+604) independently from the
IG-off retry flag (+728). The `prepare_retry` argument identifies the actual
PrepareRetry export. `gateway_controls`, `master_controls` and `main_controls`
bind the separate native filter scopes: gateway authorization, each gateway
routine, auxiliary master session, then the main ECU session. The outer SBR
prepare stage therefore uses `manage_filter=False`. The master uses the second
selected communication address (native seven-byte record stride), while the
gateway is fixed763/76B. These inputs come from the actual native recovery state
and catalog records.


PowerTrain and Solar keep separate range policies. Regular PowerTrain uses one
range per BlockSizeInfo triple, ignores the S0 header, and preserves the native
single zero-size prefix when its first range starts above block1. Solar uses
one range per block unless `ReadBlockRangeFromS0HeaderFlag` selects actual S0
ranges. Its CheckID byte order comes from the global CPU0 catalog row, while
write geometry remains selected for the current CPU.

Solar's module profile supplies `wait_before_timeout_ms` and the flash timeout.
Use `vendor_stage(before_timeout=...)` for the former: native Solar waits, saves
the existing timeout, sets its flash timeout, then creates the filter. Timeout
restoration also applies to Solar. Recovery permits up to11 initial CheckID
attempts; the host replays only its proven typed initial-ACK failure, preserving
uncertain writes/data reads and cancellation as failures.

`vendor_password_input(native_context, current_cids, parameter, family=...,
use_new=..., recovery=...)` binds the executed password branch to actual CPU
metadata. Regular PowerTrain's new-password path reads the materialized image;
Solar's GetNewPassword path can use the imported NewPassword field. External
memory and the native recovery/CPU/IG-off flags choose the branch. A skipped
regular recovery CheckID returns `None`, which its writer accepts only when the
native skip condition is bound; no placeholder password is fabricated.


Solar completion resolves the next CPU's actual
`FlagToDoIGOFFONAtCPUTypeChange` lazily after finishing. Supply
`completion_callback(slot, remaining)` and `clear_native_flags(names, remaining)`
for native callback1 when required, the ordered72c/614/610 flag clear, and
callback7. The result records whether those providers ran; missing providers do
not become observed callback completion.


Regular PowerTrain also resolves the next CPU's IG-off flag after writing:
false selects ChangeNextCpu65, callback1 and clearing728/72c; true selects the
finish80 path, which clears728. These use the same explicit completion and
flag providers. A later CPU's existence alone does not select command65.


`native_utility_call` preserves each recovered utility's explicit error argument.
Only native negative replies, positive-prefix mismatches and native pending/busy
expiry become `VendorOperationError`; host validation, cancellation, deadlines
and uncertain driver failures retain their own domains. The public
`vendor_utility_error_code` table covers MMC, SBR and HINO phase calls, common
mode changes and the associated getters. PSA uses explicit phase codes because
its data and metadata transfers share a request service.

The common gateway probe first uses the ordinary utility. Its permitted fallback
uses the P5 utility with a180-second native pending limit and5530ms retry budget.
The helper requires the native address extension `5f` on its ordinary channel.
Its P5 request provider receives `5f3e00`; replies retain `5f` at the provider
boundary and are decoded before pending-response handling. An explicit raw
expiry writer receives `5f3e`, preserving the native five-byte address. A
first-probe pending expiry does not start the fallback. SoftwareInfo
maps driver timeout9/16 during its selector probe to native getter error3; other
driver failures preserve their original code. These rules do not authorize a
module identity or imply physical ECU confirmation.


Native lifecycle failures retain their code/domain in the stage result. Cleanup
failures retain separate typed `cleanup_error_details`, including filter teardown,
timeout restoration, disconnect and SoftwareInfo BS reset. A cleanup failure does
not overwrite the original diagnostic error.

SBR's ASCII getter uses its fixed16-byte native width and never resolves the
unused binary ROM width parameter. HINO-DSS starts with tester-present `3e`;
HINO-VCS starts with `3e` then `3e01` before reading its identifier. PSA, MMC,
HINO, DSS, VCS and SBR getter profiles expose their native two-byte CAN address
width; Common, DH and SoftwareInfo retain their separate address policies.

Variable-address Common, DH and SoftwareInfo getters accept independent
`address_extension` and `response_address_extension` values. The ordinary channel
uses the transmit value for requests and pending cleanup; it uses the response
value for NRC21/NRC78 matching. Getter codecs use the response value. Omitting
the response value preserves the same-byte calling convention. The common
gateway's native fixed address requires both values to be `5f`.

The CUW18 Common/SoftwareInfo optional P4 assembly query uses native utility
error92. A proven native response failure leaves the collected CIDs intact,
sets `assembly_valid=False`, and records typed `assembly_error` details. A
successful optional read sets `assembly_valid=True`. Driver uncertainty, host
cancellation and deadlines still fail the stage while preserving known CIDs.
The native catch-all also suppresses driver exceptions. This runner conservatively
fails those: its exchange provider cannot prove whether the request write or the
response read failed. Codes9/16 alone do not establish that boundary.
