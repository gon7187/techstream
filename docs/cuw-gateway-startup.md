# Native CUW2026 central gateway startup

`scripts/cuw_gateway_startup.py` implements the CUW.dll `5b1e0 → 1ad30`
startup producer. Its fixed request/response addresses are `000007505f` and
`000007585f`. This producer is separate from the UnifiedUtils gateway-node
judge; the two classifiers must not be aliased.

The engine issues one producer for its actual worker, controller, runtime and
paired engine `J2534Device2026` view. The same runtime retains its crypto,
online capture and budgets while scoped native device calls use the engine
view before the source ImportData transition into the distinct control view.
After a stopped worker is replaced by59070, `rebind_worker(old,new)` retains
the issued producer, gateway classifier/periodic state, runtime and AES binding.
It accepts only the closed previous owner and current exact replacement on the
same controller and device pair, outside any active phase. Rebinding and its
transaction rollback perform no SDK calls.
Startup enables block size1, acquires its flow-control filter,
uses the cached CUW classifier or probes `3e → 7e`, and restores blocksize0 and
releases its own filter on normal exit. A normal probe returns classification2.
Native J2534 statuses9/16 or a native non-pending diagnostic failure select
the P5 probe `3e00 → 7e00`, whose normal return is classification1. Other host
and J2534 faults remain failures. An exhausted `7f3e78` pending response is
rethrown instead of silently switching protocols.
The cache is the actual bound RecoveryInfo `ReproGWNode` byte atED0C. A new
classification updates that byte and saves RecoveryInfo immediately when its
native logged flag is set, before authentication. Imported nonzero bytes such
as3/255 retain their raw value and take the P4 branch, as the native comparison
only distinguishes equality with1. A failed later authentication does not erase
an already saved classification.

Classification2 executes `2751 → 6751 + seed16`, the source-issued native
mode1 AES128 ECB binding, a100ms wait, `2752 + key16 → 675234`, another100ms
wait, `1060 → 50`, then1500ms. The binding must originate from the same actual
CUW2026 image as the engine. No OEM key is embedded in authored code.

Classification1 executes P5 extended session `1003`, seed `2721`, callback26
through the actual `OnlineKeyController2026` and a bound offline chronology,
then `2722 + key256`. A2000ms `3e80` periodic surrounds online calculation and
is stopped before the key is sent. Routines `31011011`, `31031011`,
`31011012`, `31031012` follow, with the literal1500ms waits and result byte01
on the two result queries. The final2000ms periodic remains runtime-owned for
later shutdown. Unavailable or failed online authorization does not become a
successful startup.

The immutable source view exposes the raw classification, final periodic ID,
`5b1e0` return AL, output flag and typed controller-local error fields.
Classification2 stays2; the
new-password decision is equality with1, never `bool(classification)`.
The source view also feeds the actual retry controller's BE48/BE34 fields at
each classification and periodic acquisition, including partial failed startup.
Callback14 executes the direct58530→5b1e0 path, copying BF9 and returning the
literal normal AL1 without inventing the outer5a835 BE0 transition. The wrapper
distinguishes native AL0/output0 from AL0/output1. Its optional fallback is the
selected ControlCommPhase export `ChangeToReprogGWModeForDHCentralGW`, using
the actual module parameter pool and engine device, including its constructor-
empty CParameter before LoadParameter. Actual DHUtils, SecretInfo and CUW source
bindings perform the fallback authentication. Raw1ad30 remains
available as `run_classifier()` for its separate exception contract.
An unavailable DH probe gives AL0/output0; authenticated DH mode gives AL1/output1
without copying the failed1ad30 classifier into BF9. Native DH CPass and J2534
faults retain their distinct outer wrapper behavior.

Callback29 implements588c0→5b690→1a1e0. It tries P6 target72 session1003 and
DID2103, setting bit1 only when requested by the observed data. Initial native
J2534 status9/16 enters the P5 session1003/DID2001 path, setting bit0x40 when
observed. Only exact initial P5 NRC7f1012 takes the P4-mode1070 fallback.
SIL switches6→3 and Ethernet6→0x800f only across a normal operation; failures
do not invent a finally reconnect. Typed failures return AL0 and update local
controller68/70, while copied engine output fields remain untouched. Native
filter-stop faults are suppressed in their exact helper regions.

Native exception regions remain distinct: initial block configuration failure
does not enter restoration, an unknown native business fault becomes9999,
a native block restoration fault skips the later filter stop, and a native
filter-stop fault is suppressed. Failed resources remain runtime-owned for
bounded shutdown. Extra cleanup after a Python host fault is host containment;
the original host exception keeps its identity.

The outer `5a835` worker owns phase1, the actual global Parameter.ini
`FlagToChangeToReprogGWModeForCentralGW` lookup using effective global CPU0,
the `c41 == 0` gate and publication of BE0/980. The actual5b1e0 normal continuation
copies BE48 into BF9/990 before the worker validates that byte. This module never sets a retry flag and
never claims that startup alone completed a flash operation.
The actual RecoveryInfo EC90/`IsCentralGWExist` field is cleared at the enabled
gate and becomes true only on AL1; these two assignments do not save the file.

Verification uses authored raw `PrimitiveResult`/`NativeMessage` SDK
chronologies through the real J2534 device, static source-issued AES and actual
offline online-controller replay. It includes positive class1/class2,
classification caching, invalid authentication/mode responses, identity checks,
missing crypto/online bindings, and host-fault/cancellation injection. Original
PEs are only read and disassembled; no OEM executable, vehicle, adapter or
licensed network service is used. Physical behavior remains unconfirmed.

A frozen215-event Sonar SDK chronology runs the actual controller CID getter,
native target selection, phase1 startup and public writer on one engine,
runtime and distinct device pair. Sonar consumes real980 by using10000ms for
the first ID read and writes2048 bytes. A separate216-event BodyFlash chronology
proves crossownership; that writer does not consume980. Both traces and cleanup
are consumed fully. Full normal prepare/write and
multiCPU controller orchestration remain separate open acceptance work.

Run `python -m unittest discover -s tests -p test_cuw_gateway_startup.py -v`.
