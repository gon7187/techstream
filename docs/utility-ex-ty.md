# Native UtilityEx TY business bodies

`scripts.utility_ex_ty.run_body(export, args, context)` implements source-reviewed TY core bodies and dispatches independently reviewed chassis, body, and powertrain providers. The core currently covers 30 export names for Techstream18, 31 for GTSPlus, and four selected-driver exports for Techstream12. It validates the exact supplied module bytes and SHA-256 before communication. It does not load an OEM DLL, open a device, discover adapters, or use private analysis files at runtime.

Supported module identities:

| Supplied variant | SHA-256 | Communication object |
| --- | --- | --- |
| Techstream 12 TY (selected-driver bodies) | `e85b2456b26d3966ca243c03fa775cf81ad58bf05689bdb87b616eda4c8b6f5f` | `selected` |
| Techstream 18 TY | `79fc495c68eb099a7ebc0d1eefe0eafd80101ac0bc09a58d3f603ed556c84762` | `native:1011d4f0` |
| GTSPlus TY | `821bbfd9957679ceef4ac32c239b8840c984e98ac61050ce7348ac2bc88b04ce` | `native:101392d0` |

The exact Techstream 12 TY (`e85b2456b26d3966ca243c03fa775cf81ad58bf05689bdb87b616eda4c8b6f5f`) and DS4 TY (`87bc49ada3f9dc8db442e74ebaf62ce868679b37d58fe3fdc4d3f24e31c4ce57`) export inventories contain no DOOR or FCHV operations. They are not aliases of either supported module.

| Export | Input | Implemented behavior |
| --- | --- | --- |
| `Ex2DOOR_01_StartConnectionHistoryClear` | `()` | Initialize, configure the controller, enter normal then extended session, settle, clear, validate response length/echo, map a routine fault, settle, restore normal session, finalize. |
| `Ex2FCHV_04_ChangeProtocol` | `(uint32,)` | Set broker parameter, stop on failure, commit parameters, stop on failure, refresh the shared state. |
| `Ex2FCHV_04_CheckCanSendTime` | `(start_uint32, interval_uint32)` | Compare the interval to the recovered DWORD timer, including its extra subtraction across wrap. |
| `Ex2MSW_01_SendMessage`, `Ex2DMOT_01_SendMessage`, `Ex2EV_02_SendMessage` | `()` | Exact12/18/Plus selected driver and150ms timeout. MSW/DMOT sendA600 and require one byte; EV sends3B2201 and requires exact7B22. |
| `Ex2SAS_02_SendMessage` | `(unused_pointer,)` | Routine1101 followed by restoration and finalization, preserving raw status. |
| `Ex2MIR_01_SendMessage` | `(bytearray >= 4,)` start; `(bytearray >= 8,)` polling | Start routine1101 and retain the session. Poll every10ms; result1 repeats, result2 succeeds, other results map1007; honor the native cancel DWORD, restore and close. |
| `Ex2MS2MM_01_SendMessage` | `(unused_pointer,)` | Initialize and send routine0050 without session transitions; require exactly four response bytes. |
| `Ex2MS2BSRL_01_SendMessage` | `(bytearray >= 3,)`18; `(bytearray >= 8,)`Plus | Two routine0141 calls separated by3000ms, native status/output mappings, timeout/NRC mapping and per-source NRC global publication. Plus identifier722 reverses result12/13 mapping. |
| `Ex2IG_01_DisableAutoPowerOffFunc` | `()` | Exact12/18/Plus selected driver path, per-source150ms timeout setter, request1070, require one response byte, always finalize. |
| `Ex2HF_01_Com_TanksNumberValueClear` | `(unused_pointer,)` | Clear DID2001 with payload1F, preserve raw status, wait50ms on success, restore and finalize. |
| `Ex2ROOF_01_ImpactDetectionInfoClear` | `()` | RoutineB022 with two200ms waits, map status7 through the concrete native10B0 field, restore and finalize. |
| `Ex2IG_02_SendMessage` | `()` | Read/change/re-read the exact power-off flag while preserving the full DID payload. Plus mode22 uses the distinct native1013E7D0 object/DID2103/bit01; UDS uses DID2001/bit40. |
| `Ex2FCHV_02_ReadData` | `(bytearray >= 300,)` | Five selected native records; start at record2, validate and copy produced DID bytes, preserve cycle-ready flag and native 200ms cadence. Retain the session on native status; close it on host exceptions. |
| `Ex2FCHV_05_SendMessage` | `(bytearray >= 8,)` | Start/check routine111B, observe the mutable cancel DWORD between source steps, map initialization/cancel/routine errors to2000/2001/2002, retain successful session until the explicit stop action. |
| `Ex2FCHV_06_SendMessage` | `(bytearray >= 8,)` | Read/write DID2004. Read copies two bytes and preserves restore status; write maps diagnostic failure to2000 and ignores restore status. |
| `Ex2FCHV_07_SupportCheck`, `Ex2FCHV_08_SupportCheck` | `(bytearray >= 20,)` | Exact35-byte DID0101 gate and DID2000 response, set three supported flags without clearing the other output values. |
| `Ex2FCHV_07_Overwrite` | `(unused_pointer,)` | Native worker publishes1000 without communication. |
| `Ex2FCHV_09_SendMessage` | `(bytearray >= 2,)` | Write DID2005 with enable byte1 and the two native input bytes; map failure to2000, restore and finalize. |
| `Ex2FCHV_10_SendMessage` | `(bytearray >= 508,)` | Native21-record support/write loop.18 sets matching flags; Plus first checks DID0101/1B00 gates and clears only nonmatching flags. Preserve per-source restore/error precedence. |
| `Ex2FCHV_13_SendMessage` | `(bytearray >= 4,)` | Three distinct2F enable frames, two continuation frames, three cleanup frames; preserve retained-session and failure-result branches. |
| `Ex2FCHV_14_SendMessage` | `(unused_pointer,)` | Routine1188 with argument1, error1005, restore then finalize. |
| `Ex2FCHV_16_SendMessage` | `(TYMessage(action, selection),)` | Enable, drive, stop, or read/poll; preserve native action-specific statuses, selection-dependent timeout/result mapping, repeat drive, response predicates, session restoration, and conditional finalization. |

The FCHV16 stop wrapper deliberately discards the stop helper's result. Successful enable retains the controller for subsequent actions. Polling starts its timeout after the first successful read, checks cancellation before wire calls, and retains the source's selected normal-session restoration paths. Host exceptions and cancellation finalize the controller. Explicit END cleanup still closes a retained controller when cancellation was already set; FCHV13 cleanup owns finalization exactly once even if its wire call raises.

The common `utility_ex` engine owns wrapper mode checks, scheduling, driver resolution, low-level controller retry/pending behavior, and session keepalive transitions. `TYContext` and `TYComm` document the required interface. Context carries the broker mode and persistent state. `support_snapshot(kind)` returns status, bytes, and offsets; `read_field`, `select_target`, `configure_target`, `select_protocol`, and `read_target` are concrete source-bound field primitives. The business engine uses `comm.session()` for the recovered session/controller state transitions rather than treating a raw session response as complete lifecycle integration.

Source review used the actual reachable business bodies, not export names or scheduler wrappers. Relevant RVAs are 18 DOOR `c3d80/c3e10`, FCHV16 `c3eb0/c3f80/c3fd0/c4020/c4040/c4120/c4280`, protocol/timer `8df0/8e30/dd10`; Plus DOOR `c9fb0/c9f10`, FCHV16 `ca210/ca040/ca090/ca0f0/ca2f0/ca3d0/ca110`, protocol/timer `9eb0/9ef0/f950`. The distinct manager identities and native field offsets were checked separately in both variants. MIR18 polling was reconstructed from ASM because decompilation removed its pending loop.

The exact same-RVA end aliases restore normal session, finalize, and publish1003.18 includes FCHV02/GWY02/GWY03/STRACT03; Plus includes FCHV02/FCHV26/GWY03/SBW01/STRACT03.18 also has a distinct SBW01 wrapper for the same worker. Plus GWY02 selects the classic controller in mode22 and the UDS controller in modes20/21. These names are admitted only against their own source identity.

Coverage remains **OPEN** for unimplemented exact source/export pairs and final integration through the common scheduler/driver. Implemented core exports do not establish whole-module parity. The lazy dispatcher composes the separate FCHV, MS2, chassis, body, powertrain, and ready retained providers without changing native argument identities. All twelve retained providers are now lazily joined after explicit checked-subset handshakes; unimplemented source/export pairs remain unadvertised. Wrapper admission and independent source review remain separate gates. Physical ECU behavior is **PHYSICAL_UNCONFIRMED**.

Run the authored trace checks with:

```bash
python -m unittest discover -s tests -p test_utility_ex_ty.py -v
```

The 73 authored checks cover state chronology, wire payload predicates, initialization/session/routine failures, selection mapping, repeated reads, timeout origin, cancellation/cleanup, broker failures, exact variant selection, module tampering, native wrap boundaries, provider buffer identity, and exact-source retained/core dispatch disjointness. They do not execute a PE or require proprietary fixtures.
